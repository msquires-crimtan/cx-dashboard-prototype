import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { execFileSync } from "child_process";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { B2BClient } from "stytch";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(helmet());
app.set("trust proxy", 1);
app.use(express.json({ limit: "10mb" }));

// ── Environment ───────────────────────────────────────────────────────────────
const PORT          = process.env.PORT          || 8080;
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || "";
const APP_PASSWORD  = process.env.APP_PASSWORD  || "changeme";
if (!process.env.APP_PASSWORD) console.error("🚨 SECURITY: APP_PASSWORD not set — running with insecure default. Set APP_PASSWORD before sharing this app.");
const COOKIE_SECRET = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString("hex");
const IS_PROD       = process.env.NODE_ENV === "production" || !!process.env.RAILWAY_ENVIRONMENT;
const COOKIE_NAME   = "cx_sess";
const COOKIE_TTL_MS = 8 * 60 * 60 * 1000;

const GITHUB_TOKEN  = process.env.GITHUB_TOKEN  || "";
const GITHUB_REPO   = process.env.GITHUB_REPO   || "msquires-crimtan/cx-dashboard-prototype";
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
const PROTOTYPE_FILE = "prototype/index.html";

// Git repo lives in /app/repo (separate from the app files in /app)
const REPO_DIR   = path.join(__dirname, "repo");
const PROTO_PATH = path.join(REPO_DIR, PROTOTYPE_FILE);

if (!ANTHROPIC_KEY) console.warn("⚠  ANTHROPIC_API_KEY not set");
if (!GITHUB_TOKEN)  console.warn("⚠  GITHUB_TOKEN not set");

// ── Supabase ──────────────────────────────────────────────────────────────────
const SUPABASE_URL         = process.env.SUPABASE_URL         || "";
const SUPABASE_ANON_KEY    = process.env.SUPABASE_ANON_KEY    || "";
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || "";
const SCHEMA               = "cxdashboard";

if (!SUPABASE_URL) console.warn("⚠  SUPABASE_URL not set");

// ── Stytch (client-facing login + MFA) ────────────────────────────────────────
const STYTCH_PROJECT_ID = process.env.STYTCH_PROJECT_ID || "";
const STYTCH_SECRET     = process.env.STYTCH_SECRET     || "";
const stytchClient = (STYTCH_PROJECT_ID && STYTCH_SECRET)
  ? new B2BClient({ project_id: STYTCH_PROJECT_ID, secret: STYTCH_SECRET })
  : null;
if (!stytchClient) console.warn("⚠  STYTCH_PROJECT_ID/STYTCH_SECRET not set — client login disabled");

async function supabase(table, { method = "GET", query = "", body = null, useServiceKey = false } = {}) {
  const url = `${SUPABASE_URL}/rest/v1/${table}${query ? "?" + query : ""}`;
  const key = useServiceKey ? SUPABASE_SERVICE_KEY : SUPABASE_ANON_KEY;
  const opts = {
    method,
    headers: {
      "apikey": key,
      "Authorization": `Bearer ${key}`,
      "Content-Type": "application/json",
      "Accept-Profile": SCHEMA,
      "Content-Profile": SCHEMA,
      "Prefer": "return=representation",
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(url, opts);
  const text = await r.text();
  try { return { status: r.status, data: JSON.parse(text) }; }
  catch { return { status: r.status, data: text }; }
}

// ── Password hashing (scrypt, no external deps) ───────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPasswordHash(password, stored) {
  const [salt, hash] = (stored || "").split(":");
  if (!salt || !hash) return false;
  const hashBuf = Buffer.from(hash, "hex");
  const candidate = crypto.scryptSync(password, salt, 64);
  return hashBuf.length === candidate.length && crypto.timingSafeEqual(candidate, hashBuf);
}

const ALLOWED_EMAIL_DOMAIN = "crimtan.com";
function isAllowedEmail(email) {
  return typeof email === "string" && new RegExp(`^[^\\s@]+@${ALLOWED_EMAIL_DOMAIN}$`, "i").test(email.trim());
}

// ── Signed-cookie session ─────────────────────────────────────────────────────
function signToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig  = crypto.createHmac("sha256", COOKIE_SECRET).update(data).digest("base64url");
  return `${data}.${sig}`;
}
function verifyToken(cookie) {
  if (!cookie) return null;
  const dot = cookie.lastIndexOf(".");
  if (dot < 0) return null;
  const data = cookie.slice(0, dot);
  const expected = `${data}.${crypto.createHmac("sha256", COOKIE_SECRET).update(data).digest("base64url")}`;
  try {
    if (!crypto.timingSafeEqual(Buffer.from(cookie), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(data, "base64url").toString());
    return payload.exp > Date.now() ? payload : null;
  } catch { return null; }
}
function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || "").split(";")
      .map(s => s.trim().split("="))
      .filter(p => p.length === 2)
      .map(([k, v]) => [k, decodeURIComponent(v)])
  );
}
function isAuthed(req) { return !!verifyToken(parseCookies(req)[COOKIE_NAME]); }
function setSessionCookie(res, email) {
  const token = signToken({ ok: true, email: email || null, exp: Date.now() + COOKIE_TTL_MS });
  const flags = [`${COOKIE_NAME}=${encodeURIComponent(token)}`, "HttpOnly", "SameSite=Lax", `Max-Age=${COOKIE_TTL_MS / 1000}`, "Path=/"];
  if (IS_PROD) flags.push("Secure");
  res.setHeader("Set-Cookie", flags.join("; "));
}

// ── Rate limits ───────────────────────────────────────────────────────────────
const loginLimit    = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const registerLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const apiLimit       = rateLimit({ windowMs: 60 * 1000, max: 30 });
const clientLoginLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });

function requireAuth(req, res, next) {
  if (isAuthed(req)) return next();
  res.status(401).json({ error: "Not authenticated." });
}

// ── Client (Stytch-backed) session cookie ─────────────────────────────────────
// Separate from the internal @crimtan.com session above. Password + MFA are
// verified once against Stytch; from then on we carry our own signed cookie,
// same pattern as the internal session, scoped to a single client's slug.
const CLIENT_COOKIE_NAME   = "cx_client_sess";
const CLIENT_COOKIE_TTL_MS = 8 * 60 * 60 * 1000;

function setClientSessionCookie(res, slug, memberId) {
  const token = signToken({ type: "client", slug, memberId, exp: Date.now() + CLIENT_COOKIE_TTL_MS });
  const flags = [`${CLIENT_COOKIE_NAME}=${encodeURIComponent(token)}`, "HttpOnly", "SameSite=Lax", `Max-Age=${CLIENT_COOKIE_TTL_MS / 1000}`, "Path=/"];
  if (IS_PROD) flags.push("Secure");
  res.setHeader("Set-Cookie", flags.join("; "));
}
function currentClientSession(req) {
  const payload = verifyToken(parseCookies(req)[CLIENT_COOKIE_NAME]);
  return payload && payload.type === "client" ? payload : null;
}
function requireClientAuth(req, res, next) {
  const session = currentClientSession(req);
  if (!session || session.slug !== req.params.slug) return res.status(401).json({ error: "Not authenticated." });
  next();
}
async function getClientBySlug(slug) {
  const { status, data } = await supabase("clients", {
    query: `slug=eq.${encodeURIComponent(slug)}&select=id,company_name,slug,login_email,stytch_organization_id,active`,
    useServiceKey: true,
  });
  return status === 200 && Array.isArray(data) ? (data[0] || null) : null;
}

// ── Auth routes ───────────────────────────────────────────────────────────────
app.post("/auth/register", registerLimit, async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const { password } = req.body;
  if (!isAllowedEmail(email)) return res.status(400).json({ error: `Only @${ALLOWED_EMAIL_DOMAIN} email addresses can register.` });
  if (!password || password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });

  try {
    const existing = await supabase("users", { query: `email=eq.${encodeURIComponent(email)}&select=id`, useServiceKey: true });
    if (existing.status !== 200) throw new Error("lookup failed");
    if (Array.isArray(existing.data) && existing.data.length > 0) {
      return res.status(409).json({ error: "An account with that email already exists." });
    }

    const created = await supabase("users", {
      method: "POST",
      body: { email, password_hash: hashPassword(password) },
      useServiceKey: true,
    });
    if (created.status >= 300) throw new Error("insert failed");

    setSessionCookie(res, email);
    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: "Could not create account — please try again." });
  }
});

app.post("/auth/login", loginLimit, async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password required." });

  // Master password — legacy shared-access fallback, kept for continuity.
  const masterMatch = crypto.timingSafeEqual(
    Buffer.from(password.padEnd(128).slice(0, 128)),
    Buffer.from(APP_PASSWORD.padEnd(128).slice(0, 128))
  ) && password === APP_PASSWORD;
  if (masterMatch) {
    setSessionCookie(res, email || null);
    return res.json({ ok: true });
  }

  if (!email) return res.status(400).json({ error: "Email required." });
  try {
    const { status, data } = await supabase("users", { query: `email=eq.${encodeURIComponent(email)}&select=email,password_hash`, useServiceKey: true });
    const user = status === 200 && Array.isArray(data) ? data[0] : null;
    if (!user || !verifyPasswordHash(password, user.password_hash)) {
      return res.status(401).json({ error: "Incorrect email or password." });
    }
    setSessionCookie(res, email);
    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: "Login failed — please try again." });
  }
});

app.post("/auth/logout", (req, res) => {
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=; HttpOnly; Max-Age=0; Path=/`);
  res.json({ ok: true });
});
app.get("/auth/check", (req, res) => {
  const payload = verifyToken(parseCookies(req)[COOKIE_NAME]);
  res.json({ authed: !!payload, email: payload?.email || null });
});

// ── Git helpers ───────────────────────────────────────────────────────────────
function git(...args) {
  return execFileSync("git", args, { cwd: REPO_DIR, encoding: "utf-8", env: {
    ...process.env,
    GIT_AUTHOR_NAME: "CX Dashboard",
    GIT_AUTHOR_EMAIL: "editor@crimtan.com",
    GIT_COMMITTER_NAME: "CX Dashboard",
    GIT_COMMITTER_EMAIL: "editor@crimtan.com",
  }}).trim();
}

async function ensureRepo() {
  if (fs.existsSync(path.join(REPO_DIR, ".git")) && fs.existsSync(PROTO_PATH)) {
    return;
  }

  const repoUrl = `https://${GITHUB_TOKEN}@github.com/${GITHUB_REPO}.git`;
  console.log("Cloning repo…");
  // Clear out any partial state from a previous failed attempt — `git clone`
  // refuses to target a non-empty directory, so a bad prior attempt would
  // otherwise wedge every future call here on the same broken state.
  fs.rmSync(REPO_DIR, { recursive: true, force: true });
  fs.mkdirSync(REPO_DIR, { recursive: true });
  execFileSync("git", ["clone", repoUrl, REPO_DIR], {
    encoding: "utf-8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "CX Dashboard",
      GIT_AUTHOR_EMAIL: "editor@crimtan.com",
      GIT_COMMITTER_NAME: "CX Dashboard",
      GIT_COMMITTER_EMAIL: "editor@crimtan.com",
    }
  });
  if (!fs.existsSync(PROTO_PATH)) {
    throw new Error(`Cloned repo but ${PROTOTYPE_FILE} is missing from it.`);
  }
  console.log("Repo cloned ✓");
}

async function commitAndPush(message) {
  git("add", PROTOTYPE_FILE);
  try { git("commit", "-m", message); } catch { return; }
  const repoUrl = `https://${GITHUB_TOKEN}@github.com/${GITHUB_REPO}.git`;
  git("push", repoUrl, GITHUB_BRANCH);
  console.log("Pushed:", message);
}

function currentEmail(req) {
  return verifyToken(parseCookies(req)[COOKIE_NAME])?.email || null;
}

// Shared by the authenticated editor preview (/prototype) and public share
// links (/share/:token) — same document, same headers.
function sendPrototypeHtml(res) {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Cache-Control", "no-store");
  // The prototype document is AI-edited HTML that relies on inline <script>
  // and onclick handlers throughout (row expand, copy, theme toggle, etc.).
  // It's only ever loaded inside this authenticated, same-origin iframe, so
  // drop the app-wide CSP for just this response instead of rewriting
  // hundreds of handlers in AI-editable markup.
  res.removeHeader("Content-Security-Policy");
  res.send(fs.readFileSync(PROTO_PATH, "utf-8"));
}

// The published snapshot clients see — a deliberate copy of PROTO_PATH, only
// updated when a colleague clicks Publish, so live AI-editing sessions never
// reach client logins mid-change.
const PUBLISHED_FILE = "prototype/production.html";
const PUBLISHED_PATH = path.join(REPO_DIR, PUBLISHED_FILE);

function sendProductionHtml(res) {
  if (!fs.existsSync(PUBLISHED_PATH)) {
    return res.status(503).send(
      "<html><body style='font-family:sans-serif;padding:60px;text-align:center;color:#666'>" +
      "<h2>Nothing published yet</h2><p>Ask your Crimtan contact to publish the latest version.</p></body></html>"
    );
  }
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Cache-Control", "no-store");
  res.removeHeader("Content-Security-Policy");
  res.send(fs.readFileSync(PUBLISHED_PATH, "utf-8"));
}

// ── Prototype routes ──────────────────────────────────────────────────────────
app.get("/prototype/ready", requireAuth, (req, res) => {
  res.json({ ready: fs.existsSync(PROTO_PATH) });
});

app.get("/prototype", requireAuth, async (req, res) => {
  try {
    await ensureRepo();
    sendPrototypeHtml(res);
  } catch (err) {
    res.status(502).send("Could not load the prototype — please try again.");
  }
});

app.get("/prototype/search", requireAuth, async (req, res) => {
  const keyword = req.query.q || "";
  if (!keyword) return res.status(400).json({ error: "q required" });
  try {
    await ensureRepo();
    const html = fs.readFileSync(PROTO_PATH, "utf-8");
    const lines = html.split("\n");
    const contexts = [];
    lines.forEach((line, i) => {
      if (line.toLowerCase().includes(keyword.toLowerCase()) && contexts.length < 3) {
        const start = Math.max(0, i - 10);
        const end = Math.min(lines.length, i + 20);
        contexts.push({ line: i + 1, context: lines.slice(start, end).join("\n") });
      }
    });
    res.json({ found: contexts.length > 0, contexts });
  } catch (err) {
    res.status(502).json({ error: "Could not search the prototype." });
  }
});

// A "turn" = one chat request's worth of edits, applied and logged atomically.
// The whole-site chat/edit history lives in Supabase (cxdashboard.chat_log),
// not in server memory or per-session state — every logged-in user sees the
// same shared record, and any turn can be rolled back by anyone, matching how
// Lovable's chat history works.
app.post("/api/chat/turn", requireAuth, async (req, res) => {
  const { user_message, edits, summary } = req.body;
  if (!Array.isArray(edits)) return res.status(400).json({ error: "edits array required" });
  try { await ensureRepo(); }
  catch (err) { return res.status(502).json({ error: "Could not load the prototype — please try again." }); }
  let html = fs.readFileSync(PROTO_PATH, "utf-8");
  const snapshotBefore = html;

  const results = [];
  for (const edit of edits) {
    const { find, replace } = edit || {};
    if (!find || replace === undefined) { results.push({ ok: false, error: "find and replace required", find: find || "" }); continue; }
    const occurrences = html.split(find).length - 1;
    if (occurrences === 0) { results.push({ ok: false, error: "Text not found", find: find.substring(0, 100) }); continue; }
    if (occurrences > 1) { results.push({ ok: false, error: `This text appears ${occurrences} times in the file — include more surrounding context so the edit only targets one spot.`, find: find.substring(0, 100) }); continue; }
    html = html.split(find).join(replace);
    results.push({ ok: true, find: find.substring(0, 100) });
  }

  const appliedCount = results.filter(r => r.ok).length;
  if (appliedCount > 0) {
    fs.writeFileSync(PROTO_PATH, html, "utf-8");
    commitAndPush((summary || user_message || "Update via CX Dashboard editor").substring(0, 100)).catch(console.error);
  }

  let turnId = null;
  try {
    const logged = await supabase("chat_log", {
      method: "POST",
      body: {
        email: currentEmail(req),
        user_message: user_message || "",
        assistant_summary: summary || "",
        edit_count: appliedCount,
        snapshot_before: appliedCount > 0 ? snapshotBefore : null,
      },
      useServiceKey: true,
    });
    turnId = Array.isArray(logged.data) ? logged.data[0]?.id : null;
  } catch (err) { console.error("chat_log insert failed:", err.message); }

  res.json({ ok: true, results, turnId });
});

// GET the full shared chat/edit history — a record of the site, not of the
// requesting user, so every user sees every turn from everyone.
app.get("/api/chat/log", requireAuth, async (req, res) => {
  try {
    const { status, data } = await supabase("chat_log", {
      query: "select=id,email,user_message,assistant_summary,edit_count,rolled_back,created_at&order=created_at.asc&limit=500",
      useServiceKey: true,
    });
    res.status(status).json(data);
  } catch (err) {
    res.status(502).json({ error: "Could not load history — please try again." });
  }
});

// Roll back a specific turn (any turn, by any user) to how the prototype
// looked immediately before that turn's edits were applied.
app.post("/api/chat/turn/:id/rollback", requireAuth, async (req, res) => {
  try {
    const { status, data } = await supabase("chat_log", {
      query: `id=eq.${encodeURIComponent(req.params.id)}&select=*`,
      useServiceKey: true,
    });
    const turn = status === 200 && Array.isArray(data) ? data[0] : null;
    if (!turn || !turn.snapshot_before) return res.status(404).json({ error: "Nothing to roll back for this change." });

    await ensureRepo();
    const currentHtml = fs.readFileSync(PROTO_PATH, "utf-8");
    fs.writeFileSync(PROTO_PATH, turn.snapshot_before, "utf-8");
    commitAndPush(`Reverted: ${(turn.user_message || "change").substring(0, 80)}`).catch(console.error);

    await supabase("chat_log", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(req.params.id)}`,
      body: { rolled_back: true },
      useServiceKey: true,
    });

    await supabase("chat_log", {
      method: "POST",
      body: {
        email: currentEmail(req),
        user_message: `(reverted "${(turn.user_message || "").substring(0, 80)}")`,
        assistant_summary: "Reverted to the state before this change.",
        edit_count: 0,
        snapshot_before: currentHtml,
      },
      useServiceKey: true,
    });

    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: "Rollback failed — please try again." });
  }
});

app.post("/prototype/refresh", requireAuth, async (req, res) => {
  try {
    if (GITHUB_TOKEN && fs.existsSync(path.join(REPO_DIR, ".git"))) {
      const repoUrl = `https://${GITHUB_TOKEN}@github.com/${GITHUB_REPO}.git`;
      git("fetch", repoUrl, GITHUB_BRANCH);
      git("checkout", "FETCH_HEAD", "--", PROTOTYPE_FILE);
    }
    res.json({ ok: true });
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// ── Share links ─────────────────────────────────────────────────────────────
// Time-limited, unauthenticated preview links a logged-in user can generate
// and hand to anyone (client, stakeholder) without giving them editor access.
const MAX_SHARE_HOURS = 24 * 30; // 30 days

app.post("/api/share", requireAuth, async (req, res) => {
  const hours = Number(req.body?.hours);
  if (!Number.isFinite(hours) || hours <= 0 || hours > MAX_SHARE_HOURS) {
    return res.status(400).json({ error: `hours must be between 0 and ${MAX_SHARE_HOURS}` });
  }
  const token = crypto.randomBytes(24).toString("base64url");
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
  try {
    const { status, data } = await supabase("share_links", {
      method: "POST",
      body: { token, created_by: currentEmail(req), expires_at: expiresAt },
      useServiceKey: true,
    });
    if (status >= 300) throw new Error("insert failed");
    const row = Array.isArray(data) ? data[0] : null;
    const url = `${req.protocol}://${req.get("host")}/share/${token}`;
    res.json({ ok: true, id: row?.id, token, url, expiresAt });
  } catch (err) {
    res.status(502).json({ error: "Could not create share link — please try again." });
  }
});

app.get("/api/share", requireAuth, async (req, res) => {
  try {
    const { status, data } = await supabase("share_links", {
      query: `revoked=eq.false&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=id,token,created_by,expires_at,created_at&order=created_at.desc`,
      useServiceKey: true,
    });
    if (status >= 300) throw new Error("query failed");
    const host = `${req.protocol}://${req.get("host")}`;
    const links = (Array.isArray(data) ? data : []).map(l => ({ ...l, url: `${host}/share/${l.token}` }));
    res.json(links);
  } catch (err) {
    res.status(502).json({ error: "Could not load share links." });
  }
});

app.post("/api/share/:id/revoke", requireAuth, async (req, res) => {
  try {
    const { status } = await supabase("share_links", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(req.params.id)}`,
      body: { revoked: true },
      useServiceKey: true,
    });
    if (status >= 300) throw new Error("update failed");
    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: "Could not revoke this link." });
  }
});

// Public — no login required. Anyone with a valid, unexpired token can view
// the current prototype, read-only, no editor chrome.
app.get("/share/:token", async (req, res) => {
  try {
    const { status, data } = await supabase("share_links", {
      query: `token=eq.${encodeURIComponent(req.params.token)}&select=revoked,expires_at`,
      useServiceKey: true,
    });
    const link = status === 200 && Array.isArray(data) ? data[0] : null;
    const expired = !link || link.revoked || new Date(link.expires_at) <= new Date();
    if (expired) {
      return res.status(410).send(
        "<html><body style='font-family:sans-serif;padding:60px;text-align:center;color:#666'>" +
        "<h2>This preview link has expired</h2><p>Ask whoever shared it to generate a new one.</p></body></html>"
      );
    }
    await ensureRepo();
    sendPrototypeHtml(res);
  } catch (err) {
    res.status(502).send("Could not load this preview — please try again.");
  }
});

// ── Publish (draft → production) ───────────────────────────────────────────────
// Colleagues edit the draft freely via Compass AI; client logins only ever see
// this separately-committed snapshot, taken deliberately via this button.
app.post("/api/publish", requireAuth, async (req, res) => {
  try {
    await ensureRepo();
    fs.writeFileSync(PUBLISHED_PATH, fs.readFileSync(PROTO_PATH, "utf-8"), "utf-8");
    git("add", PUBLISHED_FILE);
    try { git("commit", "-m", `Publish to production (${currentEmail(req) || "unknown"})`); } catch { /* nothing changed since last publish */ }
    const repoUrl = `https://${GITHUB_TOKEN}@github.com/${GITHUB_REPO}.git`;
    git("push", repoUrl, GITHUB_BRANCH);
    await supabase("publish_log", { method: "POST", body: { published_by: currentEmail(req) }, useServiceKey: true });
    res.json({ ok: true });
  } catch (err) {
    console.error("publish failed:", err.message);
    res.status(502).json({ error: `Publish failed: ${err.message}` });
  }
});

app.get("/api/publish/status", requireAuth, async (req, res) => {
  try {
    const { status, data } = await supabase("publish_log", {
      query: "select=published_by,created_at&order=created_at.desc&limit=1",
      useServiceKey: true,
    });
    const last = status === 200 && Array.isArray(data) ? data[0] || null : null;
    res.json({ published: fs.existsSync(PUBLISHED_PATH), last });
  } catch (err) {
    res.status(502).json({ error: "Could not load publish status." });
  }
});

// ── Client accounts (admin) ────────────────────────────────────────────────────
// One Stytch B2B Organization per client company, one shared Member/login per
// Organization, MFA required. Admin actions here are gated by the existing
// @crimtan.com colleague auth (requireAuth) — not a separate permission tier.
app.get("/api/admin/clients", requireAuth, async (req, res) => {
  try {
    const { status, data } = await supabase("clients", {
      query: "select=id,company_name,slug,login_email,active,created_by,created_at&order=created_at.desc",
      useServiceKey: true,
    });
    res.status(status).json(data);
  } catch (err) {
    res.status(502).json({ error: "Could not load clients." });
  }
});

app.post("/api/admin/clients", requireAuth, async (req, res) => {
  if (!stytchClient) return res.status(503).json({ error: "Stytch is not configured on this server." });
  const company_name = (req.body?.company_name || "").trim();
  const login_email  = (req.body?.login_email || "").trim().toLowerCase();
  let slug = (req.body?.slug || "").trim().toLowerCase();
  if (!company_name) return res.status(400).json({ error: "Company name required." });
  if (!slug) slug = company_name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-+|-+$)/g, "");
  if (!/^[a-z0-9-]{2,64}$/.test(slug)) return res.status(400).json({ error: "Slug must be 2-64 lowercase letters, numbers or hyphens." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(login_email)) return res.status(400).json({ error: "A valid login email is required." });

  try {
    const existing = await supabase("clients", { query: `slug=eq.${encodeURIComponent(slug)}&select=id`, useServiceKey: true });
    if (Array.isArray(existing.data) && existing.data.length > 0) {
      return res.status(409).json({ error: "A client with that slug already exists." });
    }

    const org = await stytchClient.organizations.create({
      organization_name: company_name,
      // Stytch org slugs are unique project-wide; ours only need to be unique in
      // our own table, so disambiguate with a short random suffix.
      organization_slug: `cx-${slug}-${crypto.randomBytes(3).toString("hex")}`,
      mfa_policy: "REQUIRED_FOR_ALL",
      email_invites: "ALL_ALLOWED",
      email_jit_provisioning: "NOT_ALLOWED",
    });

    const origin = `${req.protocol}://${req.get("host")}`;
    await stytchClient.passwords.email.resetStart({
      organization_id: org.organization.organization_id,
      email_address: login_email,
      reset_password_redirect_url: `${origin}/client-setup?client_slug=${encodeURIComponent(slug)}`,
    });

    const inserted = await supabase("clients", {
      method: "POST",
      body: { company_name, slug, login_email, stytch_organization_id: org.organization.organization_id, created_by: currentEmail(req) },
      useServiceKey: true,
    });
    if (inserted.status >= 300) throw new Error("insert failed");

    res.json({ ok: true, slug, loginUrl: `${origin}/client/${slug}/login` });
  } catch (err) {
    console.error("admin/clients create failed:", err.message);
    res.status(502).json({ error: `Could not create client: ${err.message}` });
  }
});

app.post("/api/admin/clients/:id/resend-invite", requireAuth, async (req, res) => {
  if (!stytchClient) return res.status(503).json({ error: "Stytch is not configured on this server." });
  try {
    const { status, data } = await supabase("clients", { query: `id=eq.${encodeURIComponent(req.params.id)}&select=*`, useServiceKey: true });
    const client = status === 200 && Array.isArray(data) ? data[0] : null;
    if (!client) return res.status(404).json({ error: "Client not found." });
    const origin = `${req.protocol}://${req.get("host")}`;
    await stytchClient.passwords.email.resetStart({
      organization_id: client.stytch_organization_id,
      email_address: client.login_email,
      reset_password_redirect_url: `${origin}/client-setup?client_slug=${encodeURIComponent(client.slug)}`,
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: "Could not resend invite." });
  }
});

app.post("/api/admin/clients/:id/deactivate", requireAuth, async (req, res) => {
  try {
    const { status } = await supabase("clients", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(req.params.id)}`,
      body: { active: false },
      useServiceKey: true,
    });
    if (status >= 300) throw new Error("update failed");
    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: "Could not deactivate client." });
  }
});

// ── Client accounts (client-facing) ────────────────────────────────────────────
app.get("/client/:slug/login", async (req, res) => {
  try {
    const client = await getClientBySlug(req.params.slug);
    if (!client || !client.active) return res.status(404).send("Unknown client.");
    res.sendFile(path.join(__dirname, "public", "client-login.html"));
  } catch (err) {
    res.status(502).send("Could not load this page — please try again.");
  }
});

app.get("/client/:slug/set-password", async (req, res) => {
  try {
    const client = await getClientBySlug(req.params.slug);
    if (!client || !client.active) return res.status(404).send("Unknown client.");
    res.sendFile(path.join(__dirname, "public", "client-set-password.html"));
  } catch (err) {
    res.status(502).send("Could not load this page — please try again.");
  }
});

// Fixed path used as the Stytch password-reset/invite redirect URL — Stytch's
// redirect allowlist only supports query-param placeholders, not dynamic path
// segments, so the client's slug travels as ?client_slug= instead of in the
// path here (client-auth.js reads it from either place).
app.get("/client-setup", async (req, res) => {
  try {
    const client = await getClientBySlug(String(req.query.client_slug || ""));
    if (!client || !client.active) return res.status(404).send("Unknown client.");
    res.sendFile(path.join(__dirname, "public", "client-set-password.html"));
  } catch (err) {
    res.status(502).send("Could not load this page — please try again.");
  }
});

app.get("/client/:slug", async (req, res) => {
  try {
    const client = await getClientBySlug(req.params.slug);
    if (!client || !client.active) return res.status(404).send("Unknown client.");
    const session = currentClientSession(req);
    if (!session || session.slug !== client.slug) return res.redirect(`/client/${client.slug}/login`);
    res.sendFile(path.join(__dirname, "public", "client.html"));
  } catch (err) {
    res.status(502).send("Could not load this page — please try again.");
  }
});

app.get("/client/:slug/info", requireClientAuth, async (req, res) => {
  try {
    const client = await getClientBySlug(req.params.slug);
    if (!client) return res.status(404).json({ error: "Unknown client." });
    res.json({ companyName: client.company_name });
  } catch (err) {
    res.status(502).json({ error: "Could not load client info." });
  }
});

app.get("/client/:slug/preview", requireClientAuth, async (req, res) => {
  try {
    const client = await getClientBySlug(req.params.slug);
    if (!client) return res.status(404).send("Unknown client.");
    await ensureRepo();
    sendProductionHtml(res);
  } catch (err) {
    res.status(502).send("Could not load this preview — please try again.");
  }
});

app.post("/client/:slug/auth/password", clientLoginLimit, async (req, res) => {
  if (!stytchClient) return res.status(503).json({ error: "Client login is not configured." });
  let client;
  try { client = await getClientBySlug(req.params.slug); }
  catch { return res.status(502).json({ error: "Could not verify this client — please try again." }); }
  if (!client || !client.active) return res.status(404).json({ error: "Unknown client." });
  const email = (req.body?.email || "").trim().toLowerCase();
  const { password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password required." });

  try {
    const result = await stytchClient.passwords.authenticate({
      organization_id: client.stytch_organization_id,
      email_address: email,
      password,
    });
    if (result.member_authenticated) {
      setClientSessionCookie(res, client.slug, result.member_id);
      return res.json({ ok: true });
    }
    if (result.member.totp_registration_id) {
      return res.json({ mfa: "challenge", intermediateToken: result.intermediate_session_token, memberId: result.member_id });
    }
    const enroll = await stytchClient.totps.create({
      organization_id: client.stytch_organization_id,
      member_id: result.member_id,
      intermediate_session_token: result.intermediate_session_token,
    });
    res.json({ mfa: "enroll", intermediateToken: result.intermediate_session_token, memberId: result.member_id, qrCode: enroll.qr_code, secret: enroll.secret });
  } catch (err) {
    res.status(401).json({ error: "Incorrect email or password." });
  }
});

app.post("/client/:slug/set-password", clientLoginLimit, async (req, res) => {
  if (!stytchClient) return res.status(503).json({ error: "Client login is not configured." });
  let client;
  try { client = await getClientBySlug(req.params.slug); }
  catch { return res.status(502).json({ error: "Could not verify this client — please try again." }); }
  if (!client || !client.active) return res.status(404).json({ error: "Unknown client." });
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: "Missing token or password." });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });

  try {
    const result = await stytchClient.passwords.email.reset({ password_reset_token: token, password });
    if (result.member_authenticated) {
      setClientSessionCookie(res, client.slug, result.member_id);
      return res.json({ ok: true, done: true });
    }
    if (result.member.totp_registration_id) {
      return res.json({ mfa: "challenge", intermediateToken: result.intermediate_session_token, memberId: result.member_id });
    }
    const enroll = await stytchClient.totps.create({
      organization_id: client.stytch_organization_id,
      member_id: result.member_id,
      intermediate_session_token: result.intermediate_session_token,
    });
    res.json({ mfa: "enroll", intermediateToken: result.intermediate_session_token, memberId: result.member_id, qrCode: enroll.qr_code, secret: enroll.secret });
  } catch (err) {
    res.status(401).json({ error: "This link is invalid or has expired — ask for a new invite." });
  }
});

// Shared by both the login MFA challenge and the first-time set-password
// enrollment step — either way, the client is finishing an MFA step started
// by an intermediate_session_token from one of the two routes above.
app.post("/client/:slug/auth/totp", clientLoginLimit, async (req, res) => {
  if (!stytchClient) return res.status(503).json({ error: "Client login is not configured." });
  let client;
  try { client = await getClientBySlug(req.params.slug); }
  catch { return res.status(502).json({ error: "Could not verify this client — please try again." }); }
  if (!client) return res.status(404).json({ error: "Unknown client." });
  const { code, intermediateToken, memberId } = req.body || {};
  if (!code || !intermediateToken || !memberId) return res.status(400).json({ error: "Missing verification code." });

  try {
    const result = await stytchClient.totps.authenticate({
      organization_id: client.stytch_organization_id,
      member_id: memberId,
      code,
      intermediate_session_token: intermediateToken,
      set_default_mfa: true,
    });
    if (!result.member_id) throw new Error("not authenticated");
    setClientSessionCookie(res, client.slug, memberId);
    res.json({ ok: true });
  } catch (err) {
    res.status(401).json({ error: "Incorrect or expired code — please try again." });
  }
});

app.post("/client/:slug/auth/logout", (req, res) => {
  res.setHeader("Set-Cookie", `${CLIENT_COOKIE_NAME}=; HttpOnly; Max-Age=0; Path=/`);
  res.json({ ok: true });
});

app.get("/client/:slug/auth/check", (req, res) => {
  const session = currentClientSession(req);
  res.json({ authed: !!(session && session.slug === req.params.slug) });
});

// ── Anthropic proxy ───────────────────────────────────────────────────────────
app.post("/proxy/anthropic", requireAuth, apiLimit, async (req, res) => {
  try {
    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify(req.body)
    });
    res.status(upstream.status).json(await upstream.json());
  } catch (err) { res.status(502).json({ error: "Upstream failed." }); }
});

// ── CX Dashboard API routes ───────────────────────────────────────────────────
// GET /api/creatives — fetch all creatives (optionally filter by sheet)
app.get("/api/creatives", requireAuth, async (req, res) => {
  const allowed = ["sheet", "status", "market", "format", "order", "limit", "offset", "select"];
  const params = {};
  for (const k of allowed) { if (req.query[k] !== undefined) params[k] = req.query[k]; }
  const { status, data } = await supabase("creatives", { query: new URLSearchParams(params).toString() });
  res.status(status).json(data);
});

// POST /api/creatives/seed — seed the database from RAW_DATA in the prototype
app.post("/api/creatives/seed", requireAuth, async (req, res) => {
  try {
    const { rows } = req.body;
    if (!rows || !Array.isArray(rows)) return res.status(400).json({ error: "rows array required" });
    const { status, data } = await supabase("creatives", {
      method: "POST",
      body: rows,
      useServiceKey: true,
    });
    res.status(status).json(data);
  } catch (err) { res.status(502).json({ error: err.message }); }
});

// PATCH /api/creatives/:rowId — update a creative row
app.patch("/api/creatives/:rowId", requireAuth, async (req, res) => {
  const { status, data } = await supabase("creatives", {
    method: "PATCH",
    query: `row_id=eq.${encodeURIComponent(req.params.rowId)}`,
    body: { ...req.body, updated_at: new Date().toISOString() },
    useServiceKey: true,
  });
  res.status(status).json(data);
});

// POST /api/edit_history — log an edit
app.post("/api/edit_history", requireAuth, async (req, res) => {
  const { status, data } = await supabase("edit_history", {
    method: "POST",
    body: req.body,
    useServiceKey: true,
  });
  res.status(status).json(data);
});

// GET /api/edit_history — fetch history (optionally filter by row_id)
app.get("/api/edit_history", requireAuth, async (req, res) => {
  const params = { order: "edited_at.desc", limit: "100" };
  if (req.query.row_id && /^[a-zA-Z0-9_-]+$/.test(req.query.row_id)) params["row_id"] = `eq.${req.query.row_id}`;
  const { status, data } = await supabase("edit_history", { query: new URLSearchParams(params).toString() });
  res.status(status).json(data);
});

// PUT /api/overrides/:rowId — upsert frame/preview overrides
app.put("/api/overrides/:rowId", requireAuth, async (req, res) => {
  const { status, data } = await supabase("overrides", {
    method: "POST",
    query: "on_conflict=row_id",
    body: { row_id: req.params.rowId, ...req.body, updated_at: new Date().toISOString() },
    useServiceKey: true,
  });
  res.status(status).json(data);
});

// GET /api/overrides — fetch all overrides
app.get("/api/overrides", requireAuth, async (req, res) => {
  const { status, data } = await supabase("overrides", {});
  res.status(status).json(data);
});

// ── Static frontend ───────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ── Boot ──────────────────────────────────────────────────────────────────────
ensureRepo().then(() => {
  app.listen(PORT, () => console.log(`CX Dashboard on :${PORT}`));
}).catch(err => {
  console.error("Boot error:", err);
  app.listen(PORT, () => console.log(`CX Dashboard on :${PORT} (repo not ready)`));
});
