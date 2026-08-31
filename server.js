import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { execFileSync } from "child_process";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

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

function requireAuth(req, res, next) {
  if (isAuthed(req)) return next();
  res.status(401).json({ error: "Not authenticated." });
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
  const repoUrl = `https://${GITHUB_TOKEN}@github.com/${GITHUB_REPO}.git`;

  if (fs.existsSync(path.join(REPO_DIR, ".git")) && fs.existsSync(PROTO_PATH)) {
    console.log("Repo ready ✓");
    return;
  }

  if (!fs.existsSync(path.join(REPO_DIR, ".git"))) {
    console.log("Cloning repo…");
    fs.mkdirSync(REPO_DIR, { recursive: true });
    try {
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
      console.log("Repo cloned ✓");
    } catch (err) {
      console.error("Clone failed:", err.message);
    }
  }

  // If prototype still missing after clone, write a placeholder
  if (!fs.existsSync(PROTO_PATH)) {
    console.log("Prototype file missing — writing placeholder…");
    fs.mkdirSync(path.dirname(PROTO_PATH), { recursive: true });
    fs.writeFileSync(PROTO_PATH, "<html><body style='font-family:sans-serif;padding:40px'><p>Prototype not yet loaded.</p></body></html>", "utf-8");
  }
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

// ── Prototype routes ──────────────────────────────────────────────────────────
app.get("/prototype/ready", requireAuth, (req, res) => {
  res.json({ ready: fs.existsSync(PROTO_PATH) });
});

app.get("/prototype", requireAuth, async (req, res) => {
  await ensureRepo();
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
});

app.get("/prototype/search", requireAuth, async (req, res) => {
  const keyword = req.query.q || "";
  if (!keyword) return res.status(400).json({ error: "q required" });
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
});

// A "turn" = one chat request's worth of edits, applied and logged atomically.
// The whole-site chat/edit history lives in Supabase (cxdashboard.chat_log),
// not in server memory or per-session state — every logged-in user sees the
// same shared record, and any turn can be rolled back by anyone, matching how
// Lovable's chat history works.
app.post("/api/chat/turn", requireAuth, async (req, res) => {
  const { user_message, edits, summary } = req.body;
  if (!Array.isArray(edits)) return res.status(400).json({ error: "edits array required" });
  await ensureRepo();
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
