import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import rateLimit from "express-rate-limit";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "10mb" }));

// ── Environment ───────────────────────────────────────────────────────────────
const PORT          = process.env.PORT          || 8080;
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || "";
const APP_PASSWORD  = process.env.APP_PASSWORD  || "changeme";
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
function setSessionCookie(res) {
  const token = signToken({ ok: true, exp: Date.now() + COOKIE_TTL_MS });
  const flags = [`${COOKIE_NAME}=${encodeURIComponent(token)}`, "HttpOnly", "SameSite=Lax", `Max-Age=${COOKIE_TTL_MS / 1000}`, "Path=/"];
  if (IS_PROD) flags.push("Secure");
  res.setHeader("Set-Cookie", flags.join("; "));
}

// ── Rate limits ───────────────────────────────────────────────────────────────
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const apiLimit   = rateLimit({ windowMs: 60 * 1000, max: 30 });

function requireAuth(req, res, next) {
  if (isAuthed(req)) return next();
  res.status(401).json({ error: "Not authenticated." });
}

// ── Auth routes ───────────────────────────────────────────────────────────────
app.post("/auth/login", loginLimit, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password required." });
  const match = crypto.timingSafeEqual(
    Buffer.from(password.padEnd(128).slice(0, 128)),
    Buffer.from(APP_PASSWORD.padEnd(128).slice(0, 128))
  ) && password === APP_PASSWORD;
  if (!match) return res.status(401).json({ error: "Incorrect password." });
  setSessionCookie(res);
  res.json({ ok: true });
});
app.post("/auth/logout", (req, res) => {
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=; HttpOnly; Max-Age=0; Path=/`);
  res.json({ ok: true });
});
app.get("/auth/check", (req, res) => res.json({ authed: isAuthed(req) }));

// ── Git helpers ───────────────────────────────────────────────────────────────
function git(cmd) {
  return execSync(cmd, { cwd: REPO_DIR, encoding: "utf-8", env: {
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
      execSync(`git clone ${repoUrl} ${REPO_DIR}`, {
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
  git(`git add ${PROTOTYPE_FILE}`);
  try { git(`git commit -m "${message.replace(/"/g, "'")}"`); } catch { return; }
  const repoUrl = `https://${GITHUB_TOKEN}@github.com/${GITHUB_REPO}.git`;
  git(`git push ${repoUrl} ${GITHUB_BRANCH}`);
  console.log("Pushed:", message);
}

// ── Undo stack ────────────────────────────────────────────────────────────────
const undoStack = [];

// ── Prototype routes ──────────────────────────────────────────────────────────
app.get("/prototype/ready", requireAuth, (req, res) => {
  res.json({ ready: fs.existsSync(PROTO_PATH) });
});

app.get("/prototype", requireAuth, async (req, res) => {
  await ensureRepo();
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Cache-Control", "no-store");
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

app.post("/prototype/edit", requireAuth, async (req, res) => {
  const { find, replace, message } = req.body;
  if (!find || replace === undefined) return res.status(400).json({ error: "find and replace required" });
  await ensureRepo();
  let html = fs.readFileSync(PROTO_PATH, "utf-8");
  if (!html.includes(find)) return res.status(404).json({ error: "Text not found", find: find.substring(0, 100) });
  undoStack.push(html); if (undoStack.length > 20) undoStack.shift();
  html = html.split(find).join(replace);
  fs.writeFileSync(PROTO_PATH, html, "utf-8");
  commitAndPush(message || "Content update via CX Dashboard editor").catch(console.error);
  res.json({ ok: true });
});

app.post("/prototype/undo", requireAuth, async (req, res) => {
  if (undoStack.length === 0) return res.status(400).json({ error: "Nothing to undo" });
  const prev = undoStack.pop();
  fs.writeFileSync(PROTO_PATH, prev, "utf-8");
  commitAndPush("Undo last change").catch(console.error);
  res.json({ ok: true, remaining: undoStack.length });
});

app.post("/prototype/refresh", requireAuth, async (req, res) => {
  try {
    if (GITHUB_TOKEN && fs.existsSync(path.join(REPO_DIR, ".git"))) {
      const repoUrl = `https://${GITHUB_TOKEN}@github.com/${GITHUB_REPO}.git`;
      git(`git fetch ${repoUrl} ${GITHUB_BRANCH}`);
      git(`git checkout FETCH_HEAD -- ${PROTOTYPE_FILE}`);
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
const ALLOWED_TABLES = ["creatives", "edit_history", "overrides"];

// GET /api/creatives — fetch all creatives (optionally filter by sheet)
app.get("/api/creatives", requireAuth, async (req, res) => {
  const query = new URLSearchParams(req.query).toString();
  const { status, data } = await supabase("creatives", { query });
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
  const query = new URLSearchParams({ ...req.query, order: "edited_at.desc", limit: "100" }).toString();
  const { status, data } = await supabase("edit_history", { query });
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
