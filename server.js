import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { execSync, exec } from "child_process";
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
const COOKIE_NAME   = "tid_sess";
const COOKIE_TTL_MS = 8 * 60 * 60 * 1000;

const GITHUB_TOKEN  = process.env.GITHUB_TOKEN  || "";
const GITHUB_REPO   = process.env.GITHUB_REPO   || "msquires-crimtan/travelid-japan-prototype";
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
const PROTOTYPE_FILE = "prototype/index.html";
const PROTOTYPE_PUBLIC_URL = "https://sandbox.crimtan.com/prototypes/travelid-japan/v30/index.html";

const REPO_DIR      = __dirname;  // server runs from repo root
const PROTO_PATH    = path.join(__dirname, PROTOTYPE_FILE);

if (!ANTHROPIC_KEY) console.warn("⚠  ANTHROPIC_API_KEY not set");
if (!GITHUB_TOKEN)  console.warn("⚠  GITHUB_TOKEN not set");

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
function git(cmd, cwd = __dirname) {
  return execSync(cmd, { cwd, encoding: "utf-8", env: {
    ...process.env,
    GIT_AUTHOR_NAME: "TravelID Editor",
    GIT_AUTHOR_EMAIL: "editor@crimtan.com",
    GIT_COMMITTER_NAME: "TravelID Editor",
    GIT_COMMITTER_EMAIL: "editor@crimtan.com",
  }}).trim();
}

async function ensurePrototype() { return ensureRepo(); }
async function ensureRepo() {
  if (fs.existsSync(PROTO_PATH)) return; // already in repo

  console.log("Prototype file missing — fetching from public URL…");
  fs.mkdirSync(path.dirname(PROTO_PATH), { recursive: true });
  try {
    const res = await fetch(PROTOTYPE_PUBLIC_URL);
    if (!res.ok) throw new Error("HTTP " + res.status);
    const html = await res.text();
    fs.writeFileSync(PROTO_PATH, html, "utf-8");
    // Commit the fetched file
    await commitAndPush("Add prototype from sandbox.crimtan.com").catch(() => {});
    console.log("Prototype fetched and committed ✓");
  } catch (err) {
    console.error("Could not fetch prototype:", err.message);
    fs.writeFileSync(PROTO_PATH, "<html><body style='font-family:sans-serif;padding:40px'><p>Preview unavailable — prototype could not be fetched.</p></body></html>", "utf-8");
  }
}

async function commitAndPush(message) {
  git(`git add ${PROTOTYPE_FILE}`);
  try { git(`git commit -m "${message.replace(/"/g, "'")}"`); } catch { return; } // nothing to commit
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
  await ensurePrototype();
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
  // Find ALL occurrences and return the first 3 contexts
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
  // Push to GitHub asynchronously
  commitAndPush(message || "Content update via TravelID Editor").catch(console.error);
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
    if (GITHUB_TOKEN) {
      const repoUrl = `https://${GITHUB_TOKEN}@github.com/${GITHUB_REPO}.git`;
      git(`git fetch ${repoUrl} ${GITHUB_BRANCH}`);
      git(`git checkout FETCH_HEAD -- ${PROTOTYPE_FILE}`);
    } else {
      const upstream = await fetch(PROTOTYPE_PUBLIC_URL);
      const html = await upstream.text();
      fs.writeFileSync(PROTO_PATH, html, "utf-8");
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

// ── Supabase PATCH (update) ──────────────────────────────────────────────────
app.patch("/api/hero_stats/:key", requireAuth, apiLimit, async (req, res) => {
  try {
    const { key } = req.params;
    const updates = req.body;
    const result = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/hero_stats?key=eq.${encodeURIComponent(key)}`,
      { method: "PATCH", headers: { "Content-Type": "application/json", "apikey": process.env.SUPABASE_SERVICE_KEY, "Authorization": `Bearer ${process.env.SUPABASE_SERVICE_KEY}`, "Prefer": "return=representation" }, body: JSON.stringify(updates) }
    );
    const data = await result.json();
    res.status(result.status).json(data);
  } catch(err) { res.status(502).json({ error: err.message }); }
});

app.patch("/api/:table", requireAuth, apiLimit, async (req, res) => {
  try {
    const { table } = req.params;
    const { filter_col, filter_val } = req.query;
    let url = `${process.env.SUPABASE_URL}/rest/v1/${table}`;
    if (filter_col && filter_val) url += `?${filter_col}=eq.${encodeURIComponent(filter_val)}`;
    const result = await fetch(url, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "apikey": process.env.SUPABASE_SERVICE_KEY, "Authorization": `Bearer ${process.env.SUPABASE_SERVICE_KEY}`, "Prefer": "return=representation" },
      body: JSON.stringify(req.body)
    });
    const data = await result.json();
    res.status(result.status).json(data);
  } catch(err) { res.status(502).json({ error: err.message }); }
});

app.post("/api/:table", requireAuth, apiLimit, async (req, res) => {
  try {
    const { table } = req.params;
    const result = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/${table}`,
      { method: "POST", headers: { "Content-Type": "application/json", "apikey": process.env.SUPABASE_SERVICE_KEY, "Authorization": `Bearer ${process.env.SUPABASE_SERVICE_KEY}`, "Prefer": "return=representation" }, body: JSON.stringify(req.body) }
    );
    const data = await result.json();
    res.status(result.status).json(data);
  } catch(err) { res.status(502).json({ error: err.message }); }
});

app.delete("/api/:table", requireAuth, apiLimit, async (req, res) => {
  try {
    const { table } = req.params;
    const { filter_col, filter_val } = req.query;
    let url = `${process.env.SUPABASE_URL}/rest/v1/${table}`;
    if (filter_col && filter_val) url += `?${filter_col}=eq.${encodeURIComponent(filter_val)}`;
    const result = await fetch(url, {
      method: "DELETE",
      headers: { "apikey": process.env.SUPABASE_SERVICE_KEY, "Authorization": `Bearer ${process.env.SUPABASE_SERVICE_KEY}` }
    });
    res.status(result.status).json({ ok: result.ok });
  } catch(err) { res.status(502).json({ error: err.message }); }
});

// ── Client portal routes ─────────────────────────────────────────────────────

// Serve client portal page (public — auth handled client-side via Supabase)
app.get("/client", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "client.html"));
});

// Expose Supabase public config (anon key only — safe to expose)
app.get("/client/config", (req, res) => {
  res.json({
    url: process.env.SUPABASE_URL || "",
    anonKey: process.env.SUPABASE_ANON_KEY || ""
  });
});

// Serve prototype to authenticated clients
// Validates Supabase JWT from Authorization header or cookie
app.get("/client/prototype", async (req, res) => {
  const token = req.query.token ||
                req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).send(`<html><body style="font-family:sans-serif;padding:40px;background:#0C0C0E;color:#fff">
      <p>Session expired. <a href="/client" style="color:#FABA8F">Sign in again</a></p>
    </body></html>`);
  }

  // Verify token with Supabase
  try {
    const verify = await fetch(process.env.SUPABASE_URL + "/auth/v1/user", {
      headers: { "apikey": process.env.SUPABASE_ANON_KEY, "Authorization": "Bearer " + token }
    });
    if (!verify.ok) throw new Error("Invalid token");
  } catch {
    return res.status(401).send(`<html><body style="font-family:sans-serif;padding:40px;background:#0C0C0E;color:#fff">
      <p>Session expired. <a href="/client" style="color:#FABA8F">Sign in again</a></p>
    </body></html>`);
  }

  await ensurePrototype();
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.send(fs.readFileSync(PROTO_PATH, "utf-8"));
});

// ── Supabase write routes (PATCH, POST, DELETE) ──────────────────────────────
app.patch("/api/hero_stats/:key", requireAuth, apiLimit, async (req, res) => {
  try {
    const result = await fetch(
      process.env.SUPABASE_URL + "/rest/v1/hero_stats?key=eq." + encodeURIComponent(req.params.key),
      { method: "PATCH", headers: { "Content-Type": "application/json", "apikey": process.env.SUPABASE_SERVICE_KEY, "Authorization": "Bearer " + process.env.SUPABASE_SERVICE_KEY, "Prefer": "return=representation" }, body: JSON.stringify(req.body) }
    );
    res.status(result.status).json(await result.json());
  } catch(err) { res.status(502).json({ error: err.message }); }
});

app.patch("/api/:table", requireAuth, apiLimit, async (req, res) => {
  try {
    const { filter_col, filter_val } = req.query;
    let url = process.env.SUPABASE_URL + "/rest/v1/" + req.params.table;
    if (filter_col && filter_val) url += "?" + filter_col + "=eq." + encodeURIComponent(filter_val);
    const result = await fetch(url, { method: "PATCH", headers: { "Content-Type": "application/json", "apikey": process.env.SUPABASE_SERVICE_KEY, "Authorization": "Bearer " + process.env.SUPABASE_SERVICE_KEY, "Prefer": "return=representation" }, body: JSON.stringify(req.body) });
    res.status(result.status).json(await result.json());
  } catch(err) { res.status(502).json({ error: err.message }); }
});

app.post("/api/:table", requireAuth, apiLimit, async (req, res) => {
  try {
    const result = await fetch(
      process.env.SUPABASE_URL + "/rest/v1/" + req.params.table,
      { method: "POST", headers: { "Content-Type": "application/json", "apikey": process.env.SUPABASE_SERVICE_KEY, "Authorization": "Bearer " + process.env.SUPABASE_SERVICE_KEY, "Prefer": "return=representation" }, body: JSON.stringify(req.body) }
    );
    res.status(result.status).json(await result.json());
  } catch(err) { res.status(502).json({ error: err.message }); }
});

app.delete("/api/:table", requireAuth, apiLimit, async (req, res) => {
  try {
    const { filter_col, filter_val } = req.query;
    let url = process.env.SUPABASE_URL + "/rest/v1/" + req.params.table;
    if (filter_col && filter_val) url += "?" + filter_col + "=eq." + encodeURIComponent(filter_val);
    const result = await fetch(url, { method: "DELETE", headers: { "apikey": process.env.SUPABASE_SERVICE_KEY, "Authorization": "Bearer " + process.env.SUPABASE_SERVICE_KEY } });
    res.status(result.status).json({ ok: result.ok });
  } catch(err) { res.status(502).json({ error: err.message }); }
});

// ── Static frontend ───────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ── Boot ──────────────────────────────────────────────────────────────────────
ensureRepo().then(() => {
  app.listen(PORT, () => console.log(`TravelID Editor on :${PORT}`));
}).catch(err => {
  console.error("Boot error:", err);
  app.listen(PORT, () => console.log(`TravelID Editor on :${PORT} (repo not ready)`));
});
