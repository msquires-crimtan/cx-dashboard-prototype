// ── Constants ─────────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are an expert web developer and AI agent making precise edits to an existing single-page HTML prototype: the Cathay Pacific × Crimtan CX Dashboard (v18).

CRITICAL RULES — read before every response:
1. NEVER rewrite or regenerate the full HTML. This is an EDITING tool only.
2. NEVER say the prototype is a "different product" or refuse a request — it is always the CX Dashboard.
3. Always produce targeted find/replace edits on the existing file.
4. find strings must be EXACT verbatim substrings copied from the source context provided.

WHAT THIS DASHBOARD IS:
- A campaign creative management tool for Cathay Pacific × Crimtan
- Tracks programmatic ad creatives across 8 regional sheets: EUR, HK, NEA, TAM, SAMEA, SEA, SWP, HK-CN
- Uses CSS variables and class-based styles (NOT inline styles)
- Has light/dark theme toggle, row expand panels, column visibility pills, inline dropdowns for CP/Crimtan/Format

KEY HTML STRUCTURES (exact strings for find):

Hero title:
<div class="hero-title">Smarter <em>Creative</em>.<br>Smarter <span>Programmatic</span>.</div>

Hero description:
<div class="hero-desc">Filter by region, destination or language — then click through directly to preview in the Crimtan console.</div>

Header branding:
<div class="logo-client">Cathay Pacific</div>
<div class="logo-sub">Creative Hub · 2025/2026</div>

Theme toggle:
<div class="ts-track" id="ts-track" onclick="toggleTheme()" title="Toggle light/dark theme">

Column visibility pills:
<span class="col-pill locked active" data-col="core" title="Always visible">🔒 Core</span>
<span class="col-pill active" data-col="cp" onclick="toggleCol(this,'cp')"><span class="pill-check">✓</span> CX</span>
<span class="col-pill active" data-col="crimtan" onclick="toggleCol(this,'crimtan')"><span class="pill-check">✓</span> Crimtan</span>

Hero stats (dynamic, populated by JS):
<div><div class="hstat-v" id="s-total">—</div><div class="hstat-l">Creatives</div></div>
<div><div class="hstat-v teal" id="s-live">—</div><div class="hstat-l">Live</div></div>
<div><div class="hstat-v rose" id="s-mkt">—</div><div class="hstat-l">Markets</div></div>
<div><div class="hstat-v sun" id="s-dst">—</div><div class="hstat-l">Destinations</div></div>

CSS variable names: --dp (deep bg), --tp (panel bg), --rose (#FF006E), --blue (#161689), --teal (#00B5B8), --sun (#FFD166), --text, --text2, --text3, --border, --border2, --bg2, --bg3, --rl (border radius)

You can make ANY change the user requests:
- Text, copy, headlines, labels, numbers
- New data columns or filters
- Styling (colours, fonts, layout) — use CSS variables
- New features or interactive elements
- API integrations

WORKFLOW — for every user request that changes the prototype:
1. Read the source context provided
2. Identify the exact text to change
3. Call the apply_edit tool once per change — call it multiple times in the same turn for multiple changes
4. After the tool call(s), give a brief plain-English summary of what changed

Rules:
- find must be verbatim from the source context — never reconstruct or guess
- find must uniquely identify ONE location — this file has hundreds of near-identical repeated rows/blocks, so a short or generic find string can silently match more than one place. Include enough surrounding context (a nearby id, row value, or neighbouring tag) to make it unique. The edit is rejected if find matches more than once.
- For new sections: find a unique anchor tag and append new code after it
- If the request doesn't require changing the prototype (a question, clarification, etc.), just reply in text — do not call apply_edit

Always use the source context provided. Be confident and concise. Never refuse — attempt every change.`;

const APPLY_EDIT_TOOL = {
  name: "apply_edit",
  description: "Apply one exact find/replace edit to the CX Dashboard prototype HTML. Call once per change; call it multiple times in the same turn for multiple changes.",
  input_schema: {
    type: "object",
    properties: {
      find: { type: "string", description: "Exact verbatim substring to find in the prototype HTML, copied from the provided source context." },
      replace: { type: "string", description: "The replacement text." }
    },
    required: ["find", "replace"],
    additionalProperties: false
  },
  strict: true
};

// Chat/edit history is a shared, site-wide record (Supabase-backed) — every
// logged-in user sees every turn from everyone, not just their own session.
let sharedLog = [];
let currentUserEmail = null;

function senderName(email) {
  if (!email) return "Shared login";
  const local = email.split("@")[0].replace(/[._]+/g, " ");
  return local.replace(/\b\w/g, c => c.toUpperCase());
}

function initials(name) {
  const parts = String(name || "").trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

const COMPASS_ICON_SVG = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="#fff" stroke-width="1.5"/><circle cx="12" cy="12" r="3" fill="#fff"/><line x1="12" y1="2" x2="12" y2="6" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/><line x1="12" y1="18" x2="12" y2="22" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/><line x1="2" y1="12" x2="6" y2="12" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/><line x1="18" y1="12" x2="22" y2="12" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/></svg>';

// ── Auth ──────────────────────────────────────────────────────────────────────
const gateEl    = document.getElementById("gate");
const appEl     = document.getElementById("app");
const emailEl   = document.getElementById("email");
const pwEl      = document.getElementById("pw");
const loginBtn  = document.getElementById("login-btn");
const pwErr     = document.getElementById("pw-err");
const logoutBtn = document.getElementById("logout-btn");
const undoBtn   = document.getElementById("undo-btn");
const resetBtn  = document.getElementById("reset-btn");
const forgotLink = document.getElementById("forgot-link");
const forgotNote = document.getElementById("forgot-note");
const modeToggle = document.getElementById("mode-toggle");
const gateSub    = document.getElementById("gate-sub");

let authMode = "login"; // "login" | "register"

forgotLink.addEventListener("click", () => {
  const showing = forgotNote.style.display === "block";
  forgotNote.style.display = showing ? "none" : "block";
  forgotLink.textContent = showing ? "Forgot password?" : "Hide";
});

modeToggle.addEventListener("click", () => {
  authMode = authMode === "login" ? "register" : "login";
  pwErr.style.display = "none";
  if (authMode === "register") {
    loginBtn.textContent = "Create account";
    modeToggle.textContent = "Already have an account? Sign in";
    gateSub.textContent = "Create an account with your @crimtan.com email";
    pwEl.setAttribute("autocomplete", "new-password");
  } else {
    loginBtn.textContent = "Sign in";
    modeToggle.textContent = "New here? Create an account";
    gateSub.textContent = "AI content editor — authorised access only";
    pwEl.setAttribute("autocomplete", "current-password");
  }
});

function showApp() {
  gateEl.style.display = "none";
  appEl.classList.add("on");
  txtEl.focus();
  statusEl.querySelector("span").textContent = "Setting up prototype…";
  loadInitialChat();
  waitForPrototype().then(ready => {
    if (ready) loadPreview();
    else statusEl.querySelector("span").textContent = "Prototype unavailable — try refreshing.";
  });
}

fetch("/auth/check", { credentials: "same-origin" })
  .then(r => r.json()).then(d => { if (d.authed) { currentUserEmail = d.email || null; showApp(); } }).catch(() => {});

function submitAuth() {
  const email = emailEl.value.trim();
  const pw = pwEl.value;
  if (!pw) return;
  if (authMode === "register" && !email) {
    pwErr.textContent = "Email required.";
    pwErr.style.display = "block";
    return;
  }
  loginBtn.disabled = true;
  loginBtn.textContent = authMode === "register" ? "Creating…" : "Checking…";
  pwErr.style.display = "none";

  const endpoint = authMode === "register" ? "/auth/register" : "/auth/login";
  fetch(endpoint, { method: "POST", headers: {"Content-Type":"application/json"}, credentials: "same-origin", body: JSON.stringify({ email, password: pw }) })
    .then(async res => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Something went wrong.");
      currentUserEmail = email || null;
      showApp();
    })
    .catch(err => {
      pwErr.textContent = err.message || (authMode === "register" ? "Could not create account." : "Incorrect email or password.");
      pwErr.style.display = "block";
      loginBtn.disabled = false;
      loginBtn.textContent = authMode === "register" ? "Create account" : "Sign in";
    });
}

emailEl.addEventListener("keydown", e => { if (e.key === "Enter") submitAuth(); });
pwEl.addEventListener("keydown", e => { if (e.key === "Enter") submitAuth(); });
loginBtn.addEventListener("click", submitAuth);

logoutBtn.addEventListener("click", async () => {
  await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
  location.reload();
});

// Undo (topbar button = roll back the most recent still-active change,
// from anyone — the shared log, not a per-session stack)
undoBtn.addEventListener("click", () => {
  const latest = [...sharedLog].reverse().find(t => t.edit_count > 0 && !t.rolled_back);
  if (latest) rollbackTurn(latest.id, undoBtn);
});

// Reset to published version — this only re-checks-out the file from git;
// the shared chat/edit history is a record of the site and isn't affected.
resetBtn.addEventListener("click", async () => {
  if (!confirm("Reset the preview to the published version? This will undo all local changes.")) return;
  resetBtn.classList.add("spinning");
  try {
    await fetch("/prototype/refresh", { method: "POST", credentials: "same-origin" });
    loadPreview(true);
    addMsg("assistant", "✓ Preview reset to the published version.", null, true);
  } catch { addMsg("assistant", "Reset failed — try again.", null, true); }
  resetBtn.classList.remove("spinning");
});

// ── Tabs ──────────────────────────────────────────────────────────────────────
const chatView    = document.getElementById("chat-view");
const historyView = document.getElementById("history-view");

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    if (tab.dataset.tab === "chat") {
      chatView.style.display = "flex";
      historyView.classList.remove("active");
    } else {
      chatView.style.display = "none";
      historyView.classList.add("active");
    }
  });
});

function renderHistory() {
  const empty = document.getElementById("h-empty");
  const existing = historyView.querySelectorAll(".h-item");
  existing.forEach(e => e.remove());
  const entries = sharedLog.filter(t => t.edit_count > 0 || (t.user_message || "").startsWith("(reverted"));
  if (entries.length === 0) { empty.style.display = "block"; return; }
  empty.style.display = "none";
  [...entries].reverse().forEach(turn => {
    const el = document.createElement("div");
    el.className = "h-item" + (turn.rolled_back ? " rolled-back" : "");
    const time = new Date(turn.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    el.innerHTML = `
      <div class="h-item-meta">
        <span class="h-item-who">${esc(senderName(turn.email))}</span>
        <span class="h-item-time">${time}</span>
      </div>
      <div class="h-item-desc">${esc(turn.assistant_summary || turn.user_message)}</div>`;
    if (turn.edit_count > 0 && !turn.rolled_back) {
      const btn = document.createElement("button");
      btn.className = "h-undo-btn";
      btn.innerHTML = '<i class="ti ti-arrow-back-up" style="font-size:10px"></i> Roll back here';
      btn.addEventListener("click", () => rollbackTurn(turn.id, btn));
      el.appendChild(btn);
    }
    historyView.appendChild(el);
  });
}

// Re-fetch the shared log (after sending a message or rolling back) and
// refresh the History tab + Undo button state. Does NOT touch the chat feed
// — that's only replayed once, at initial load, via loadInitialChat().
async function refreshSharedLog() {
  try {
    const res = await fetch("/api/chat/log", { credentials: "same-origin" });
    sharedLog = await res.json();
    if (!Array.isArray(sharedLog)) sharedLog = [];
  } catch { sharedLog = []; }
  renderHistory();
  syncChatChipsWithLog();
  undoBtn.disabled = !sharedLog.some(t => t.edit_count > 0 && !t.rolled_back);
}

// Rolling back a turn from the History tab (or the topbar Undo button) should
// also update that turn's own chat bubble if it's already rendered, so a
// stale "N changes applied" + still-clickable revert link doesn't linger.
function syncChatChipsWithLog() {
  sharedLog.filter(t => t.rolled_back).forEach(turn => {
    const mi = msgsEl.querySelector(`[data-turn-id="${turn.id}"]`);
    if (!mi) return;
    const chip = mi.querySelector(".chip");
    if (chip) { chip.className = "chip info"; chip.innerHTML = '<i class="ti ti-arrow-back-up" style="font-size:11px"></i>Reverted'; }
    mi.querySelector(".revert-link")?.remove();
  });
}

// Replay the full shared conversation into the chat feed — called once at
// login, so every user sees the same thread regardless of who said what.
async function loadInitialChat() {
  await refreshSharedLog();
  // Only greet on a fresh/empty project — once there's real shared history,
  // showing "I'm Compass AI" again on every login is just noise.
  if (sharedLog.some(t => t.user_message)) {
    document.getElementById("intro-msg-1")?.remove();
    document.getElementById("intro-msg-2")?.remove();
  }
  sharedLog.forEach(turn => {
    if (!turn.user_message) return;
    addMsg("user", esc(turn.user_message), null, false, senderName(turn.email));
    const chips = [];
    if (turn.edit_count > 0) {
      chips.push(turn.rolled_back
        ? { type: "info", icon: "arrow-back-up", label: "Reverted" }
        : { type: "done", icon: "circle-check", label: `${turn.edit_count} change${turn.edit_count > 1 ? "s" : ""} applied` });
    }
    const assistantMi = addMsg("assistant", esc(turn.assistant_summary || ""), chips, false, "Compass AI");
    if (turn.edit_count > 0 && !turn.rolled_back) addRevertLink(assistantMi, turn.id);
  });
}

function addRevertLink(mi, turnId) {
  mi.dataset.turnId = turnId;
  const btn = document.createElement("button");
  btn.className = "revert-link";
  btn.innerHTML = '<i class="ti ti-arrow-back-up" style="font-size:10px"></i> Revert this change';
  btn.addEventListener("click", () => rollbackTurn(turnId, btn));
  mi.appendChild(btn);
}

async function rollbackTurn(turnId, btnEl) {
  if (!confirm("Roll back to how the prototype looked right before this change? (This itself becomes a new entry you can revert.)")) return;
  if (btnEl) btnEl.disabled = true;
  try {
    const res = await fetch(`/api/chat/turn/${turnId}/rollback`, { method: "POST", credentials: "same-origin" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "Rollback failed.");
    loadPreview(true);
    setTimeout(flashPreview, 600);
    await refreshSharedLog();
    addMsg("assistant", "↩ Reverted to the state before that change.", null, true);
  } catch (err) {
    addMsg("assistant", `Revert failed: ${esc(err.message)}`, null, true);
  } finally {
    if (btnEl) btnEl.disabled = false;
  }
}

// ── Preview ───────────────────────────────────────────────────────────────────
const iframeEl    = document.getElementById("preview-iframe");
const statusEl    = document.getElementById("preview-status");
const previewWrap = document.getElementById("preview-wrap");
const refreshBtn  = document.getElementById("refresh-btn");

function loadPreview(force = false) {
  iframeEl.classList.remove("loaded");
  statusEl.style.display = "flex";
  iframeEl.src = "/prototype?t=" + Date.now() + (force ? "&force=1" : "");
}

// Poll until prototype is ready, then load
async function waitForPrototype() {
  for (let i = 0; i < 20; i++) {
    try {
      const r = await fetch("/prototype/ready", { credentials: "same-origin" });
      const d = await r.json();
      if (d.ready) return true;
    } catch {}
    await new Promise(res => setTimeout(res, 2000));
  }
  return false;
}

iframeEl.addEventListener("load", () => {
  iframeEl.classList.add("loaded");
  statusEl.style.display = "none";
});

function flashPreview() {
  previewWrap.classList.remove("flash");
  void previewWrap.offsetWidth;
  previewWrap.classList.add("flash");
}

refreshBtn.addEventListener("click", async () => {
  refreshBtn.classList.add("spinning");
  await fetch("/prototype/refresh", { method: "POST", credentials: "same-origin" }).catch(() => {});
  loadPreview(true);
  setTimeout(() => refreshBtn.classList.remove("spinning"), 1500);
});

// ── Chat ──────────────────────────────────────────────────────────────────────
const msgsEl = document.getElementById("msgs");
const txtEl  = document.getElementById("txt");
const sndEl  = document.getElementById("snd");
let busy = false, history = [];

const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
const scroll = () => msgsEl.scrollTop = msgsEl.scrollHeight;
const now = () => new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

function addMsg(role, html, chips, system = false, sender = null) {
  const wrap = document.createElement("div");
  wrap.className = `msg ${system ? "assistant" : role} fi`;
  const av = document.createElement("div");
  av.className = `av ${role === "user" ? "user" : "ai"}`;
  if (system) av.innerHTML = '<i class="ti ti-info-circle"></i>';
  else if (role === "user") av.textContent = initials(sender);
  else av.innerHTML = COMPASS_ICON_SVG;
  const mi = document.createElement("div"); mi.className = "mi";
  if (sender) {
    const senderEl = document.createElement("div");
    senderEl.className = "msg-sender";
    senderEl.textContent = sender;
    mi.appendChild(senderEl);
  }
  const bub = document.createElement("div"); bub.className = "bub";
  if (system) { bub.style.background = "var(--b50)"; bub.style.borderColor = "var(--b100)"; bub.style.color = "var(--b600)"; }
  bub.innerHTML = html;
  mi.appendChild(bub);
  (chips || []).forEach(c => {
    const el = document.createElement("div");
    el.className = `chip ${c.type}`; if (c.id) el.id = c.id;
    el.innerHTML = `<i class="ti ti-${c.icon}" style="font-size:11px"></i>${c.label}`;
    mi.appendChild(el);
  });
  wrap.appendChild(av); wrap.appendChild(mi);
  msgsEl.appendChild(wrap); scroll(); return mi;
}

function addThinking(label) {
  const wrap = document.createElement("div"); wrap.id = "thinking"; wrap.className = "msg assistant fi";
  const av = document.createElement("div"); av.className = "av ai"; av.innerHTML = COMPASS_ICON_SVG;
  const bub = document.createElement("div"); bub.className = "bub";
  bub.style.background = "var(--g50)"; bub.style.border = "0.5px solid var(--g100)";
  bub.innerHTML = `<div style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--g600)">
    <i class="ti ti-loader" style="animation:spin .7s linear infinite;display:inline-block;font-size:14px;color:var(--t600)"></i>
    <span id="thinking-label">${label || "Reading prototype & thinking…"}</span>
  </div>`;
  wrap.appendChild(av); wrap.appendChild(bub); msgsEl.appendChild(wrap); scroll();
}
function updateThinking(label) {
  const el = document.getElementById("thinking-label");
  if (el) el.textContent = label;
}
function removeThinking() { document.getElementById("thinking")?.remove(); }

async function proxyPost(ep, body) {
  const res = await fetch(ep, { method: "POST", headers: {"Content-Type":"application/json"}, credentials: "same-origin", body: JSON.stringify(body) });
  if (res.status === 401) { location.reload(); throw new Error("session_expired"); }
  const data = await res.json();
  if (!res.ok || data.type === "error") {
    throw new Error(data?.error?.message || `Request failed (${res.status}).`);
  }
  return data;
}

// Fetch targeted excerpts from the prototype around a keyword
async function fetchSourceContext(keyword) {
  if (!keyword) return null;
  try {
    const res = await fetch("/prototype/search?q=" + encodeURIComponent(keyword), { credentials: "same-origin" });
    const data = await res.json();
    if (!data.found) return null;
    return data.contexts.map(function(c, i) { return "--- Context " + (i+1) + " (line " + c.line + ") ---\n" + c.context; }).join("\n\n");
  } catch(e) { return null; }
}

async function callClaude(userMsg) {
  // Before sending to Claude, fetch relevant source context so edits are precise
  const context = await fetchSourceContext(extractKeyword(userMsg));

  const enrichedMsg = context
    ? `${userMsg}\n\n<prototype_source_context>\n${context}\n</prototype_source_context>\n\nUse the exact text from the source context above when constructing your apply_edit find strings.`
    : userMsg;

  history.push({ role: "user", content: enrichedMsg });
  const data = await proxyPost("/proxy/anthropic", {
    model: "claude-sonnet-5",
    max_tokens: 4000,
    system: SYSTEM_PROMPT,
    tools: [APPLY_EDIT_TOOL],
    messages: history
  });
  const content = data.content || [];
  const text = content.filter(b => b.type === "text").map(b => b.text).join("");
  const edits = content.filter(b => b.type === "tool_use" && b.name === "apply_edit").map(b => b.input);
  // Store clean version in history (text only — tool_use blocks aren't persisted
  // since we never send matching tool_result turns back)
  history.push({ role: "assistant", content: text });
  return { text, edits };
}

// Extract a likely keyword from the user's message to find relevant source context
function extractKeyword(msg) {
  // Pull quoted strings first
  const quoted = msg.match(/"([^"]+)"/);
  if (quoted) return quoted[1];
  // Otherwise use longest word that's likely a content term
  const words = msg.split(/\s+/).filter(w => w.length > 4 && !/^(change|update|add|make|the|this|that|with|from|into|show|find|replace)/i.test(w));
  return words[0] || msg.split(" ").slice(0, 3).join(" ");
}

// Apply all of this turn's edits atomically and log the turn to the shared,
// site-wide history in one call (replaces the old per-edit /prototype/edit
// loop — one write, one git commit, one history row per chat turn).
async function applyTurn(userMessage, edits, summary) {
  const res = await fetch("/api/chat/turn", {
    method: "POST", headers: {"Content-Type":"application/json"},
    credentials: "same-origin",
    body: JSON.stringify({ user_message: userMessage, edits, summary })
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Could not apply changes.");
  return { results: data.results || [], turnId: data.turnId || null };
}

async function handleSend() {
  const text = txtEl.value.trim(); if (!text || busy) return;
  busy = true; sndEl.disabled = true; txtEl.value = ""; txtEl.style.height = "auto";
  addMsg("user", esc(text), null, false, senderName(currentUserEmail));
  addThinking("Reading prototype source…");

  try {
    updateThinking("Thinking about your change…");
    const reply = await callClaude(text);
    removeThinking();

    const edits = reply.edits;
    const summary = reply.text.trim();

    if (edits.length > 0) {
      const chipId = "chip-" + Date.now();
      const assistantMi = addMsg("assistant", esc(summary) || "Applying changes…", [
        { type: "working", icon: "loader", label: `Applying ${edits.length} edit${edits.length > 1 ? "s" : ""}…`, id: chipId }
      ], false, "Compass AI");

      const { results, turnId } = await applyTurn(text, edits, summary);
      const failed = results.filter(r => !r.ok);
      const succeeded = results.filter(r => r.ok);

      const chip = document.getElementById(chipId);
      if (failed.length === 0) {
        if (chip) { chip.className = "chip done"; chip.innerHTML = '<i class="ti ti-circle-check" style="font-size:11px"></i>Applied — updating preview…'; }
        loadPreview(true);
        setTimeout(() => {
          flashPreview();
          if (chip) { chip.className = "chip done"; chip.innerHTML = `<i class="ti ti-circle-check" style="font-size:11px"></i>${edits.length} change${edits.length > 1 ? "s" : ""} applied`; }
        }, 600);

        if (turnId) addRevertLink(assistantMi, turnId);
        await refreshSharedLog();
      } else {
        const msg = failed.map(f => `${esc(f.error || "Edit failed")}: <code>${esc(f.find.substring(0, 60))}…</code>`).join("<br>");
        if (chip) { chip.className = "chip error"; chip.innerHTML = `<i class="ti ti-alert-circle" style="font-size:11px"></i>${failed.length} edit${failed.length > 1 ? "s" : ""} failed`; }
        addMsg("assistant", `Some edits couldn't be applied:<br>${msg}<br><br>Try rephrasing or being more specific about what to change.`, null, true);
        if (succeeded.length > 0) {
          loadPreview(true); setTimeout(flashPreview, 600);
          if (turnId) addRevertLink(assistantMi, turnId);
          await refreshSharedLog();
        }
      }
    } else {
      // No edits — just a conversational response
      addMsg("assistant", esc(summary || "I didn't make any changes — could you rephrase what you'd like updated?"), null, false, "Compass AI");
    }
  } catch (err) {
    if (err.message !== "session_expired") {
      removeThinking();
      addMsg("assistant", `Something went wrong: ${esc(err.message || "please try again.")}`, [{ type: "error", icon: "alert-circle", label: "Error" }]);
    }
  }

  busy = false; sndEl.disabled = false; txtEl.focus();
}

sndEl.addEventListener("click", handleSend);
txtEl.addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); } });
txtEl.addEventListener("input", () => { txtEl.style.height = "auto"; txtEl.style.height = Math.min(txtEl.scrollHeight, 120) + "px"; });

// ── View code modal ───────────────────────────────────────────────────────────
const codeBtn      = document.getElementById("code-btn");
const codeModal     = document.getElementById("code-modal");
const codeModalPre  = document.getElementById("code-modal-pre");
const codeModalCopy = document.getElementById("code-modal-copy");

[document.getElementById("code-modal-close"), document.getElementById("code-modal-close-2")].forEach(btn => {
  btn.addEventListener("click", () => codeModal.classList.remove("open"));
});

codeBtn.addEventListener("click", async () => {
  codeModal.classList.add("open");
  codeModalPre.textContent = "Loading…";
  try {
    const res = await fetch("/prototype", { credentials: "same-origin" });
    codeModalPre.textContent = await res.text();
  } catch {
    codeModalPre.textContent = "Failed to load source.";
  }
});

codeModalCopy.addEventListener("click", () => {
  navigator.clipboard.writeText(codeModalPre.textContent).then(() => {
    const original = codeModalCopy.textContent;
    codeModalCopy.textContent = "Copied!";
    setTimeout(() => { codeModalCopy.textContent = original; }, 1200);
  });
});

// ── Full-screen preview ───────────────────────────────────────────────────────
const fullscreenBtn = document.getElementById("fullscreen-btn");
fullscreenBtn.addEventListener("click", () => {
  const isFullscreen = appEl.classList.toggle("preview-fullscreen");
  fullscreenBtn.innerHTML = isFullscreen
    ? '<i class="ti ti-arrows-minimize" style="font-size:12px"></i> Exit full screen'
    : '<i class="ti ti-arrows-maximize" style="font-size:12px"></i> Full screen';
});
