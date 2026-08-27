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

WORKFLOW — for every user request:
1. Read the source context provided
2. Identify the exact text to change
3. Produce ONE OR MORE edits using this EXACT format:

[EDIT]: find:"EXACT_TEXT_TO_FIND" replace:"REPLACEMENT_TEXT"

Rules:
- find must be verbatim from the source context — never reconstruct or guess
- For new sections: find a unique anchor tag and append new code after it
- Use \" to escape quotes inside strings
- Multiple [EDIT] lines are applied in order
- After edits, give a brief plain-English summary

Always use the source context provided. Be confident and concise. Never refuse — attempt every change.`;

let changeHistory = [];
let undoCount = 0;

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
  waitForPrototype().then(ready => {
    if (ready) loadPreview();
    else statusEl.querySelector("span").textContent = "Prototype unavailable — try refreshing.";
  });
}

fetch("/auth/check", { credentials: "same-origin" })
  .then(r => r.json()).then(d => { if (d.authed) showApp(); }).catch(() => {});

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

// Undo (topbar button = undo latest)
undoBtn.addEventListener("click", () => rollbackTo(changeHistory.length - 2));

// Reset to published version
resetBtn.addEventListener("click", async () => {
  if (!confirm("Reset the preview to the published version? This will undo all local changes.")) return;
  resetBtn.classList.add("spinning");
  try {
    await fetch("/prototype/refresh", { method: "POST", credentials: "same-origin" });
    changeHistory = []; undoBtn.disabled = true;
    renderHistory();
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
  if (changeHistory.length === 0) { empty.style.display = "block"; return; }
  empty.style.display = "none";
  [...changeHistory].reverse().forEach((item, i) => {
    const el = document.createElement("div");
    el.className = "h-item";
    // i=0 is most recent; only most recent can be undone via server undo
    const isLatest = i === 0;
    const targetIdx = changeHistory.length - 1 - i;
    el.innerHTML = `
      <div class="h-item-meta">
        <span class="h-item-time">${item.time}</span>
        <button class="h-undo-btn" title="${isLatest ? 'Undo this change' : 'Roll back to this point'}">
          <i class="ti ti-arrow-back-up" style="font-size:10px"></i> ${isLatest ? 'Undo' : 'Roll back here'}
        </button>
      </div>
      <div class="h-item-desc">${esc(item.desc)}</div>`;
    el.querySelector(".h-undo-btn").addEventListener("click", () => rollbackTo(targetIdx));
    historyView.appendChild(el);
  });
}

async function rollbackTo(targetIdx) {
  // targetIdx is the index in changeHistory we want to roll back to
  // We need to undo (changeHistory.length - 1 - targetIdx) times
  const stepsToUndo = changeHistory.length - 1 - targetIdx;
  if (stepsToUndo <= 0) return;
  if (!confirm("Roll back " + stepsToUndo + " change" + (stepsToUndo > 1 ? "s" : "") + "? This cannot be re-done.")) return;
  for (let i = 0; i < stepsToUndo; i++) {
    const res = await fetch("/prototype/undo", { method: "POST", credentials: "same-origin" });
    const data = await res.json();
    if (!data.ok) break;
    changeHistory.pop();
  }
  undoBtn.disabled = changeHistory.length === 0;
  renderHistory();
  loadPreview(true);
  addMsg("assistant", "↩ Rolled back " + stepsToUndo + " change" + (stepsToUndo > 1 ? "s" : "") + ".", null, true);
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

function addMsg(role, html, chips, system = false) {
  const wrap = document.createElement("div");
  wrap.className = `msg ${system ? "assistant" : role} fi`;
  const av = document.createElement("div");
  av.className = `av ${role === "user" ? "user" : "ai"}`;
  av.innerHTML = system ? '<i class="ti ti-info-circle"></i>' : (role === "user" ? '<i class="ti ti-user"></i>' : '<i class="ti ti-plane-tilt"></i>');
  const mi = document.createElement("div"); mi.className = "mi";
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
  const av = document.createElement("div"); av.className = "av ai"; av.innerHTML = '<i class="ti ti-plane-tilt"></i>';
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
    ? `${userMsg}\n\n<prototype_source_context>\n${context}\n</prototype_source_context>\n\nUse the exact text from the source context above when constructing your [EDIT] find strings.`
    : userMsg;

  history.push({ role: "user", content: enrichedMsg });
  const data = await proxyPost("/proxy/anthropic", {
    model: "claude-sonnet-5",
    max_tokens: 4000,
    system: SYSTEM_PROMPT,
    messages: history
  });
  const text = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("");
  // Store clean version in history (without the source context)
  history.push({ role: "assistant", content: text });
  return text;
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

// Parse all [EDIT] blocks from Claude's response
function parseEdits(reply) {
  const edits = [];
  // Match [EDIT]: find:"..." replace:"..."
  const re = /\[EDIT\]:\s*find:"((?:[^"\\]|\\.)*)"\s+replace:"((?:[^"\\]|\\.)*)"/gs;
  let m;
  while ((m = re.exec(reply)) !== null) {
    edits.push({
      find: m[1].replace(/\\"/g, '"').replace(/\\n/g, '\n'),
      replace: m[2].replace(/\\"/g, '"').replace(/\\n/g, '\n')
    });
  }
  return edits;
}

// Apply edits to the local prototype file
async function applyEdits(edits, commitMsg) {
  const results = [];
  for (let i = 0; i < edits.length; i++) {
    const edit = edits[i];
    const res = await fetch("/prototype/edit", {
      method: "POST", headers: {"Content-Type":"application/json"},
      credentials: "same-origin",
      body: JSON.stringify({ find: edit.find, replace: edit.replace, message: commitMsg || "Update via CX Dashboard Editor" })
    });
    const data = await res.json();
    results.push({ ok: res.ok, error: data.error, find: edit.find });
  }
  return results;
}

async function handleSend() {
  const text = txtEl.value.trim(); if (!text || busy) return;
  busy = true; sndEl.disabled = true; txtEl.value = ""; txtEl.style.height = "auto";
  addMsg("user", esc(text));
  addThinking("Reading prototype source…");

  try {
    updateThinking("Thinking about your change…");
    const reply = await callClaude(text);
    removeThinking();

    const edits = parseEdits(reply);
    // Summary = reply without [EDIT] lines
    const summary = reply.replace(/\[EDIT\]:.*$/gm, "").trim();

    if (edits.length > 0) {
      const chipId = "chip-" + Date.now();
      addMsg("assistant", esc(summary) || "Applying changes…", [
        { type: "working", icon: "loader", label: `Applying ${edits.length} edit${edits.length > 1 ? "s" : ""}…`, id: chipId }
      ]);

      const results = await applyEdits(edits, (summary || text).substring(0, 100));
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

        // Update undo button + history
        undoBtn.disabled = false;
        undoCount++;
        changeHistory.push({ time: now(), desc: summary || text });
        renderHistory();
      } else {
        const msg = failed.map(f => `Could not find: <code>${esc(f.find.substring(0, 60))}…</code>`).join("<br>");
        if (chip) { chip.className = "chip error"; chip.innerHTML = `<i class="ti ti-alert-circle" style="font-size:11px"></i>${failed.length} edit${failed.length > 1 ? "s" : ""} failed`; }
        addMsg("assistant", `Some edits couldn't be applied — the text wasn't found in the prototype:<br>${msg}<br><br>Try rephrasing or being more specific about what to change.`, null, true);
        if (succeeded.length > 0) { loadPreview(true); setTimeout(flashPreview, 600); }
      }
    } else {
      // No edits — just a conversational response
      addMsg("assistant", esc(summary || reply));
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
