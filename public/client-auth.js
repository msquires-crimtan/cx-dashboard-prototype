// Drives both /client/:slug/login (email + password) and
// /client-setup?client_slug=... (first-time password + MFA enrollment, linked
// from the invite email — a fixed path since Stytch's redirect-URL allowlist
// only supports query-param placeholders, not dynamic path segments) — both
// pages share the MFA step, just reached from a different first step.
const slug = new URLSearchParams(location.search).get("client_slug") || location.pathname.split("/")[2];

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Something went wrong.");
  return data;
}

function showErr(el, message) {
  el.textContent = message;
  el.style.display = "block";
}

let mfaCtx = null;

function enterMfaStep(data, firstStepEl) {
  mfaCtx = { intermediateToken: data.intermediateToken, memberId: data.memberId };
  firstStepEl.style.display = "none";
  const mfaStep = document.getElementById("step-mfa");
  mfaStep.style.display = "flex";
  const qr = document.getElementById("mfa-qr");
  const secretEl = document.getElementById("mfa-secret");
  if (data.mfa === "enroll" && data.qrCode) {
    qr.src = data.qrCode;
    qr.style.display = "block";
    if (data.secret) {
      secretEl.textContent = `Can't scan? Enter this code manually: ${data.secret}`;
      secretEl.style.display = "block";
    }
  } else {
    document.getElementById("mfa-instructions").textContent = "Enter the 6-digit code from your authenticator app.";
  }
  document.getElementById("mfa-code").focus();
}

const pwSubmit = document.getElementById("pw-submit");
if (pwSubmit) {
  const stepPassword = document.getElementById("step-password");
  const errEl = document.getElementById("pw-err");
  async function submitPassword() {
    errEl.style.display = "none";
    pwSubmit.disabled = true;
    try {
      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value;
      const data = await postJSON(`/client/${slug}/auth/password`, { email, password });
      if (data.ok) { location.href = `/client/${slug}`; return; }
      enterMfaStep(data, stepPassword);
    } catch (err) {
      showErr(errEl, err.message);
    } finally {
      pwSubmit.disabled = false;
    }
  }
  pwSubmit.addEventListener("click", submitPassword);
  document.getElementById("password").addEventListener("keydown", e => { if (e.key === "Enter") submitPassword(); });
}

const setPwSubmit = document.getElementById("setpw-submit");
if (setPwSubmit) {
  const stepSetPw = document.getElementById("step-setpw");
  const errEl = document.getElementById("setpw-err");
  async function submitSetPassword() {
    errEl.style.display = "none";
    const password = document.getElementById("new-password").value;
    const confirmPw = document.getElementById("new-password-confirm").value;
    if (password.length < 8) return showErr(errEl, "Password must be at least 8 characters.");
    if (password !== confirmPw) return showErr(errEl, "Passwords don't match.");
    const token = new URLSearchParams(location.search).get("token");
    if (!token) return showErr(errEl, "This link is missing its token — ask for a new invite.");
    setPwSubmit.disabled = true;
    try {
      const data = await postJSON(`/client/${slug}/set-password`, { token, password });
      if (data.done) { location.href = `/client/${slug}`; return; }
      enterMfaStep(data, stepSetPw);
    } catch (err) {
      showErr(errEl, err.message);
    } finally {
      setPwSubmit.disabled = false;
    }
  }
  setPwSubmit.addEventListener("click", submitSetPassword);
}

const mfaSubmit = document.getElementById("mfa-submit");
if (mfaSubmit) {
  const errEl = document.getElementById("mfa-err");
  async function submitMfa() {
    errEl.style.display = "none";
    mfaSubmit.disabled = true;
    try {
      const code = document.getElementById("mfa-code").value.trim();
      const data = await postJSON(`/client/${slug}/auth/totp`, { code, ...mfaCtx });
      if (data.ok) { location.href = `/client/${slug}`; return; }
      throw new Error("Verification failed.");
    } catch (err) {
      showErr(errEl, err.message);
    } finally {
      mfaSubmit.disabled = false;
    }
  }
  mfaSubmit.addEventListener("click", submitMfa);
  document.getElementById("mfa-code").addEventListener("keydown", e => { if (e.key === "Enter") submitMfa(); });
}
