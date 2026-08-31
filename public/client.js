const slug = location.pathname.split("/")[2];
const iframe = document.getElementById("preview-iframe");
const status = document.getElementById("preview-status");

fetch(`/client/${slug}/info`, { credentials: "same-origin" })
  .then(res => res.ok ? res.json() : Promise.reject())
  .then(data => { document.getElementById("company-name").textContent = data.companyName || ""; })
  .catch(() => {});

iframe.addEventListener("load", () => {
  iframe.classList.add("loaded");
  status.style.display = "none";
});
iframe.src = `/client/${slug}/preview`;

document.getElementById("signout-btn").addEventListener("click", async () => {
  try {
    await fetch(`/client/${slug}/auth/logout`, { method: "POST", credentials: "same-origin" });
  } catch {}
  location.href = `/client/${slug}/login`;
});
