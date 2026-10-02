// Fissure extension popup: read the active tab URL, require an explicit
// authorization check, then drive the local Fissure server's scan flow.

const $ = (id) => document.getElementById(id);
let tabUrl = "";

// Remember server + token across popups.
chrome.storage.local.get(["server", "token"], (v) => {
  if (v.server) $("server").value = v.server;
  if (v.token) $("token").value = v.token;
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  tabUrl = (tabs[0] && tabs[0].url) || "";
  $("url").textContent = tabUrl || "(no URL)";
});

function refreshButton() {
  $("scan").disabled = !($("authorize").checked && $("token").value && tabUrl.startsWith("http"));
}
$("authorize").addEventListener("change", refreshButton);
$("token").addEventListener("input", refreshButton);

async function api(path, method, body) {
  const server = $("server").value.replace(/\/+$/, "");
  const token = $("token").value.trim();
  const res = await fetch(server + path, {
    method,
    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok && res.status !== 200) {
    let detail = res.status;
    try { detail = (await res.json()).detail || res.status; } catch (e) {}
    throw new Error("server said: " + detail);
  }
  return res.json();
}

$("scan").addEventListener("click", async () => {
  const server = $("server").value.replace(/\/+$/, "");
  const token = $("token").value.trim();
  chrome.storage.local.set({ server, token });
  $("scan").disabled = true;
  const status = $("status");
  status.textContent = "Starting…";
  try {
    const started = await api("/scan", "POST", { url: tabUrl });
    status.textContent = `Target in scope (${started.scope}). Authorizing…`;
    const run = await api(`/scan/${started.scan_id}/authorize`, "POST", { approved: true });
    if (run.status !== "running") { status.textContent = "Scan not started."; return; }

    status.textContent = "Scanning…";
    for (let i = 0; i < 120; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      const st = await api(`/scan/${started.scan_id}`, "GET");
      if (st.status === "done") {
        const s = st.summary;
        const reportUrl = `${server}/scan/${started.scan_id}/report?token=${encodeURIComponent(token)}`;
        status.innerHTML = `Done — <b>${s.label}</b>, ${s.total_findings} finding(s).<br>` +
          `<a href="${reportUrl}" target="_blank">Open report</a>`;
        return;
      }
      if (st.status === "error") { status.textContent = "Error: " + st.error; return; }
    }
    status.textContent = "Timed out waiting for the scan.";
  } catch (e) {
    status.textContent = "Failed: " + e.message + "\n(Is the Fissure server running? Token correct?)";
    $("scan").disabled = false;
  }
});
