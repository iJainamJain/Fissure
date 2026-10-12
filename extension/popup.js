// Fissure popup: auto-connect to the local Fissure service, fetch the bearer
// token automatically (the extension's host permission lets it read localhost),
// then scan the active tab after an explicit authorization click.

const $ = (id) => document.getElementById(id);
let tabUrl = "";
let token = "";

function setStatus(state, text) {
  $("dot").className = "dot" + (state === "ok" ? " ok" : state === "wait" ? " wait" : "");
  $("conn").textContent = text;
}

function server() {
  return $("server").value.replace(/\/+$/, "");
}

function refreshBtn() {
  $("scan").disabled = !(token && $("authorize").checked && tabUrl.startsWith("http"));
}

// Read the active tab URL.
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  tabUrl = (tabs[0] && tabs[0].url) || "";
  $("url").textContent = tabUrl || "(no URL)";
  refreshBtn();
});

// Auto-connect: ping, then fetch the token — no manual paste.
async function connect() {
  token = "";
  refreshBtn();
  setStatus("wait", "Connecting…");
  try {
    const ping = await fetch(server() + "/ping");
    if (!ping.ok) throw new Error("no server");
    const t = await fetch(server() + "/token");
    const data = await t.json();
    token = data.token || "";
    if (!token) throw new Error("no token");
    setStatus("ok", "Connected to Fissure");
    $("msg").textContent = "";
  } catch (e) {
    setStatus("bad", "Fissure app not running");
    $("msg").innerHTML = "Open the <b>Fissure</b> desktop app (the local server " +
      "auto-starts), then click <b>Reconnect</b>.";
  }
  refreshBtn();
}

$("authorize").addEventListener("change", refreshBtn);
$("retry").addEventListener("click", connect);

async function api(path, method, body) {
  const res = await fetch(server() + path, {
    method,
    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status >= 400) throw new Error(data.detail || data.error || res.status);
  return data;
}

$("scan").addEventListener("click", async () => {
  $("scan").disabled = true;
  $("result").innerHTML = "";
  $("msg").textContent = "Starting…";
  try {
    const started = await api("/scan", "POST", { url: tabUrl });
    $("msg").textContent = `In scope (${started.scope}). Authorizing…`;
    const run = await api(`/scan/${started.scan_id}/authorize`, "POST", { approved: true });
    if (run.status !== "running") { $("msg").textContent = "Scan not started."; return; }

    $("msg").textContent = "Scanning…";
    for (let i = 0; i < 180; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      const st = await api(`/scan/${started.scan_id}`, "GET");
      if (st.status === "done") {
        const s = st.summary;
        const reportUrl = `${server()}/scan/${started.scan_id}/report?token=${encodeURIComponent(token)}`;
        $("msg").innerHTML = `<b>${s.label}</b> · ${s.total_findings} findings · ` +
          `<a href="${reportUrl}" target="_blank">open report</a>`;
        return;
      }
      if (st.status === "error") { $("msg").textContent = "Error: " + st.error; return; }
    }
    $("msg").textContent = "Timed out.";
  } catch (e) {
    $("msg").textContent = "Failed: " + e.message;
  } finally {
    refreshBtn();
  }
});

connect();
