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

// Severity/risk-label -> color + CSS class (matches popup.html chip classes).
const SEV = {
  critical: "#e5484d", high: "#f76808", medium: "#f5a623", low: "#46a758",
  clean: "#46a758", info: "#8b98a5",
};
function sevClass(label) {
  const k = (label || "").toLowerCase();
  return SEV[k] ? k : "info";
}

function showScanbar(on) {
  $("scanbar").classList.toggle("show", !!on);
}

// Render a result card from the finished scan summary {score, label, total_findings}.
// GET /scan/<id> returns only the summary (no per-finding detail), so we show the
// richest view the summary supports: a colored risk chip, a score meter, counts
// and the report link.
function renderResult(summary, reportUrl) {
  const s = summary || {};
  const label = (s.label || "CLEAN").toString();
  const cls = sevClass(label);
  const score = Number(s.score || 0);
  const total = Number(s.total_findings || 0);
  const color = SEV[cls] || SEV.info;
  const frac = Math.min(score / 60, 1);  // 60 = CRITICAL threshold
  const countText = total === 1 ? "1 finding" : `${total} findings`;
  $("result").innerHTML =
    `<div class="rcard">
       <div class="rtop">
         <span class="chip ${cls}">${label.toUpperCase()}</span>
         <span class="scount">${countText}</span>
       </div>
       <div class="rmeter"><i style="width:${(frac * 100).toFixed(0)}%;background:${color}"></i></div>
       <div class="rstats">
         <div class="stat"><div class="n">${score}</div><div class="l">Risk score</div></div>
         <div class="stat"><div class="n">${total}</div><div class="l">Findings</div></div>
       </div>
       <div class="rlink"><a href="${reportUrl}" target="_blank">Open full report →</a></div>
     </div>`;
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
  showScanbar(false);
  try {
    const started = await api("/scan", "POST", { url: tabUrl });
    $("msg").textContent = `In scope (${started.scope}). Authorizing…`;
    const run = await api(`/scan/${started.scan_id}/authorize`, "POST", { approved: true });
    if (run.status !== "running") { $("msg").textContent = "Scan not started."; return; }

    $("msg").textContent = "Scanning…";
    showScanbar(true);
    for (let i = 0; i < 180; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      const st = await api(`/scan/${started.scan_id}`, "GET");
      if (st.status === "done") {
        const reportUrl = `${server()}/scan/${started.scan_id}/report?token=${encodeURIComponent(token)}`;
        $("msg").textContent = "Scan complete.";
        renderResult(st.summary, reportUrl);
        return;
      }
      if (st.status === "error") { $("msg").textContent = "Error: " + st.error; return; }
    }
    $("msg").textContent = "Timed out.";
  } catch (e) {
    $("msg").textContent = "Failed: " + e.message;
  } finally {
    showScanbar(false);
    refreshBtn();
  }
});

connect();
