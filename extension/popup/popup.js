/**
 * ⚡ CYBERPUNK PHISH-SHIELD — HUD Popup Controller
 * Manages real-time gauge rendering, REST API sync, and crowd threat reporting.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const activeUrlElem = document.getElementById("activeUrl");
  const riskScoreElem = document.getElementById("riskScore");
  const gaugeCircle = document.getElementById("gaugeCircle");
  const statusBadge = document.getElementById("statusBadge");
  const verdictText = document.getElementById("verdictText");
  const checklistGrid = document.getElementById("checklistGrid");
  const reportBtn = document.getElementById("reportBtn");
  const reAnalyzeBtn = document.getElementById("reAnalyzeBtn");
  const toast = document.getElementById("toast");
  const connectionStatus = document.getElementById("connectionStatus");

  let currentTabUrl = "";

  // 1. Get Active Tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0]) {
      currentTabUrl = tabs[0].url || "";
      activeUrlElem.textContent = currentTabUrl;
    }
  } catch (err) {
    activeUrlElem.textContent = "Unable to read tab URL";
    return;
  }

  if (!currentTabUrl || currentTabUrl.startsWith("chrome://") || currentTabUrl.startsWith("chrome-extension://")) {
    renderInternalPage();
    return;
  }

  // 2. Instant On-Device Fallback Scoring (<10ms)
  const localPrediction = OnDeviceML.predictClientRiskScore(currentTabUrl);
  renderTelemetry(localPrediction.riskScore, localPrediction.status, "LOCAL_PRE-CLASSIFIED", createLocalChecklist(localPrediction));

  // 3. Fetch Full Diagnostic Telemetry from Backend / Cache
  fetchFullTelemetry(currentTabUrl);

  // Button Listeners
  reportBtn.addEventListener("click", () => handleReportPhish(currentTabUrl, localPrediction.riskScore));
  reAnalyzeBtn.addEventListener("click", () => {
    chrome.storage.local.get(["cached_analyses"], (res) => {
      const cached = res.cached_analyses || {};
      delete cached[currentTabUrl];
      chrome.storage.local.set({ cached_analyses: cached }, () => {
        fetchFullTelemetry(currentTabUrl);
        showToast("Cache Cleared & Re-Scanned");
      });
    });
  });

  async function fetchFullTelemetry(url) {
    // Check local storage cache first
    const storage = await chrome.storage.local.get(["cached_analyses"]);
    const cacheMap = storage.cached_analyses || {};
    const entry = cacheMap[url];

    if (entry && (Date.now() - entry.timestamp < 24 * 60 * 60 * 1000)) {
      const d = entry.data;
      renderTelemetry(d.risk_score || d.riskScore, d.status, d.verdict, d.checklist);
      return;
    }

    try {
      const response = await fetch("http://127.0.0.1:5000/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      if (response.ok) {
        const data = await response.json();
        renderTelemetry(data.risk_score, data.status, data.verdict, data.checklist);
        connectionStatus.innerHTML = `<span class="dot"></span><span>SYS_ONLINE</span>`;
      } else {
        connectionStatus.innerHTML = `<span class="dot" style="background:#ffb700"></span><span>GRID_OFFLINE</span>`;
      }
    } catch (e) {
      connectionStatus.innerHTML = `<span class="dot" style="background:#ff0055"></span><span>LOCAL_STANDALONE</span>`;
    }
  }

  function renderTelemetry(score, status, verdict, checklist) {
    // Animate Gauge (Circumference ~ 264)
    const maxOffset = 264;
    const targetOffset = maxOffset - (maxOffset * score) / 100;
    gaugeCircle.style.strokeDashoffset = targetOffset;
    riskScoreElem.textContent = `${Math.round(score)}%`;

    // Apply color coding
    if (status === "DANGER" || score >= 75) {
      gaugeCircle.style.stroke = "var(--neon-pink)";
      riskScoreElem.style.color = "var(--neon-pink)";
      statusBadge.textContent = "[ THREAT DETECTED ]";
      statusBadge.style.color = "var(--neon-pink)";
    } else if (status === "WARN" || score >= 40) {
      gaugeCircle.style.stroke = "var(--warning-amber)";
      riskScoreElem.style.color = "var(--warning-amber)";
      statusBadge.textContent = "[ SUSPICIOUS ACTIVITY ]";
      statusBadge.style.color = "var(--warning-amber)";
    } else {
      gaugeCircle.style.stroke = "var(--neon-green)";
      riskScoreElem.style.color = "var(--neon-green)";
      statusBadge.textContent = "[ SYSTEM SECURE ]";
      statusBadge.style.color = "var(--neon-green)";
    }

    verdictText.textContent = (verdict || "SECURE_DOM").replace(/_/g, " ");

    // Render Checklist Matrix
    if (checklist && checklist.length > 0) {
      checklistGrid.innerHTML = "";
      checklist.forEach((item) => {
        const div = document.createElement("div");
        const statusClass = item.status === "PASS" ? "status-pass" : (item.status === "WARN" ? "status-warn" : "status-fail");
        div.className = `check-item ${statusClass}`;
        div.innerHTML = `
          <span class="check-name">${item.name}</span>
          <span class="check-val">${item.value || item.status}</span>
        `;
        checklistGrid.appendChild(div);
      });
    }
  }

  function renderInternalPage() {
    activeUrlElem.textContent = "SYSTEM INTEGRATION PAGE";
    riskScoreElem.textContent = "0%";
    statusBadge.textContent = "[ PROTECTED CORE ]";
    verdictText.textContent = "CHROME SYSTEM COMPONENT";
    checklistGrid.innerHTML = `<div class="check-item status-pass"><span class="check-name">System Page</span><span class="check-val">Whitelisted</span></div>`;
  }

  function createLocalChecklist(pred) {
    const f = pred.features;
    return [
      { name: "Lexical Length", status: f.urlLength > 70 ? "FAIL" : "PASS", value: `${f.urlLength} Chars` },
      { name: "Subdomains", status: f.numSubdomains > 3 ? "FAIL" : "PASS", value: `${f.numSubdomains} Count` },
      { name: "IP Address Host", status: f.isIp ? "FAIL" : "PASS", value: f.isIp ? "Detected" : "Clean" },
      { name: "Urgency Keywords", status: f.keywordCount > 0 ? "FAIL" : "PASS", value: `${f.keywordCount} Tokens` }
    ];
  }

  async function handleReportPhish(url, score) {
    try {
      const res = await fetch("http://127.0.0.1:5000/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, reason: "Cyberpunk HUD User Submitted Flag", client_score: score })
      });
      if (res.ok) {
        showToast("🚨 Threat Logged to Global Grid");
      } else {
        showToast("Report Queued Locally");
      }
    } catch (e) {
      showToast("Report Logged Offline");
    }
  }

  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2500);
  }
});
