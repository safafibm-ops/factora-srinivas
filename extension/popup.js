// Factora Guardian popup: show the analyzer verdict first, then historical links.

document.addEventListener("DOMContentLoaded", () => {
  const riskCard = document.getElementById("risk-card");
  const riskBadge = document.getElementById("risk-badge");
  const riskTitle = document.getElementById("risk-title");
  const riskSubtext = document.getElementById("risk-subtext");
  const alertsList = document.getElementById("alerts-list");
  const serverStatus = document.getElementById("server-status");
  const rescanBtn = document.getElementById("rescan-btn");
  const rescanLabel = document.getElementById("rescan-label");
  const rescanIcon = document.getElementById("rescan-icon");
  const checklist = document.getElementById("checklist");
  let rescanTimeout = null;

  function stopRescan() {
    if (rescanTimeout) clearTimeout(rescanTimeout);
    rescanTimeout = null;
    rescanBtn.disabled = false;
    rescanLabel.textContent = "Re-scan this tab";
    rescanIcon.textContent = "↻";
  }

  function normalizePageUrl(value) {
    try {
      const url = new URL(value);
      return `${url.origin}${url.pathname}${url.search}`;
    } catch {
      return value || "";
    }
  }

  function setAlerts(messages) {
    alertsList.replaceChildren();
    (messages || []).slice(0, 6).forEach(message => {
      const item = document.createElement("li");
      item.className = "alert-item";
      item.textContent = String(message);
      alertsList.appendChild(item);
    });
    if (!alertsList.children.length) {
      const item = document.createElement("li");
      item.className = "alert-item";
      item.textContent = "No specific red flags were returned. Keep using normal verification steps.";
      alertsList.appendChild(item);
    }
  }

  function setChecklist(steps) {
    checklist.replaceChildren();
    (Array.isArray(steps) ? steps : []).forEach(step => {
      const label = document.createElement("label");
      label.className = "check-label";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      const text = document.createElement("span");
      text.textContent = `${step.step_title || "Verify before proceeding"} — ${step.action_url_or_instruction || step.why_it_matters || ""}`;
      checkbox.addEventListener("change", () => label.classList.toggle("completed", checkbox.checked));
      label.append(checkbox, text);
      checklist.appendChild(label);
    });
    if (!checklist.children.length) {
      const label = document.createElement("label");
      label.className = "check-label";
      label.textContent = "Do not pay, share credentials, or run repository code before independent verification.";
      checklist.appendChild(label);
    }
  }

  function renderPending(message = "The current tab has no completed Factora scan yet.", scanning = false) {
    if (!scanning) stopRescan();
    riskCard.className = "risk-card caution";
    riskBadge.className = "risk-badge caution";
    riskBadge.textContent = "Scan pending / unavailable";
    riskTitle.textContent = "No safety verdict available";
    riskSubtext.textContent = message;
    setAlerts(["Do not treat an absent scan result as proof that this page is safe."]);
    setChecklist([]);
  }

  function renderReport(reportData) {
    stopRescan();
    const analysis = reportData.analysis;
    const correlation = reportData.record || {};
    if (!analysis) {
      renderPending(reportData.error || "The analyzer did not return a result for this tab.");
      return;
    }

    const score = Number(analysis.fuzzy_risk_score || 0);
    const matches = Array.isArray(correlation.related_incidents) ? correlation.related_incidents : [];
    const severity = score >= 70 ? "danger" : (score >= 45 || matches.length ? "caution" : "safe");
    const tier = matches.length && score < 45 ? "Caution · historical indicator match" : (analysis.risk_tier || "Caution");
    let pageLabel = reportData.claimed_org || "Current page analysis";
    if (!reportData.claimed_org && reportData.url) {
      try { pageLabel = new URL(reportData.url).hostname; } catch { /* keep the fallback label */ }
    }
    riskCard.className = `risk-card ${severity}`;
    riskBadge.className = `risk-badge ${severity}`;
    riskBadge.textContent = `${tier} · ${score.toFixed(1)} / 100`;
    riskTitle.textContent = pageLabel;
    riskSubtext.textContent = matches.length
      ? `The analyzer returned this risk score and Agent 2 found ${matches.length} matching historical indicator${matches.length === 1 ? "" : "s"}. A match is a lead to verify, not proof of guilt.`
      : "Risk score is based on the analyzer's findings. A low score is not a guarantee of safety.";

    const findings = [...(analysis.why_it_is_risky_summary || [])];
    matches.slice(0, 4).forEach(match => findings.push(match.connection_explanation));
    setAlerts(findings);
    setChecklist(analysis.verify_before_proceeding_checklist);
  }

  // Report the availability of both actual model endpoints, not just one API.
  Promise.all([
    fetch("http://localhost:8000/api/analyzer/health").then(r => r.ok ? r.json() : null),
    fetch("http://localhost:8000/api/correlator/health").then(r => r.ok ? r.json() : null),
  ]).then(([analyzer, correlator]) => {
    const analyzerReady = Boolean(analyzer?.ml_model_loaded);
    const correlatorReady = Boolean(correlator?.ml_model_loaded);
    serverStatus.textContent = analyzerReady && correlatorReady
      ? "Both AI models online"
      : `Model status ${Number(analyzerReady) + Number(correlatorReady)}/2`;
    serverStatus.className = analyzerReady && correlatorReady ? "status-pill online" : "status-pill";
  }).catch(() => {
    serverStatus.textContent = "Backend unavailable";
    serverStatus.className = "status-pill";
  });

  function loadReportForActiveTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const activeUrl = normalizePageUrl(tabs?.[0]?.url || "");
      chrome.storage.local.get(["latestReport"], data => {
        const report = data?.latestReport;
        if (report && normalizePageUrl(report.url) === activeUrl) renderReport(report);
        else renderPending("Waiting for the current tab's page scan. Use Re-Scan Tab if it does not finish.");
      });
    });
  }

  loadReportForActiveTab();
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.latestReport) loadReportForActiveTab();
  });

  function requestRescan(tabId) {
    chrome.tabs.sendMessage(tabId, { type: "FACTORA_RESCAN_PAGE" }, response => {
      const sendError = chrome.runtime.lastError;
      if (!sendError && response?.accepted) return;

      // The active tab may have been open before the extension was reloaded.
      // Inject the current content script, then ask it to scan in place.
      chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] })
        .then(() => setTimeout(() => {
          chrome.tabs.sendMessage(tabId, { type: "FACTORA_RESCAN_PAGE" }, retryResponse => {
            const retryError = chrome.runtime.lastError;
            if (retryError || !retryResponse?.accepted) {
              renderPending(`Could not start a scan for this tab. ${retryError?.message || "Open a regular website tab and try again."}`);
            }
          });
        }, 100))
        .catch(error => renderPending(`Chrome could not access this tab. Open a regular website tab and try again. ${error.message}`));
    });
  }

  rescanBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const tabId = tabs?.[0]?.id;
      if (!tabId) {
        renderPending("Chrome could not identify the active tab.");
        return;
      }
      rescanBtn.disabled = true;
      rescanLabel.textContent = "Scanning…";
      rescanIcon.textContent = "◌";
      renderPending("Re-scanning this tab. The popup will update when the analyzer and correlator finish.", true);
      rescanTimeout = setTimeout(() => {
        renderPending("The scan did not finish in time. Check that the Factora backend is running, then try again.");
      }, 45000);
      requestRescan(tabId);
    });
  });
});
