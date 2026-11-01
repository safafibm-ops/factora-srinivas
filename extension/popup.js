// Factora Guardian - Popup Logic
// Renders the AI threat report, interactive checklist, and live status.

document.addEventListener("DOMContentLoaded", () => {
  const riskCard = document.getElementById("risk-card");
  const riskBadge = document.getElementById("risk-badge");
  const riskTitle = document.getElementById("risk-title");
  const riskSubtext = document.getElementById("risk-subtext");
  const alertsList = document.getElementById("alerts-list");
  const serverStatus = document.getElementById("server-status");
  const rescanBtn = document.getElementById("rescan-btn");
  const checklist = document.getElementById("checklist");

  // Handle checklist strike-through interactions
  checklist.querySelectorAll("input[type='checkbox']").forEach(box => {
    box.addEventListener("change", (e) => {
      const parent = e.target.closest(".check-label");
      if (e.target.checked) {
        parent.classList.add("completed");
      } else {
        parent.classList.remove("completed");
      }
    });
  });

  // Check backend server health
  fetch("http://localhost:8000/api/correlator/health")
    .then(r => r.json())
    .then(data => {
      if (data.status === "ok") {
        serverStatus.textContent = "AI Backend Online";
        serverStatus.className = "status-pill online";
      }
    })
    .catch(() => {
      serverStatus.textContent = "Offline Mode";
      serverStatus.className = "status-pill";
    });

  // Load latest report from storage
  chrome.storage.local.get(["latestReport"], (data) => {
    if (data && data.latestReport && data.latestReport.record) {
      renderReport(data.latestReport);
    } else {
      // Default initial state
      renderSafeState();
    }
  });

  // Re-scan trigger
  rescanBtn.addEventListener("click", () => {
    rescanBtn.textContent = "Scanning...";
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && tabs[0].id) {
        chrome.tabs.reload(tabs[0].id, () => {
          setTimeout(() => {
            window.close();
          }, 400);
        });
      }
    });
  });

  function renderReport(reportData) {
    const rec = reportData.record;
    const isThreat = rec.is_recurring_campaign || (rec.related_incidents && rec.related_incidents.length > 0);

    if (isThreat) {
      riskCard.className = "risk-card danger";
      riskBadge.className = "risk-badge danger";
      riskBadge.textContent = "🚨 Critical Syndicate Alert";
      riskTitle.textContent = rec.detected_campaign_name || "Organized Scam Syndicate";
      riskSubtext.textContent = `Correlated with ${rec.related_incidents.length} known student scam cases in Factora DB.`;

      // Render red flags
      if (rec.recommended_community_warnings && rec.recommended_community_warnings.length > 0) {
        alertsList.innerHTML = rec.recommended_community_warnings
          .slice(0, 3)
          .map(w => `<li class="alert-item">${w}</li>`)
          .join("");
      }
    } else {
      renderSafeState();
    }
  }

  function renderSafeState() {
    riskCard.className = "risk-card safe";
    riskBadge.className = "risk-badge safe";
    riskBadge.textContent = "🛡️ Verified / Safe";
    riskTitle.textContent = "No Known Threat Detected";
    riskSubtext.textContent = "This page does not match any recognized phishing syndicates or fraudulent recruiting campaigns.";

    alertsList.innerHTML = `
      <li class="alert-item">Page domain and indicators appear standard.</li>
      <li class="alert-item">Always verify offer letters with your college placement cell.</li>
    `;
  }
});

