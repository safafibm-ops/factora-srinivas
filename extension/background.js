// Factora Guardian - Background Service Worker
// Bridges browser content scripts with the Factora FastAPI Cyber Defense backend.

const BACKEND_URL = "http://localhost:8000";

console.log("[Factora Guardian] Background Service Worker ready.");

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "ANALYZE_PAGE") {
    handlePageAnalysis(request.indicators, sender.tab)
      .then(result => sendResponse(result))
      .catch(err => {
        console.warn("[Factora Guardian] Backend request failed, utilizing offline fallback:", err);
        sendResponse({ success: false, error: err.message });
      });
    return true; // Keep message channel open for asynchronous response
  }

  if (request.type === "GET_LATEST_REPORT") {
    chrome.storage.local.get(["latestReport"], (data) => {
      sendResponse(data.latestReport || null);
    });
    return true;
  }
});

async function handlePageAnalysis(indicators, tab) {
  const incidentId = `INC-EXT-${Date.now().toString(36).toUpperCase()}`;
  let analysis = null;
  const pageText = indicators.page_text || "";
  const repoUrl = indicators.github_repo_url || indicators.github_repos?.[0] || null;
  const pageUrl = indicators.urls?.[0] || tab?.url || "";
  const host = (() => {
    try { return new URL(pageUrl).hostname.toLowerCase(); }
    catch { return ""; }
  })();
  const isWebmail = /(^|\.)(mail\.google\.com|outlook\.live\.com|outlook\.office\.com|mail\.yahoo\.com)$/.test(host);

  const analyzerPayload = {
    // GitHub README text is not a job-scam message. The repo scanner analyzes
    // the repository itself; keep page text for email/web pages and messages.
    input_text: indicators.github_repo_url ? null : pageText,
    target_url: repoUrl || isWebmail || !/^https?:\/\//i.test(pageUrl) ? null : pageUrl,
    github_repo_url: repoUrl,
  };

  const correlationIndicators = { ...indicators };
  delete correlationIndicators.page_text;
  delete correlationIndicators.github_repo_url;

  try {
    const analysisResponse = await fetch(`${BACKEND_URL}/api/analyzer/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(analyzerPayload)
    });

    if (!analysisResponse.ok) {
      throw new Error(`Analyzer returned HTTP ${analysisResponse.status}`);
    }
    analysis = await analysisResponse.json();

    const correlationResponse = await fetch(`${BACKEND_URL}/api/correlator/correlate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        incident_id: analysis.incident_id || incidentId,
        extracted_indicators: analysis.extracted_indicators || correlationIndicators
      })
    });
    if (!correlationResponse.ok) {
      throw new Error(`Correlator returned HTTP ${correlationResponse.status}`);
    }

    const data = await correlationResponse.json();
    console.log("[Factora Guardian] Threat Analysis:", analysis);
    console.log("[Factora Guardian] Threat Correlation:", data);

    // Save latest report in storage for popup.html
    const storedData = {
      incident_id: incidentId,
      url: indicators.urls[0] || "",
      claimed_org: indicators.claimed_organization || "",
      analysis,
      record: data,
      timestamp: new Date().toLocaleTimeString()
    };
    chrome.storage.local.set({ latestReport: storedData });

    // Update Chrome Toolbar Badge
    if (tab && tab.id) {
      const riskScore = Number(analysis.fuzzy_risk_score || 0);
      const hasMatches = data.is_recurring_campaign || (data.related_incidents && data.related_incidents.length > 0);
      if (riskScore >= 70 || hasMatches) {
        chrome.action.setBadgeText({ text: "!", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#EF4444", tabId: tab.id });
      } else if (riskScore >= 45) {
        chrome.action.setBadgeText({ text: "!", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#F59E0B", tabId: tab.id });
      } else {
        chrome.action.setBadgeText({ text: "", tabId: tab.id });
      }
    }

    return { success: true, analysis, record: data };
  } catch (error) {
    console.warn("[Factora Guardian] Cannot reach backend on localhost:8000:", error.message);
    
    // Set warning badge for tab if indicators look suspicious even if backend is offline
    if (tab && tab.id && (indicators.student_scam_flags.upfront_fee || indicators.uses_free_form_or_host)) {
      chrome.action.setBadgeText({ text: "!", tabId: tab.id });
      chrome.action.setBadgeBackgroundColor({ color: "#F59E0B", tabId: tab.id });
    }

    const failedReport = {
      incident_id: incidentId,
      url: indicators.urls?.[0] || tab?.url || "",
      claimed_org: indicators.claimed_organization || "",
      analysis,
      record: null,
      error: error.message,
      timestamp: new Date().toLocaleTimeString()
    };
    chrome.storage.local.set({ latestReport: failedReport });
    return { success: Boolean(analysis), analysis, record: null, error: error.message };
  }
}
