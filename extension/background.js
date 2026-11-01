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

  const payload = {
    incident_id: incidentId,
    extracted_indicators: indicators
  };

  try {
    const response = await fetch(`${BACKEND_URL}/api/correlator/correlate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}`);
    }

    const data = await response.json();
    console.log("[Factora Guardian] Threat Correlation Result:", data);

    // Save latest report in storage for popup.html
    const storedData = {
      incident_id: incidentId,
      url: indicators.urls[0] || "",
      claimed_org: indicators.claimed_organization || "",
      record: data,
      timestamp: new Date().toLocaleTimeString()
    };
    chrome.storage.local.set({ latestReport: storedData });

    // Update Chrome Toolbar Badge
    if (tab && tab.id) {
      if (data.is_recurring_campaign || (data.related_incidents && data.related_incidents.length > 0)) {
        chrome.action.setBadgeText({ text: "!", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#EF4444", tabId: tab.id });
      } else {
        chrome.action.setBadgeText({ text: "OK", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#10B981", tabId: tab.id });
      }
    }

    return { success: true, record: data };
  } catch (error) {
    console.warn("[Factora Guardian] Cannot reach backend on localhost:8000:", error.message);
    
    // Set warning badge for tab if indicators look suspicious even if backend is offline
    if (tab && tab.id && (indicators.student_scam_flags.upfront_fee || indicators.uses_free_form_or_host)) {
      chrome.action.setBadgeText({ text: "!", tabId: tab.id });
      chrome.action.setBadgeBackgroundColor({ color: "#F59E0B", tabId: tab.id });
    }

    return { success: false, error: error.message };
  }
}
