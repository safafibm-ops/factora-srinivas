// Factora Guardian - Student Cyber Defense Content Script
// Scans webpages/emails for scam indicators and injects a non-intrusive floating tactile safety widget.

(function () {
  if (window.__FACTORA_GUARDIAN_CONTENT_READY__) return;
  window.__FACTORA_GUARDIAN_CONTENT_READY__ = true;
  console.log("[Factora Guardian] Active on:", window.location.href);

  // Avoid running in iframes
  if (window.top !== window.self) return;

  // 1. Scanner Regexes
  const UPI_REGEX = /[a-zA-Z0-9.\-_]{2,256}@(oksbi|okhdfcbank|okicici|okaxis|ybl|paytm|upi|ibl|axl)/gi;
  const PHONE_REGEX = /(?:\+91|91)?[\s-]?[6-9]\d{9}/g;
  const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const GITHUB_REPO_REGEX = /https?:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+/gi;

  const SCAM_KEYWORD_PATTERNS = {
    upfront_fee: /(registration\s+fee|security\s+deposit|laptop\s+bond|training\s+charge|processing\s+fee|stamp\s+duty|caution\s+money|kit\s+fee|\b(?:send|transfer|pay|deposit)\s+(?:rs\.?|inr|₹)\s*[\d,]+)/i,
    zero_interview: /(direct\s+selection|direct\s+joining|without\s+interview|no\s+assessment|immediate\s+appointment)/i,
    task_scam: /(youtube\s+like|hotel\s+review|google\s+maps\s+rating|daily\s+task\s+salary|telegram\s+task)/i,
    mule_account: /(receive\s+in\s+your\s+account|upi\s+transfer\s+commission|account\s+rental|payment\s+partner)/i
  };

  function extractPageIndicators() {
    const contentRoot = document.querySelector(".a3s.aiL") || document.querySelector("main") || document.body;
    const bodyText = contentRoot ? contentRoot.innerText : "";
    const pageUrl = window.location.href;
    const hostname = window.location.hostname;

    // Collect all links on page
    const links = Array.from((contentRoot || document).querySelectorAll("a[href]")).map(a => a.href);
    
    // Extract unique indicators
    const upis = Array.from(new Set(bodyText.match(UPI_REGEX) || []));
    const phones = Array.from(new Set(bodyText.match(PHONE_REGEX) || [])).slice(0, 5);
    const emails = Array.from(new Set(bodyText.match(EMAIL_REGEX) || []))
      .filter(e => !e.endsWith("@example.com") && !e.includes("w3.org"))
      .slice(0, 5);
    
    const pathParts = window.location.pathname.split("/").filter(Boolean);
    const currentGitHubRepo = hostname === "github.com" && pathParts.length >= 2
      ? `https://github.com/${pathParts[0]}/${pathParts[1]}`
      : null;
    const githubRepos = Array.from(new Set([
      ...(currentGitHubRepo ? [currentGitHubRepo] : []),
      ...(bodyText.match(GITHUB_REPO_REGEX) || []),
      ...links.filter(l => l.includes("github.com/"))
    ])).slice(0, 3);

    // Free form / unverified hosting check
    const usesFreeForm = (
      hostname.includes("forms.gle") ||
      hostname.includes("docs.google.com/forms") ||
      hostname.includes("tally.so") ||
      hostname.includes("notion.site") ||
      hostname.includes("typeform.com")
    );

    // Flags
    const flags = {
      upfront_fee: SCAM_KEYWORD_PATTERNS.upfront_fee.test(bodyText),
      zero_interview: SCAM_KEYWORD_PATTERNS.zero_interview.test(bodyText),
      task_scam: SCAM_KEYWORD_PATTERNS.task_scam.test(bodyText),
      mule_account_request: SCAM_KEYWORD_PATTERNS.mule_account.test(bodyText),
      ugc_fake_uni: false,
      aicte_unverified: false
    };

    return {
      urls: [pageUrl],
      unrolled_final_urls: [pageUrl],
      domains: [hostname],
      domain_age_days: null,
      uses_free_form_or_host: usesFreeForm,
      emails: emails,
      phones_or_upi: [...upis, ...phones],
      claimed_organization: document.title.slice(0, 40) || hostname,
      official_domain_mismatch: usesFreeForm,
      github_repos: githubRepos,
      suspicious_packages: [],
      student_scam_flags: flags,
      page_text: `${bodyText}\n\nVisible links:\n${links.slice(0, 40).join("\n")}`.slice(0, 10000),
      github_repo_url: currentGitHubRepo
    };
  }

  // 2. UI Injection (Isolated Shadow DOM)
  function injectGuardianWidget(indicators) {
    if (document.getElementById("factora-guardian-host")) return;

    const host = document.createElement("div");
    host.id = "factora-guardian-host";
    document.body.appendChild(host);

    const shadow = host.attachShadow({ mode: "open" });

    const style = document.createElement("style");
    style.textContent = `
      * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
      
      .factora-badge {
        position: fixed;
        bottom: 24px;
        right: 24px;
        z-index: 2147483647;
        background: #0f172a;
        color: #f8fafc;
        border: 1px solid #334155;
        border-radius: 9999px;
        padding: 10px 18px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
        display: flex;
        align-items: center;
        gap: 10px;
        cursor: pointer;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        font-size: 13px;
        font-weight: 600;
        user-select: none;
      }
      .factora-badge:hover {
        transform: translateY(-2px);
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
      }
      .factora-pulse-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: #38bdf8;
      }
      .factora-pulse-dot.danger {
        background: #ef4444;
        box-shadow: 0 0 0 4px rgba(239, 68, 68, 0.25);
        animation: pulse 1.8s infinite;
      }
      .factora-pulse-dot.caution {
        background: #f59e0b;
        box-shadow: 0 0 0 4px rgba(245, 158, 11, 0.25);
      }
      .factora-pulse-dot.safe {
        background: #10b981;
      }
      @keyframes pulse {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.2); opacity: 0.8; }
      }

      /* Slide-out Safety Card */
      .factora-card {
        position: fixed;
        bottom: 74px;
        right: 24px;
        width: 360px;
        max-height: 520px;
        z-index: 2147483647;
        background: #0f172a;
        color: #f8fafc;
        border: 1px solid #334155;
        border-radius: 16px;
        padding: 20px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
        display: none;
        flex-direction: column;
        gap: 14px;
        overflow-y: auto;
      }
      .factora-card.open {
        display: flex;
        animation: slideUp 0.2s ease-out;
      }
      @keyframes slideUp {
        from { opacity: 0; transform: translateY(12px); }
        to { opacity: 1; transform: translateY(0); }
      }

      .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 10px;
      }
      .card-title {
        font-size: 14px;
        font-weight: 700;
        color: #38bdf8;
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .close-btn {
        background: transparent;
        border: none;
        color: #94a3b8;
        cursor: pointer;
        font-size: 18px;
        line-height: 1;
      }
      .close-btn:hover { color: #f8fafc; }

      .threat-banner {
        border-radius: 8px;
        padding: 10px 14px;
        font-size: 12px;
      }
      .threat-banner.danger {
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.4);
        color: #fca5a5;
      }
      .threat-banner.caution {
        background: rgba(245, 158, 11, 0.15);
        border: 1px solid rgba(245, 158, 11, 0.4);
        color: #fcd34d;
      }
      .threat-banner.safe {
        background: rgba(16, 185, 129, 0.15);
        border: 1px solid rgba(16, 185, 129, 0.4);
        color: #6ee7b7;
      }

      .section-heading {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94a3b8;
        font-weight: 700;
        margin-top: 4px;
      }
      .reasons-list {
        margin: 0;
        padding-left: 18px;
        font-size: 12px;
        color: #cbd5e1;
        display: flex;
        flex-direction: column;
        gap: 6px;
      }

      /* Checklist */
      .checklist-group {
        display: flex;
        flex-direction: column;
        gap: 8px;
        background: #1e293b;
        padding: 12px;
        border-radius: 10px;
      }
      .check-item {
        display: flex;
        align-items: flex-start;
        gap: 8px;
        font-size: 12px;
        color: #e2e8f0;
      }
      .check-item input[type="checkbox"] {
        margin-top: 2px;
        cursor: pointer;
        accent-color: #38bdf8;
      }

      /* Actions */
      .action-btns {
        display: flex;
        gap: 8px;
        margin-top: 4px;
      }
      .btn-primary {
        flex: 1;
        background: #0284c7;
        color: white;
        border: none;
        border-radius: 8px;
        padding: 8px 12px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        text-align: center;
        text-decoration: none;
      }
      .btn-primary:hover { background: #0369a1; }
      .btn-secondary {
        background: #334155;
        color: #cbd5e1;
        border: none;
        border-radius: 8px;
        padding: 8px 12px;
        font-size: 12px;
        cursor: pointer;
      }
      .btn-secondary:hover { background: #475569; }
    `;
    shadow.appendChild(style);

    // Initial Badge (Scanning state)
    const badge = document.createElement("div");
    badge.className = "factora-badge";
    badge.innerHTML = `
      <div class="factora-pulse-dot" id="dot"></div>
      <span id="badge-text">Factora: Scanning Page...</span>
    `;
    shadow.appendChild(badge);

    // Expandable Card
    const card = document.createElement("div");
    card.className = "factora-card";
    card.id = "card";
    card.innerHTML = `
      <div class="card-header">
        <div class="card-title">🛡️ Factora Student Guardian</div>
        <button class="close-btn" id="close-card">×</button>
      </div>
      <div class="threat-banner caution" id="banner">
        <strong>Analyzing Page</strong><br>
        Checking indicators against Factora ML Threat Syndicates...
      </div>
      <div class="section-heading">Key Red Flags</div>
      <ul class="reasons-list" id="reasons">
        <li>Evaluating domain age and recruitment credentials...</li>
      </ul>
      <div class="section-heading">Verify Before Proceeding</div>
      <div class="checklist-group" id="checklist">
        <label class="check-item">
          <input type="checkbox">
          <span>Verify offer on company's official careers portal</span>
        </label>
        <label class="check-item">
          <input type="checkbox">
          <span>Never transfer money or UPI fees for recruitment</span>
        </label>
        <label class="check-item">
          <input type="checkbox">
          <span>Confirm drive with Campus Placement Officer (TPO)</span>
        </label>
      </div>
      <div class="action-btns">
        <a class="btn-primary" href="https://cybercrime.gov.in" target="_blank">File Report (1930)</a>
        <button class="btn-secondary" id="hide-btn">Dismiss</button>
      </div>
    `;
    shadow.appendChild(card);

    // Toggle card on badge click
    badge.addEventListener("click", () => {
      card.classList.toggle("open");
    });
    shadow.getElementById("close-card").addEventListener("click", () => {
      card.classList.remove("open");
    });
    shadow.getElementById("hide-btn").addEventListener("click", () => {
      card.classList.remove("open");
    });

    // 3. Request Analysis from Factora Backend via background.js
    requestPageAnalysis(shadow, indicators);
  }

  function requestPageAnalysis(shadow, indicators) {
    const badgeText = shadow.getElementById("badge-text");
    const banner = shadow.getElementById("banner");
    if (badgeText) badgeText.textContent = "Factora: Scanning Page...";
    if (banner) {
      banner.className = "threat-banner caution";
      banner.textContent = "Running a fresh analyzer and historical-indicator scan...";
    }
    chrome.runtime.sendMessage(
      { type: "ANALYZE_PAGE", indicators },
      response => {
        const messageError = chrome.runtime.lastError;
        updateWidgetUI(shadow, messageError ? { success: false, error: messageError.message } : response, indicators);
      }
    );
  }

  // The popup can request a fresh scan without reloading the page. This works
  // for single-page apps and avoids closing the popup before results arrive.
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request?.type !== "FACTORA_RESCAN_PAGE") return false;
    const indicators = extractPageIndicators();
    const host = document.getElementById("factora-guardian-host");
    if (host?.shadowRoot) requestPageAnalysis(host.shadowRoot, indicators);
    else injectGuardianWidget(indicators);
    sendResponse({ accepted: true });
    return false;
  });

  function renderEvidenceList(list, messages) {
    list.replaceChildren();
    (messages || []).forEach(message => {
      const item = document.createElement("li");
      item.textContent = String(message);
      list.appendChild(item);
    });
  }

  function renderChecklist(container, steps) {
    container.replaceChildren();
    const items = Array.isArray(steps) ? steps : [];
    items.forEach(step => {
      const label = document.createElement("label");
      label.className = "check-item";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      const text = document.createElement("span");
      text.textContent = `${step.step_title || "Verify before proceeding"}: ${step.why_it_matters || ""} ${step.action_url_or_instruction || ""}`;
      label.append(checkbox, text);
      container.appendChild(label);
    });
    if (!items.length) {
      const label = document.createElement("label");
      label.className = "check-item";
      label.textContent = "Do not send money, share credentials, or run repository code until independently verified.";
      container.appendChild(label);
    }
  }

  function updateWidgetUI(shadow, response, indicators) {
    const dot = shadow.getElementById("dot");
    const badgeText = shadow.getElementById("badge-text");
    const banner = shadow.getElementById("banner");
    const reasonsList = shadow.getElementById("reasons");
    const checklist = shadow.getElementById("checklist");

    if (!response || !response.success || !response.analysis) {
      const localFlags = indicators.student_scam_flags || {};
      const localWarnings = [];
      if (localFlags.upfront_fee) localWarnings.push("Possible payment request detected locally; backend analysis did not complete.");
      if (localFlags.zero_interview) localWarnings.push("Possible no-interview offer language detected locally.");
      if (indicators.github_repo_url) localWarnings.push("Repository contents were not analyzed because the backend scan did not complete.");
      if (!localWarnings.length) localWarnings.push("The backend scan did not complete. No safe verdict is available.");
      if (response?.error) localWarnings.push(`Backend error: ${response.error}`);
      dot.className = `factora-pulse-dot ${localFlags.upfront_fee || indicators.github_repo_url ? "caution" : ""}`;
      badgeText.textContent = "Factora: Scan Incomplete";
      banner.className = "threat-banner caution";
      banner.replaceChildren();
      const heading = document.createElement("strong");
      heading.textContent = "No safety verdict available";
      banner.append(heading, document.createElement("br"), document.createTextNode("The backend analysis failed; do not treat this page as safe."));
      renderEvidenceList(reasonsList, localWarnings);
      renderChecklist(checklist, []);
      return;
    }

    const analysis = response.analysis;
    const rec = response.record;
    const matches = Array.isArray(rec?.related_incidents) ? rec.related_incidents : [];
    const score = Number(analysis.fuzzy_risk_score || 0);
    let tier = analysis.risk_tier || "Caution";
    if (matches.length && score < 45) tier = "Caution";
    const severity = score >= 70 ? "danger" : score >= 45 || matches.length ? "caution" : "safe";
    dot.className = `factora-pulse-dot ${severity}`;
    badgeText.textContent = severity === "danger" ? `Factora: ${tier}` : `Factora: ${tier}`;
    banner.className = `threat-banner ${severity}`;
    banner.replaceChildren();
    const heading = document.createElement("strong");
    heading.textContent = `${tier} · ${score.toFixed(1)} / 100`;
    banner.append(heading, document.createElement("br"));
    banner.appendChild(document.createTextNode(matches.length
      ? `Analyzer result plus ${matches.length} historical indicator match${matches.length === 1 ? "" : "es"}.`
      : "Based on the analyzer scan. A low score is not a guarantee of safety."));

    const reasons = [...(analysis.why_it_is_risky_summary || [])];
    matches.slice(0, 4).forEach(match => reasons.push(match.connection_explanation));
    if (!reasons.length) reasons.push("No suspicious indicators were found in the available page content.");
    renderEvidenceList(reasonsList, reasons);
    renderChecklist(checklist, analysis.verify_before_proceeding_checklist);
  }

  // Run on page load
  window.addEventListener("load", () => {
    setTimeout(() => {
      const indicators = extractPageIndicators();
      injectGuardianWidget(indicators);
    }, 500);
  });
})();
