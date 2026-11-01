# Member 3: Community Victim Network & External Go-To Reporting Websites Hub
**Directory:** `/backend/community_hub/`
**Owner:** Member 3

---

## 1. Mission & Scope

Member 3 manages Factora's community cyber threat intelligence network and centralized Community Dashboard:
1. **Internal Crowdsourced Victim Network:** Collects anonymous incident reports, monetary losses (in INR), scammer contact handles, and proof screenshots from campus students.
2. **External "Go-To" Scam Reporting Portals Integration:** Aggregates reputation data from global anti-scam databases and provides direct routing links so victims and proactive students can report scammers directly to official law enforcement and cyber safety agencies.
3. **Legal Aid & Immediate Response Engine:** Automatically generates legally cited FIR complaint drafts compliant with the National Cyber Crime Reporting Portal (`cybercrime.gov.in`) and provides time-critical "Golden Hour" 1930 helpline recovery checklists.
4. **Community Cyber Threat Intelligence Dashboard:** Central hub with real-time statistics, 6-category threat breakdown, filterable recent activity, cross-report trending indicators, and active student advisories.

---

## 2. Key Pillars & Architecture

### Pillar A: Internal Campus Victim Database (`storage.py`)
- Persistent SQLite datastore (`community_defense.db`) with `PRAGMA journal_mode=MEMORY` and busy timeouts.
- Accepts structured reports via `VictimReportSubmission` and issues unique tracking references (e.g. `COMM-REPORT-TCS-2611011929`).
- Pre-seeded with 14 verified student scam cases across all 6 core categories.
- Calculates cumulative financial impact: `total_financial_loss_inr` and `total_submitted_incidents`.
- Anonymizes victim statements to provide social proof: *"Student from Srinivas Inst transferred Rs. 3,500; contact blocked immediately"*.
- Exposes historical incident records to Agent 2 Correlator (`GET /api/community/reports-all`) for multi-incident syndicate graph construction.

### Pillar B: External Go-To Reporting Portals (`external_portals.py`)
Factora connects students directly to verified complaint & intelligence portals:
- **National Cyber Crime Reporting Portal (MHA, Govt of India):** `https://cybercrime.gov.in` (Direct URL for filing financial cyber fraud & job scams).
- **National Cyber Crime Helpline (1930):** Direct hotline for Citizen Financial Cyber Fraud Reporting System (CFCFRMS) auto-freezes.
- **CERT-In (Indian Computer Emergency Response Team):** `https://www.cert-in.org.in` (Incident reporting for malware, fake domains & phishing).
- **ScamAdviser:** `https://www.scamadviser.com` (Direct domain trust score & WHOIS age checks).
- **Reddit r/Scams Community:** Live sentiment and thread queries on emerging modus operandi.
- **NPCI Dispute Redressal Portal:** `https://www.npci.org.in` (Direct dispute mechanism for fraudulent UPI VPAs).
- **National Consumer Helpline (NCH):** `https://consumerhelpline.gov.in` (Education & fake coaching deposit complaints).

### Pillar C: Legal Aid & Incident Response Engine (`legal_aid.py`)
- **Automated FIR / Cyber Complaint Draft:** Generates formal complaint text citing Section 66D/66C of the Information Technology Act 2000, Section 419/420 of IPC, and Sections 318/319 of Bharatiya Nyaya Sanhita (BNS) 2023.
- **Emergency 1930 "Golden Hour" Freeze Guide:** Action steps to halt inter-bank money routing within 2–24 hours of unauthorized UPI transfer.
- **Campus Placement Cell Bulletin:** Ready-to-broadcast warning advisories for college placement coordinators and WhatsApp groups.

### Pillar D: Community Threat Intelligence Dashboard (`dashboard_ui.py`)
A tactile neumorphic single-page web dashboard implementing all 5 required views:
1. **Dashboard Statistics:** Total submitted incidents, newly reported incidents (past 7 days), corroborated reports, potential threat campaigns, and active community alerts.
2. **Threat Category Overview:** Dynamic risk metrics and counts for Phishing, Recruitment & Internship Fraud, Financial Scams, GitHub Repo Risks, Website Impersonation, and Account Compromise.
3. **Recent Community Activity:** Filterable feed showing category, date, amount, verification badge, and interactive modal trigger.
4. **Trending Threats:** Indicators appearing across multiple reports (UPI IDs, domains, repos) with incident counts, financial exposure, and risk assessments.
5. **Community Alerts:** Curated active high-priority campus warning advisories.

---

## 3. Contract Output & Endpoints

- **Contract:** Produces `CommunityThreatLookupResponse` (locked model in `shared/schemas.py`, with non-breaking optional fields `matched_indicators`, `complaint_draft_fir`, `emergency_freeze_checklist`, and `campus_broadcast_advisory`).
- **Dashboard Endpoints:**
  - `GET /api/community/ui` & `GET /community` — Serves the interactive Tactile Neumorphic web dashboard.
  - `GET /api/community/dashboard` — Full aggregated JSON payload for external consumers.
  - `GET /api/community/dashboard/stats` — 5 primary database statistics metrics.
  - `GET /api/community/dashboard/categories` — 6 core threat categories overview.
  - `GET /api/community/dashboard/activity` — Recent activity feed with category filtering (`?category=...&limit=...`).
  - `GET /api/community/dashboard/trending-threats` — Cross-incident indicator rankings.
  - `GET /api/community/dashboard/alerts` — Active community alerts and warnings.
  - `GET /api/community/dashboard/incident/{incident_ref}` — Detailed incident dossier with FIR draft and freeze steps.
- **Core Intelligence Endpoints:**
  - `GET /api/community/health` — Service health and SQLite metrics.
  - `GET /api/community/mock` — Realistic mock response for frontend development.
  - `POST /api/community/lookup` — Query threat indicators across victim database & external portal connectors.
  - `GET /api/community/external-portals` — Curated directory of Go-To reporting sites with tailored deep-links.
  - `POST /api/community/report` — Ingest 11-field student victim report with pseudonymous attribution, validation, initial `SUBMITTED` status, and instant FIR draft.
  - `POST /api/community/upload-evidence` — Upload permitted evidence files (PNG, JPG, WEBP, PDF, TXT up to 10 MB each) with secure sanitization and virus isolation.
  - `GET /api/community/evidence/{filename}` — Safely retrieve uploaded evidence documents/screenshots with path traversal prevention.
  - `GET /api/community/reports/my-submissions` — Retrieve incidents submitted by the authenticated pseudonymous handle with real-time verification review status.
  - `GET /api/community/feed` — Server-side paginated community incident feed with 5 multi-factor query filters (`page`, `page_size`, `category`, `risk_level`, `verification_status`, `date_filter`, `incident_type`, `q`), card metadata (title, category, short desc, date, risk level, status, related incidents count), and PII redaction.
  - `GET /api/community/feed/filters` — Dynamic filter options for categories, risk levels, verification statuses, date filters, and scam types.
  - `GET /api/community/search` — Dedicated 6-step threat indicator search (`q=...`, `page`, `page_size`). Distinguishes confirmed exact indicator matches (`confidence=1.0`) from correlated syndicate campaigns (`confidence=0.88`) and approximate company name matches (`confidence=0.70`). Never treats similar company names or message text as proof of connection or organization guilt.
  - `GET /api/community/statistics` — Global platform metrics.
  - `GET /api/community/reports-all` — Export historical dataset for Agent 2 Correlator graph construction.
  - `POST /api/community/generate-fir-draft` — Dedicated FIR complaint generator.
- **Dynamic Threat Alerts (Prompt 5 Requirement 1):**
  - `GET /api/community/alerts` — Dynamic community threat advisories generated from multi-incident SQLite indicator overlap with deduplication and cautious disclaimer ("Potentially Related Incidents").
  - `GET /api/community/alerts/{alert_id}` — Threat advisory details with list of connected incident records for user inspection.
- **Cyber Awareness & Education Centre (Prompt 5 Requirement 3):**
  - `GET /api/community/education` — 6 educational defense modules enriched with live database statistics and real-world loss metrics.
  - `GET /api/community/education/{topic_id}` — Detailed threat vector guidance, warning signs, sanitized examples, consequences, prevention tips, and actions.
- **Threat Relationship Graph (Prompt 5 Requirement 4):**
  - `GET /api/community/graph` — Multi-incident correlation graph returning `GraphNode` and `GraphEdge` objects based strictly on corroborated indicators (domains, UPI/phones, repos, campaigns) with zero decorative hallucination.
  - `GET /api/community/graph/{incident_ref}` — Targeted neighborhood graph for a specific incident with empty state handling (`has_relationships = False`) when no links exist.
- **Moderation & Verification System (Prompt 5 Requirement 2):**
  - `GET /api/community/moderation/reports` — Protected moderation queue (`X-Moderator-Key` required) to view submitted reports, evidence, and filter by status/flag.
  - `POST /api/community/moderation/review/{incident_ref}` — Apply status update (`SUBMITTED`, `UNDER_REVIEW`, `CORROBORATED`, `DISPUTED`, `CLOSED`, `ARCHIVED`), approve public display, and log immutable audit record.
  - `POST /api/community/moderation/flag/{incident_ref}` — Flag report as duplicate (linking canonical ref), spam, misleading, or incomplete.
  - `GET /api/community/moderation/logs/{incident_ref}` — Retrieve immutable audit trail for an incident.
- **Independent Agent Decoupled Endpoints:**
  - `GET /api/community/agents/status` — Probes Agent 1 and Agent 2 over configurable HTTP without launching them; reports explicit `service-unavailable` / `pending-analysis` if offline.
  - `POST /api/community/agents/analyze` — Forwards payloads to Agent 1 when available; returns `pending-analysis` without fabricating responses if unavailable.
  - `POST /api/community/agents/correlate` — Forwards incidents to Agent 2 for campaign correlation; returns `pending-analysis` without generating fake graph data if unavailable.
