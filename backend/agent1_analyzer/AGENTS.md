# Agent 1: Cyber Threat Detection Agent — Analyzer
**Directory:** `/backend/agent1_analyzer/`
**Owner:** Member 1

---

## 1. Mission & Scope

Agent 1 is the primary intake and threat detection engine of Factora. It ingests suspicious communications (emails, WhatsApp/SMS transcripts, offer letters, URLs, and code repository links) and extracts atomic threat indicators to determine fraud probability with mathematical and heuristic rigor.

---

## 2. Ingestion & Analysis Pipelines

1. **Multimodal Ingestion:**
   - **Text & Raw Copy:** Regex and NLP tokenization for salary promises, urgent deadlines, and payment keywords.
   - **Offer Letter & Screenshot OCR:** Vision AI extraction of corporate headers, rubber stamps, signatures, and contact handles.
   - **URL & Domain Intelligence:** Redirect unrolling, WHOIS creation age (<90 days = critical flag), DNS SPF/DKIM record lookups, and detection of Google Forms / Tally / free form builder abuse for job intake.
2. **Developer & Student Supply-Chain Analysis:**
   - **GitHub Repo Inspection:** Scans assessment codebases for hidden malicious patterns.
   - **VS Code Traps:** Identifies `.vscode/tasks.json` configured with `runOn: folderOpen` to execute untrusted code silently upon opening the workspace.
   - **Malicious Dependency Hooks:** Flags npm `preinstall`, `install`, `postinstall`, or `prepare` scripts that initiate curl/powershell payloads, and pip `setup.py` execution hooks.
3. **Student-Targeted Scam Registries & Rules:**
   - **UGC Fake University Registry:** Validates college names against the official University Grants Commission blacklist.
   - **AICTE & Scholarship Verification:** Checks against approved technical education institutions and official `scholarships.gov.in` parameters.
   - **Zero-Interview Flag:** Highlights direct offers without technical assessments.
   - **Upfront Fee Rule:** Flags registration fees, security deposits for laptops/assets, and training bonds.
   - **Task & Mule Scams:** Detects Telegram rating/subscriber task loops and requests to use student bank accounts for forwarding funds.

---

## 3. P.R.I.M.E. Scoring Matrix

Each incident is evaluated across six criteria on a 0.0 – 10.0 scale:
- **P — Proof & Domain Identity:** DKIM/SPF alignment, WHOIS age, corporate email vs. free webmail.
- **R — Redirection & Obfuscation:** Shorteners (bit.ly, tinyurl), dynamic redirects, hidden trackers.
- **I — Incentive & Urgency Pressure:** Astronomical stipends, 24h expiration timers, emotional coercion.
- **M — Money & Transaction Ask:** UPI payment requests, onboarding fees, security bonds.
- **E — Execution & Code Safety:** Untrusted binaries, suspicious npm/pip hooks, malicious `.vscode` tasks.
- **S — Student Registry Verification:** UGC fake university list matches, unaccredited institutes.

Fuzzy Risk Formula synthesizes these weights into a 0–100 index mapping to:
`Verified Safe` | `Low Risk` | `Caution` | `High Risk` | `Critical Scam`

---

## 4. Contract Output & Endpoints

- **Contract:** Produces `ThreatIntelligenceRecord` adhering to `/shared/schemas.py`.
- **Mandatory Feature:** Must include `verify_before_proceeding_checklist` (`List[VerificationStep]`).
- **Endpoints:**
  - `POST /api/analyzer/analyze`
  - `GET /api/analyzer/mock`
  - `GET /api/analyzer/checklist/{incident_id}`
  - `GET /api/analyzer/health`
