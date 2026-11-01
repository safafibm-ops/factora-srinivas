# Factora Team Progress Tracker
**Problem 1: Safety Tech — FAKE OR REAL (Hackathon 2026)**

This document tracks implementation status across all 4 team streams. Every member updates their respective checklist upon completing tasks.

## Latest Reliability Fixes
- [x] Fixed extension re-scan to message the active tab's content script, inject it when absent, keep the popup open for results, and show timeout/access errors.
- [x] Connected the browser extension's page text and current GitHub repository to Agent 1 before sending Agent 1's extracted indicators to Agent 2.
- [x] Made the extension and popup display Agent 1's risk tier/evidence and avoid showing a safe verdict when a scan has not completed.
- [x] Detects payment requests such as "send Rs 5,000" even without the word "fee".
- [x] Added repository purpose checks for malware-sample collections and made the result a research-material caution, not a claim that the owner is malicious.
- [x] Removed upfront-fee false positives when message explicitly says the employer does not request fees or deposits.
- [x] Changed inaccessible GitHub audits to report **Caution / unverified**, without claiming the repository is safe or confirmed malicious.
- [x] Required concrete shared indicators before Agent 2 reports a historical incident match; campaign warnings now describe potential associations.
- [x] Display live analyzer and correlator model-load status in the dashboard instead of hard-coded readiness labels.
- [x] Corrected the TCS demo URL so its short-link/domain signal is actually analyzed.
- [x] Prevent explicit no-fee policy statements from being scored as fee demands; fee rules now require affirmative payment evidence.

---

## 🏗️ Stream 0: Architecture & Contracts (Lead Architect)
- [x] Initialized monorepo directory layout with domain separation.
- [x] Created locked Pydantic v2 data models in `/shared/schemas.py`.
- [x] Built universal `get_mock_data()` helper function for offline testing.
- [x] Defined team sync and contract enforcement rules in `/.agents/rules/sync-and-contracts.md`.
- [x] Implemented unified FastAPI gateway in `/backend/main.py` with permissive CORS.
- [x] Built working mock routers in `agent1_analyzer`, `agent2_correlator`, and `community_hub`.
- [x] Verified local server execution (`uvicorn backend.main:app --reload`).

---

## 🔍 Stream 1: Member 1 — Agent 1 (Cyber Threat Analyzer)
- [x] Directory and role documentation established in `/backend/agent1_analyzer/AGENTS.md`.
- [x] Trained Agent 1 Real ML Ensemble (`Calibrated LinearSVC + XGBoost` on 32,500+ rows, ROC-AUC 0.987, F1 0.914).
- [x] Built live URL redirect unrolling & Wayback Machine CDX API footprint analyzer.
- [x] Connected WHOIS domain age lookup (<90 days high-risk threshold).
- [x] Implemented Brand-to-Domain mismatch & Google Forms/Tally abuse detector.
- [x] Created official UGC Fake Universities database & Indian student registry verifier (`scholarships.gov.in`, AICTE).
- [x] Implemented multi-tier Screenshot OCR & Vision Entity Extractor.
- [x] Built GitHub repo assessment & dependency malware auditor (`.vscode/tasks.json` folderOpen, npm hooks, typosquats).
- [x] Built P.R.I.M.E. Neuro-Symbolic fuzzy risk scorer (6-criteria 0–10 matrix, 0–100 index, risk tiers).
- [x] Generated evidence-backed `why_it_is_risky_summary` & interactive `verify_before_proceeding_checklist`.
- [x] Connected production endpoints `POST /api/analyzer/analyze` and `GET /api/analyzer/checklist/{id}`.
- [x] Working mock router endpoint `GET /api/analyzer/mock` active.
- [x] Heuristic threat analysis endpoint `POST /api/analyzer/analyze` active.
- [x] Checklist retrieval endpoint `GET /api/analyzer/checklist/{incident_id}` active.
- [ ] Connect production WHOIS domain age lookup (<90 days threshold).
- [ ] Implement URL redirect unroller with tracker stripping.
- [ ] Integrate Vision AI / OCR engine for offer letter screenshots & PDFs.
- [ ] Connect UGC Fake University & AICTE unverified registry checks.
- [ ] Integrate GitHub repository scanner for `.vscode/tasks.json` folderOpen and package hook backdoors.
- [ ] Implement fine-grained P.R.I.M.E. fuzzy scoring algorithm (0–100 scale).

---

## 🕸️ Stream 2: Member 2 — Agent 2 (Threat Intelligence Correlator)
- [x] Directory and role documentation established in `/backend/agent2_correlator/AGENTS.md`.
- [x] Working mock router endpoint `GET /api/correlator/mock` active.
- [x] Correlation endpoint `POST /api/correlator/correlate` active.
- [x] Graph visual export endpoint `GET /api/correlator/graph/{incident_id}` active.
- [x] Build in-memory / SQLite vector database for historical incident indicators.
- [x] Implement Jaccard / Levenshtein similarity matching for domains, emails, and handles.
- [x] UPI ID and phone number clustering logic to identify recurring syndicates.
- [x] Dynamic NetworkX / Cytoscape graph node & edge generator with confidence weighting.
- [x] Automated generation of campus-wide warning announcements for recurring syndicates.

---

## 🛡️ Stream 3: Member 3 — Community Hub & External Reporting Portals
- [x] Directory and role documentation established in /backend/community_hub/AGENTS.md.
- [x] Working mock router endpoint GET /api/community/mock active.
- [x] Indicator lookup endpoint POST /api/community/lookup active.
- [x] External portals directory endpoint GET /api/community/external-portals active.
- [x] Student victim report submission endpoint POST /api/community/report active.
- [x] Persistent SQLite database (community_defense.db) for crowdsourced victim reports, INR loss counter, and PII masking.
- [x] Integrated Evidence storage with file validation, MIME sanitization, and path traversal prevention.
- [x] Automated legal aid FIR complaint drafting and emergency bank freeze checklists.
- [x] Interactive Threat Relationship Graph with SVG node-link topology and click inspection.
- [x] Decoupled agent integration endpoints with status badges for Agent 1 and Agent 2.
- [x] Restyled Community Dashboard UI (/api/community/ui) to match tactile ceramic & obsidian hardware aesthetic with back-navigation to Main Platform.

---

## 🎨 Stream 4: Member 4 — Tactile Neumorphic Frontend UI
- [x] Architecture, tokens, and aesthetic documented in `/frontend/AGENTS.md`.
- [x] Initialized frontend application structure (React 18 + Tailwind + Lucide Icons).
- [x] Implemented Tactile Neumorphic / Skeuomorphic-Modern design tokens (monochrome / grayscale).
- [x] Built Tactile Speedometer Gauge meter for P.R.I.M.E. fuzzy risk score (0–100).
- [x] Built Interactive "What to Verify Before Proceeding" checklist with checkboxes and guidance.
- [x] Built Interactive Threat Relationship Graph canvas (`GraphNode` & `GraphEdge` rendering).
- [x] Built Community Victim Feed with live INR loss ticker and anonymous reporting modal.
- [x] Built External "Go-To" Scam Reporting Portal directory cards with one-click official filing links.
- [x] End-to-end integration with `http://localhost:8000/api/*` endpoints served seamlessly at `/` and `/ui`.
- [x] Upgraded Left Navigation to tactile squircle sidebar with brand header (`Factora PRO`), categorized section headings (`Threat Intelligence`, `Community Defense`, `Integrations`), labeled items with badges, and mobile bottom navigation strip.

