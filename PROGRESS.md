# Factora Team Progress Tracker
**Problem 1: Safety Tech — FAKE OR REAL (Hackathon 2026)**

This document tracks implementation status across all 4 team streams. Every member updates their respective checklist upon completing tasks.

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
- [ ] Build in-memory / SQLite vector database for historical incident indicators.
- [ ] Implement Jaccard / Levenshtein similarity matching for domains, emails, and handles.
- [ ] UPI ID and phone number clustering logic to identify recurring syndicates.
- [ ] Dynamic NetworkX / Cytoscape graph node & edge generator with confidence weighting.
- [ ] Automated generation of campus-wide warning announcements for recurring syndicates.

---

## 🛡️ Stream 3: Member 3 — Community Hub & External Reporting Portals
- [x] Directory and role documentation established in `/backend/community_hub/AGENTS.md`.
- [x] Working mock router endpoint `GET /api/community/mock` active.
- [x] Indicator lookup endpoint `POST /api/community/lookup` active.
- [x] External portals directory endpoint `GET /api/community/external-portals` active.
- [x] Student victim report submission endpoint `POST /api/community/report` active.
- [ ] Persistent storage for crowdsourced victim reports and INR loss counter.
- [ ] Live external threat lookup connectors (ScamAdviser API, PhishTank, URLHaus).
- [ ] Subreddit scraper / query integration for `r/Scams` emerging tactics.
- [ ] Direct deep-link generator for `cybercrime.gov.in`, CERT-In, and National Consumer Helpline.

---

## 🎨 Stream 4: Member 4 — Tactile Neumorphic Frontend UI
- [x] Architecture, tokens, and aesthetic documented in `/frontend/AGENTS.md`.
- [ ] Initialize frontend application structure (React / Next.js / Vite / Tailwind).
- [ ] Implement Tactile Neumorphic / Skeuomorphic-Modern design tokens (monochrome / grayscale).
- [ ] Build Tactile Speedometer Gauge meter for P.R.I.M.E. fuzzy risk score (0–100).
- [ ] Build Interactive "What to Verify Before Proceeding" checklist with checkboxes and guidance.
- [ ] Build Interactive Threat Relationship Graph canvas (`GraphNode` & `GraphEdge` rendering).
- [ ] Build Community Victim Feed with live INR loss ticker and anonymous reporting modal.
- [ ] Build External "Go-To" Scam Reporting Portal directory cards with one-click official filing links.
- [ ] End-to-end integration with `http://localhost:8000/api/*` endpoints.

