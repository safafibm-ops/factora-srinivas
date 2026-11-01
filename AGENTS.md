# Factora — Safety Tech Cyber Defense Monorepo
**Problem 1: Fake or Real (Hackathon 2026)**

Factora is a specialized, multi-agent cyber defense platform engineered to protect students, job seekers, and developers from deceptive recruitment campaigns, phishing syndicates, academic accreditation scams, and repository supply-chain attacks.

---

## 1. System Architecture & 4-Member Division of Labor

The monorepo is partitioned into four decoupled modules operating under a locked Pydantic contract (`/shared/schemas.py`). Teammates work in parallel inside their respective directories without merge friction:

```
factora-srinivas/
├── shared/
│   ├── schemas.py              # Locked Pydantic v2 data models & get_mock_data()
│   └── __init__.py
├── backend/
│   ├── main.py                 # FastAPI application wiring all 3 agent routers
│   ├── agent1_analyzer/        # Member 1: Threat Detection Agent (Analyzer)
│   │   ├── AGENTS.md
│   │   └── router.py
│   ├── agent2_correlator/      # Member 2: Threat Intelligence Correlation Agent
│   │   ├── AGENTS.md
│   │   └── router.py
│   └── community_hub/          # Member 3: Community Victim DB & Go-To Portals Hub
│       ├── AGENTS.md
│       └── router.py
├── frontend/                   # Member 4: Tactile Neumorphic Frontend Dashboard
│   └── AGENTS.md
├── .agents/rules/
│   └── sync-and-contracts.md   # Architectural integrity rules & sync directives
├── PROGRESS.md                 # Real-time team feature checklist
└── AGENTS.md                   # System-level architecture & agent registry
```

---

## 2. Agent & Team Member Registry

| Member / Role | Domain Directory | Core Responsibility | Contract Output |
|---|---|---|---|
| **Member 1: Agent 1** | `/backend/agent1_analyzer/` | Cyber Threat Detection Agent (Analyzer). Ingests emails, URLs, OCR images, code repos. Evaluates P.R.I.M.E. criteria, student scam heuristics, and compiles verification checklist. | `ThreatIntelligenceRecord` |
| **Member 2: Agent 2** | `/backend/agent2_correlator/` | Cyber Threat Intelligence Correlation Agent (Correlator). Matches indicators against past attacks & Community DB, reveals syndicates, and generates entity relationship graphs. | `ThreatRelationshipRecord` |
| **Member 3: Member 3** | `/backend/community_hub/` | Community Victim Network & External Go-To Reporting Portals Hub. Crowdsourced victim reporting, financial loss tally, and bidirectional integration with external reporting sites. | `CommunityThreatLookupResponse` |
| **Member 4: Member 4** | `/frontend/` | Tactile Neumorphic UI Dashboard. Implements high-contrast tactile widgets, verification checklist, entity graph canvas, and victim reporting forms. | End-User Experience |

---

## 3. Strict Operating Rules for Team Autonomy

1. **Contract Adherence:** All inter-agent data exchange strictly abides by `/shared/schemas.py`. Never change shared model fields without team consensus.
2. **Directory Isolation:** Commit code exclusively inside your designated directory.
3. **Always Mock-Ready:** Every service implements `get_mock_data()` and `/mock` endpoints so that frontend development and cross-agent testing can proceed uninterrupted.
4. **Non-Negotiable Core Features:**
   - **Interactive "Before You Proceed" Verification Checklist:** Guides students through protective actions before responding or executing code.
   - **External "Go-To" Scam Reporting Integration:** Collects external reputation data and provides direct links to official reporting portals (`cybercrime.gov.in`, CERT-In, ScamAdviser, Reddit r/Scams).
   - **Student-Specific Checks:** Upfront fees, zero-interview letters, UGC fake universities, AICTE verification, task scams, money mules, and GitHub assessment malware.

---

## 4. Running the Development Server

From the repository root (`factora-srinivas`):

```bash
# 1. Install dependencies
pip install fastapi uvicorn pydantic

# 2. Start the unified FastAPI backend
uvicorn backend.main:app --reload --port 8000
```

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- API Health Check: `http://localhost:8000/api/health`
