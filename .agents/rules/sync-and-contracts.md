---
trigger: always_on
description: Enforces Factora shared contracts and team progress
---

# Factora Architecture & Sync Rules

@[factora_schemas](../../shared/schemas.py)
@[factora_progress](../../PROGRESS.md)

## Team Sync & Contract Governance Rules

1. **Strict Contract Validation:**
   - All backend endpoints and frontend integrations **must strictly validate** request and response payloads using `/shared/schemas.py`.
   - Any schema modification requires consensus and must be updated in `/shared/schemas.py` and reflected in `get_mock_data()`.

2. **Folder Isolation & Parallel Work:**
   - Teammates must stay strictly inside their assigned domain folders:
     - **Member 1 (Agent 1):** `/backend/agent1_analyzer/`
     - **Member 2 (Agent 2):** `/backend/agent2_correlator/`
     - **Member 3 (Community Hub):** `/backend/community_hub/`
     - **Member 4 (Frontend UI):** `/frontend/`
   - Never modify another member's internal business logic without coordination. All communication happens across the locked schemas.

3. **Live Progress Tracking:**
   - Update `/PROGRESS.md` whenever a feature, task, test, or router endpoint is completed or updated.

4. **Mandatory Hackathon Features (Zero Tolerance for Dropping):**
   - **(a) Interactive "What to Verify Before Proceeding" Checklist:** Every analysis returned by Agent 1 must include clear, actionable verification steps (`verify_before_proceeding_checklist`) for the student before they click, pay, or execute anything.
   - **(b) External "Go-To" Scam Reporting Websites Integration:** Member 3 and Frontend must aggregate reports from external threat sources (ScamAdviser, PhishTank, Reddit) AND provide direct, one-click outbound routing to official portals (`cybercrime.gov.in`, CERT-In, National Consumer Helpline).
   - **(c) Student-Specific Scam Checks:** Never omit checks for:
     - UGC Fake University & AICTE Accreditation registries.
     - Official `.gov.in` scholarship verification (`scholarships.gov.in`).
     - Upfront deposit/fee demands (laptop security, interview guarantee, onboarding charges).
     - Zero-interview automatic offer letters.
     - Telegram/WhatsApp "task scams" (pay-per-like/rating).
     - Student money-mule / UPI rental requests.
     - Developer traps: GitHub repo assessment malware (e.g. VS Code `.vscode/tasks.json` folderOpen hooks, npm `postinstall` / `prepare` stealer scripts).
