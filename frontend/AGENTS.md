# Member 4: Factora Frontend UI Application
**Directory:** `/frontend/`
**Owner:** Member 4

---

## 1. Mission & Scope

Member 4 is responsible for delivering the end-user interface for Factora. The UI turns complex multi-agent intelligence into an intuitive, tactile web application that enables students, placement officers, and developers to assess offers, verify safety steps, inspect threat networks, and report scams.

---

## 2. Visual Aesthetic & Design Tokens (Locked Reference Standard)

Factora adheres to a **Tactile Neumorphic & 3D Skeuomorphic-Modern** design language in a high-contrast monochrome / grayscale palette, derived from the team's approved design references:

* **Canvas & Surfaces:**
  * Background: Soft off-white / light slate (`#F2F4F7` / `#ECEEF1`).
  * Cards: Pure white (`#FFFFFF`) with multi-layered soft drop shadows (`box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.06), 0 8px 10px -6px rgba(0, 0, 0, 0.04)`), generous corner radiuses (`24px`–`28px`).
* **Tactile Contrasts & Controls:**
  * Buttons: Deep matte charcoal/black (`#141518`) pills with smooth specular edge lighting, white typography, and directional icons (`→`).
  * Secondary Controls: Squircle action buttons (`✓`, `✕`, `⏸`), pill toggles, and inset filter badges.
  * Indicators: Electric neon green status dot (`#22C55E`) for verified states; crisp high-contrast red/amber for critical threats.
* **Specialized Visual Widgets:**
  * **Tactile Speedometer Dial:** Semi-circular gauge meter displaying the 0–100 P.R.I.M.E. fuzzy risk index with a 3D needle and numerical calibrations (`0`, current score, `100`).
  * **3D Stacked Deck:** Layered card offset effect for entity attribution and recruiter verification profiles.
  * **Organic Wave & Bar Visualizations:** Tactile spline charts for risk trends and contribution/activity history.

---

## 3. Four Core Interface Views

1. **Intake & Instant Threat Analyzer (Agent 1 Feed):**
   - Multimodal input bar: text paste, URL entry, offer letter file/screenshot upload, and GitHub repo URL.
   - P.R.I.M.E. Criteria Radar / Bar Breakdown (Proof, Redirection, Urgency, Money, Execution, Student Registry).
   - **Interactive "Before You Proceed" Verification Checklist:** An interactive checklist with toggleable checkboxes and direct guidance links that guides students through mandatory pre-action checks before they reply or pay.
2. **Threat Correlation & Entity Graph (Agent 2 Canvas):**
   - Interactive node-link canvas rendering `GraphNode` and `GraphEdge` structures.
   - Highlights connected syndicates, shared UPI IDs, lookalike domains, and recurring campaign warnings.
3. **Community Victim Network & Loss Ticker (Member 3 Feed):**
   - Live campus ticker displaying `total_reported_money_lost_inr` and `internal_victim_reports_count`.
   - Anonymized victim testimonials with proof viewer.
   - Anonymous "Report a Scam" quick modal with evidence upload.
4. **External "Go-To" Scam Reporting Directory:**
   - Card gallery displaying verified external platforms (`cybercrime.gov.in`, CERT-In, ScamAdviser, Reddit r/Scams).
   - Direct-action buttons linking users immediately to external official complaint filing pages.

---

## 4. API Consumption Contract

All frontend components consume endpoints from the unified FastAPI backend (`http://localhost:8000`):
- `POST /api/analyzer/analyze` and `GET /api/analyzer/mock`
- `POST /api/correlator/correlate` and `GET /api/correlator/mock`
- `POST /api/community/lookup` and `GET /api/community/mock`
- `GET /api/community/external-portals`
- `POST /api/community/report`

