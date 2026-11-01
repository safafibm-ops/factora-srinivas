# Member 3: Community Victim Network & External Go-To Reporting Websites Hub
**Directory:** `/backend/community_hub/`
**Owner:** Member 3

---

## 1. Mission & Scope

Member 3 manages Factora's dual-action community intelligence network:
1. **Internal Crowdsourced Victim Network:** Collects anonymous incident reports, monetary losses (in INR), scammer contact handles, and proof screenshots from campus students.
2. **External "Go-To" Scam Reporting Portals Integration:** Aggregates reputation data from global anti-scam databases and provides direct routing links so victims and proactive students can report scammers directly to official law enforcement and cyber safety agencies.

---

## 2. Key Pillars

### Pillar A: Internal Campus Victim Database
- Accepts structured reports via `VictimReportSubmission`.
- Calculates cumulative financial impact: `total_reported_money_lost_inr` and `internal_victim_reports_count`.
- Anonymizes victim statements to provide social proof: *"Student from Srinivas Inst transferred ₹3,500; contact blocked immediately"*.
- Exposes historical incident records to Agent 2 for multi-incident correlation.

### Pillar B: External Go-To Reporting Portals
Factora does not silo scam data—it connects users directly to verified complaint portals:
- **National Cyber Crime Reporting Portal (MHA, Govt of India):** `https://cybercrime.gov.in` (Direct URL for filing financial cyber fraud & job scams).
- **CERT-In (Indian Computer Emergency Response Team):** `https://www.cert-in.org.in` (Direct incident reporting for malware & phishing).
- **ScamAdviser:** `https://www.scamadviser.com` (Domain age & automated trust score verification).
- **PhishTank / URLHaus:** Direct repository checks for reported phishing links.
- **Reddit r/Scams Community:** Live sentiment and thread queries on emerging modus operandi.

---

## 3. Contract Output & Endpoints

- **Contract:** Produces `CommunityThreatLookupResponse` containing `List[ExternalPortalReport]`.
- **Endpoints:**
  - `POST /api/community/lookup`
  - `GET /api/community/mock`
  - `GET /api/community/external-portals`
  - `POST /api/community/report`
  - `GET /api/community/health`

