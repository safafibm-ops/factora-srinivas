# Agent 2: Cyber Threat Intelligence Correlation Agent — Correlator
**Directory:** `/backend/agent2_correlator/`
**Owner:** Member 2

---

## 1. Mission & Scope

Agent 2 elevates Factora from isolated point-in-time scanning to syndicated threat intelligence. It correlates parsed indicators from Agent 1 with the historical incident repository and Member 3's Community Victim Database to uncover organized phishing syndicates, recurring fake recruiters, and coordinated scam campaigns.

---

## 2. Correlation Capabilities

1. **Indicator Cross-Matching:**
   - Evaluates shared parameters across incidents:
     - **Financial Identifiers:** Exact UPI ID matches, phone numbers, IFSC prefixes, and beneficiary names.
     - **Infrastructure:** Shared WHOIS registrants, IP clusters, DNS nameservers, and certificate fingerprints.
     - **Code Repositories:** Shared GitHub author accounts, recurring commit signatures, and duplicate obfuscated dependency packages.
2. **Campaign Detection & Relationship Graph:**
   - Groups related incidents into named threat campaigns (e.g., *"GhostRecruiter Syndicate #4"*).
   - Generates directional relationship graphs composed of `GraphNode` and `GraphEdge` structures.
   - Calculates a `relationship_confidence` score (0.0 to 1.0) and generates human-readable explanations of why two events are linked (e.g. *"Identical SBI UPI receiver was used in 14 previous fake Infosys placement offers"*).
3. **Campus-Wide Early Warnings:**
   - When a recurring campaign crosses threshold frequency, Agent 2 synthesizes actionable recommendations for placement officers and college student councils.

---

## 3. Contract Output & Endpoints

- **Contract:** Produces `ThreatRelationshipRecord` adhering to `/shared/schemas.py`.
- **Endpoints:**
  - `POST /api/correlator/correlate`
  - `GET /api/correlator/mock`
  - `GET /api/correlator/graph/{incident_id}`
  - `GET /api/correlator/health`
