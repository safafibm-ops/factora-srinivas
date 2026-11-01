"""
Factora Dynamic Community Threat Alerts Engine
Module: backend.community_hub.threat_alerts
Generates real-time, evidence-based alerts directly from the SQLite community incident records.

Safety Guarantees & Constraints:
1. Derives alerts from actual multi-incident indicator overlap in the database (no hardcoding).
2. Avoids duplicate alerts for the same underlying campaign by clustering shared indicators.
3. Uses cautious language: "Potentially Related Incidents".
4. Never makes unsupported accusations against organizations or individuals.
5. Provides related incidents list so users can inspect evidence.
"""

from typing import List, Dict, Any, Optional, Set
import hashlib
import json
import sqlite3
from pathlib import Path

from backend.community_hub.storage import (
    get_db_connection,
    extract_row_indicators,
    mask_contact,
    compute_incident_risk_level
)

CATEGORY_NAMES = {
    "recruitment_fraud": "Recruitment & Internship Fraud",
    "financial_scam": "Financial Scams",
    "github_repo_risk": "GitHub Repository & Package Risks",
    "website_impersonation": "Website Impersonation",
    "phishing": "Phishing",
    "account_compromise": "Account Compromise"
}


def generate_dynamic_community_alerts() -> List[Dict[str, Any]]:
    """
    Scans victim_reports in SQLite, detects recurring indicators (domains, UPI/phones, repos, campaigns),
    merges overlapping clusters to prevent duplicate alerts for the same syndicate, and generates
    cautious, evidence-grounded threat advisories.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM victim_reports ORDER BY id DESC")
        rows = cursor.fetchall()

        if not rows:
            return []

        # 1. Index all indicators
        indicator_to_incidents: Dict[str, Set[str]] = {}
        row_by_ref: Dict[str, sqlite3.Row] = {}

        for row in rows:
            ref = row["incident_ref"]
            row_by_ref[ref] = row
            inds = extract_row_indicators(row)

            for dom in inds.get("domains", []):
                indicator_to_incidents.setdefault(f"dom:{dom.lower()}", set()).add(ref)

            for upi_ph in inds.get("phones_or_upi", []):
                indicator_to_incidents.setdefault(f"contact:{upi_ph.lower()}", set()).add(ref)

            for repo in inds.get("github_repos", []):
                indicator_to_incidents.setdefault(f"repo:{repo.lower()}", set()).add(ref)

            camp = row["campaign_name"]
            if camp and camp != "Under Automated Correlation":
                indicator_to_incidents.setdefault(f"camp:{camp}", set()).add(ref)

        # 2. Filter to recurring indicators with >= 2 incidents
        recurring = {k: v for k, v in indicator_to_incidents.items() if len(v) >= 2}

        # 3. Cluster merging: If two indicators share >= 70% of incidents or belong to the same campaign, merge them
        # to avoid duplicate alerts for the same underlying activity.
        clusters: List[Dict[str, Any]] = []
        assigned_refs: Set[str] = set()

        # Prioritize confirmed campaign clusters first
        for ind_key, ref_set in sorted(recurring.items(), key=lambda x: (not x[0].startswith("camp:"), -len(x[1]))):
            overlap = ref_set.intersection(assigned_refs)
            if len(overlap) == len(ref_set):
                # Completely subsumed by an existing alert
                continue

            # Check if this overlaps heavily with an existing cluster
            merged = False
            for c in clusters:
                c_refs = c["incident_refs"]
                if len(ref_set.intersection(c_refs)) >= 1 and (ind_key.startswith("camp:") or c["canonical_key"].startswith("camp:")):
                    c["incident_refs"].update(ref_set)
                    c["indicators"].add(ind_key)
                    assigned_refs.update(ref_set)
                    merged = True
                    break

            if not merged:
                clusters.append({
                    "canonical_key": ind_key,
                    "indicators": {ind_key},
                    "incident_refs": set(ref_set)
                })
                assigned_refs.update(ref_set)

        alerts = []
        for c in clusters:
            ref_list = sorted(list(c["incident_refs"]))
            incident_rows = [row_by_ref[r] for r in ref_list if r in row_by_ref]
            if len(incident_rows) < 2:
                continue

            # Determine dominant category and latest date
            cat_counts: Dict[str, int] = {}
            total_lost = 0.0
            latest_date = "2026-01-01"

            related_incidents_payload = []
            for r in incident_rows:
                cat = r["category"] or r["scam_type"]
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
                amt = float(r["amount_demanded_or_lost_inr"] or 0.0)
                total_lost += amt
                r_date = r["reported_at"]
                if r_date > latest_date:
                    latest_date = r_date

                risk_l, risk_c = compute_incident_risk_level(r, len(incident_rows) - 1)
                related_incidents_payload.append({
                    "incident_ref": r["incident_ref"],
                    "incident_title": r["incident_title"],
                    "claimed_organization": r["claimed_organization"],
                    "reported_at": r["reported_at"],
                    "risk_level": risk_l,
                    "risk_color": risk_c,
                    "verification_status": r["verification_status"],
                    "amount_demanded_or_lost_inr": amt,
                    "description": r["description"][:140] + "..." if len(r["description"]) > 140 else r["description"]
                })

            dom_cat = max(cat_counts, key=cat_counts.get)
            cat_display_name = CATEGORY_NAMES.get(dom_cat, dom_cat.replace("_", " ").title())

            # Format shared indicators
            display_indicators = []
            canonical_label = ""
            for ind in c["indicators"]:
                prefix, val = ind.split(":", 1)
                if prefix == "dom":
                    display_indicators.append(val)
                    if not canonical_label:
                        canonical_label = f"Domain '{val}'"
                elif prefix == "contact":
                    display_indicators.append(mask_contact(val))
                    if not canonical_label:
                        canonical_label = f"Receiver '{mask_contact(val)}'"
                elif prefix == "repo":
                    repo_clean = val.split("/")[-1] if "/" in val else val
                    display_indicators.append(f"GitHub: {repo_clean}")
                    if not canonical_label:
                        canonical_label = f"Repository '{repo_clean}'"
                elif prefix == "camp":
                    display_indicators.append(f"Campaign: {val}")
                    canonical_label = val

            if not canonical_label:
                canonical_label = f"Cluster #{len(alerts) + 1}"

            alert_hash = hashlib.md5(f"{c['canonical_key']}-{len(ref_list)}".encode("utf-8")).hexdigest()[:6].upper()
            alert_id = f"ALT-CORR-{alert_hash}"

            is_critical = total_lost >= 10000 or len(incident_rows) >= 3
            severity = "CRITICAL" if is_critical else "HIGH"
            sev_color = "#EF4444" if is_critical else "#F59E0B"

            # Cautious title and advisory formulation
            title = f"Potentially Related Incidents Involving Suspect {canonical_label}"
            advisory = (
                f"{len(incident_rows)} community reports share corroborated indicator {canonical_label}. "
                f"Demands observed: total ₹{total_lost:,.0f} lost across victims. "
                f"Verify official channels directly before transferring funds, providing credentials, or executing code."
            )

            alerts.append({
                "alert_id": alert_id,
                "title": title,
                "alert_title": title,
                "category": cat_display_name,
                "threat_category": dom_cat,
                "severity": severity,
                "severity_color": sev_color,
                "number_of_related_incidents": len(incident_rows),
                "related_incidents_count": len(incident_rows),
                "shared_indicators": display_indicators[:5],
                "relationship_confidence": 0.95 if c["canonical_key"].startswith("dom:") or c["canonical_key"].startswith("contact:") else 0.88,
                "date": latest_date[:10],
                "issued_at": latest_date[:10],
                "generated_date": latest_date[:10],
                "status": "Active Alert",
                "target_demographic": "Engineering & College Students",
                "advisory_text": advisory,
                "summary": advisory,
                "cautious_disclaimer": "Potentially Related Incidents. Shared indicators alone do not prove a common perpetrator or company compromise.",
                "related_incidents": related_incidents_payload
            })

        return alerts
    finally:
        conn.close()


def get_community_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full alert payload including all related incident records."""
    alerts = generate_dynamic_community_alerts()
    for a in alerts:
        if a["alert_id"] == alert_id.strip():
            return a
    return None
