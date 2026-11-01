"""Test script to verify Agent 2 router endpoints synchronously."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.agent2_correlator.router import health_check, correlate_incident, get_incident_graph
from shared.schemas import IncidentCorrelateRequest, ThreatIndicators, StudentScamFlags

def main():
    print("1. Testing /api/correlator/health...")
    h = health_check()
    print("Health response:", h)

    print("\n2. Testing /api/correlator/correlate...")
    req = IncidentCorrelateRequest(
        incident_id="INC-2026-LIVE-TEST-99",
        extracted_indicators=ThreatIndicators(
            domains=["tcs-careers-portal.in"],
            emails=["hr@tcs-careers-portal.in"],
            phones_or_upi=["+919876543210", "tcs.hrverification@oksbi"],
            claimed_organization="Tata Consultancy Services",
            github_repos=["https://github.com/tcs-assessment-portal/coding-round-2026"],
            suspicious_packages=["cross-env-stealer"],
            student_scam_flags=StudentScamFlags(upfront_fee=True, zero_interview=True)
        )
    )
    rec = correlate_incident(req)
    print("Correlation successful!")
    print(f"  Detected Syndicate: {rec.detected_campaign_name}")
    print(f"  Is Recurring:       {rec.is_recurring_campaign}")
    print(f"  Matched Incidents:  {len(rec.related_incidents)}")
    print(f"  Graph Nodes:        {len(rec.graph_nodes)}")
    print(f"  Graph Edges:        {len(rec.graph_edges)}")
    print(f"  Warnings:           {len(rec.recommended_community_warnings)}")

    print("\n3. Testing /api/correlator/graph/INC-2026-LIVE-TEST-99...")
    g = get_incident_graph("INC-2026-LIVE-TEST-99")
    print("Graph retrieval successful!")
    print(f"  Nodes: {g['total_nodes']}, Edges: {g['total_edges']}, Campaign: {g['campaign']}")

if __name__ == "__main__":
    main()
