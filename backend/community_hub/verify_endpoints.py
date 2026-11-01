import sys
import os
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.community_hub.storage import (
    init_db,
    get_dashboard_statistics,
    get_category_overview,
    get_recent_activity,
    get_trending_threats,
    get_community_alerts,
    get_incident_by_ref,
)
from backend.community_hub.router import (
    get_full_dashboard,
    get_dashboard_stats,
    get_dashboard_categories,
    get_dashboard_activity,
    get_dashboard_trending_threats,
    get_dashboard_alerts,
    get_incident_detail,
    serve_community_dashboard,
    get_agents_status,
    forward_to_agent1,
    forward_to_agent2,
)

def test_router_endpoints():
    print("[1/5] Testing Full Aggregated Dashboard API (GET /api/community/dashboard)...")
    d = get_full_dashboard()
    assert d["status"] == "success"
    assert "agent_services" in d
    assert d["statistics"]["total_submitted_incidents"] >= 10
    assert len(d["categories"]) == 6
    assert len(d["recent_activity"]) >= 10
    assert len(d["trending_threats"]) >= 5
    assert len(d["community_alerts"]) >= 3
    print(f" -> Aggregated dashboard payload verified: {len(d['recent_activity'])} incidents, {len(d['categories'])} categories")

    print("[2/5] Testing Sub-endpoints (Stats, Categories, Trending, Alerts)...")
    stats = get_dashboard_stats()
    print(f" -> /api/community/dashboard/stats: {stats['total_submitted_incidents']} total, {stats['newly_reported_incidents']} new, {stats['active_community_alerts']} alerts")

    cats = get_dashboard_categories()
    print(f" -> /api/community/dashboard/categories: {len(cats)} categories verified")
    expected_cats = [
        "Recruitment & Internship Fraud",
        "Financial Scams",
        "GitHub Repository & Package Risks",
        "Website Impersonation",
        "Phishing",
        "Account Compromise"
    ]
    for c in cats:
        assert c["name"] in expected_cats

    trending = get_dashboard_trending_threats()
    print(f" -> /api/community/dashboard/trending-threats: {len(trending)} indicators identified")
    for t in trending[:2]:
        print(f"    * [{t['indicator_type']}] {t['indicator']} ({t['incident_count']} sightings) - {t['risk_assessment']}")

    alerts = get_dashboard_alerts()
    print(f" -> /api/community/dashboard/alerts: {len(alerts)} advisories active")

    print("[3/5] Testing Incident Dossier Detail (GET /api/community/dashboard/incident/{ref})...")
    first_ref = d["recent_activity"][0]["incident_ref"]
    dossier = get_incident_detail(first_ref)
    print(f" -> /api/community/dashboard/incident/{first_ref}: {dossier['claimed_organization']} | FIR draft len: {len(dossier['complaint_draft_fir'])}")
    assert "complaint_draft_fir" in dossier
    assert "emergency_freeze_checklist" in dossier
    assert "agent2_integration" in dossier
    print(f"    * Agent 2 Decoupled Correlation Status: {dossier['agent2_integration']['correlation_status']} ({dossier['agent2_integration']['status']})")

    print("[4/5] Testing Agent Decoupled Integration Endpoints...")
    agents_status = get_agents_status()
    print(f" -> /api/community/agents/status:")
    print(f"    * Agent 1 status: {agents_status['agent1_threat_analyzer']['status']} ({agents_status['agent1_threat_analyzer']['analysis_status']})")
    print(f"    * Agent 2 status: {agents_status['agent2_correlator']['status']} ({agents_status['agent2_correlator']['correlation_status']})")
    assert agents_status["agent1_threat_analyzer"]["status"] in ["online", "service-unavailable"]
    assert agents_status["agent2_correlator"]["status"] in ["online", "service-unavailable"]

    # Test forwarding to Agent 1 when agent process is not started
    a1_result = forward_to_agent1({"input_text": "Fake job offer asking for 3500 deposit"})
    print(f" -> /api/community/agents/analyze result: {a1_result['status']} (analysis_status: {a1_result.get('analysis_status')})")
    assert a1_result["analysis_status"] in ["completed", "pending-analysis"]

    # Test forwarding to Agent 2 when agent process is not started
    a2_result = forward_to_agent2(incident_id=first_ref)
    print(f" -> /api/community/agents/correlate result: {a2_result['status']} (correlation_status: {a2_result.get('correlation_status')})")
    assert a2_result["correlation_status"] in ["completed", "pending-analysis"]

    print("[5/5] Testing Dashboard HTML UI Endpoint (GET /api/community/ui)...")
    ui_resp = serve_community_dashboard()
    assert ui_resp.status_code == 200
    ui_html = ui_resp.body.decode("utf-8")
    assert "FACTORA" in ui_html
    assert "agent1StatusBadge" in ui_html
    assert "agent2StatusBadge" in ui_html
    assert "modalAgent2Badge" in ui_html
    print(f" -> UI HTML successfully rendered: {len(ui_resp.body)} bytes with agent status badges integrated")

    print("\n========================================================")
    print("ALL 5 DASHBOARD SECTIONS, APIS & AGENT INTEGRATIONS PASSED 100%!")
    print("========================================================")

if __name__ == "__main__":
    init_db()
    test_router_endpoints()
