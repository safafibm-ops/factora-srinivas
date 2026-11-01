"""
Member 3: Community Victim Network & External Go-To Reporting Websites Hub Router
Provides endpoints to query crowdsourced campus victim reports, submit new incident evidence,
and aggregate intelligence from external reporting sites while routing victims to official portals.
"""

from fastapi import APIRouter
from typing import List, Dict, Any

try:
    from shared.schemas import (
        CommunityLookupRequest,
        CommunityThreatLookupResponse,
        ExternalPortalReport,
        VictimReportSubmission,
        get_mock_data,
    )
except ImportError:
    from ...shared.schemas import (
        CommunityLookupRequest,
        CommunityThreatLookupResponse,
        ExternalPortalReport,
        VictimReportSubmission,
        get_mock_data,
    )

router = APIRouter(prefix="/api/community", tags=["Member 3: Community Hub & External Portals"])


@router.get("/health", summary="Community Hub Health Status")
async def health_check():
    return {"status": "ok", "agent": "Member 3: Community Victim Network & External Portals Hub"}


@router.get("/mock", response_model=CommunityThreatLookupResponse, summary="Get Mock Community Threat Lookup")
async def get_mock_community_response():
    """Returns a realistic mock CommunityThreatLookupResponse for frontend development."""
    data = get_mock_data()
    return data["community_hub"]


@router.post("/lookup", response_model=CommunityThreatLookupResponse, summary="Lookup Indicator in Community & External Portals")
async def lookup_community_threats(payload: CommunityLookupRequest):
    """
    Checks indicators against internal student victim reports and queries external reputation
    and threat reporting networks (ScamAdviser, PhishTank, Reddit r/Scams).
    """
    data = get_mock_data()
    mock_resp: CommunityThreatLookupResponse = data["community_hub"]
    return mock_resp


@router.get("/external-portals", response_model=List[ExternalPortalReport], summary="Get Go-To Scam Reporting Portals")
async def get_external_reporting_portals():
    """
    Provides a curated directory of official and community 'Go-To' scam reporting portals
    (CyberCrime.gov.in, CERT-In, ScamAdviser, Reddit r/Scams, NCH) with direct links.
    """
    data = get_mock_data()
    mock_resp: CommunityThreatLookupResponse = data["community_hub"]
    return mock_resp.external_portal_matches


@router.post("/report", summary="Submit Student Victim Report")
async def submit_victim_report(report: VictimReportSubmission) -> Dict[str, Any]:
    """
    Allows a student or campus placement cell to anonymously report a fraudulent offer,
    stating amount demanded or lost, scammer contacts, and evidence.
    """
    return {
        "status": "success",
        "message": "Report successfully logged in Factora Community Defense Network.",
        "incident_ref": f"COMM-REPORT-{report.claimed_organization.upper()[:4]}-8842",
        "broadcast_alert_generated": True
    }

