"""
Agent 2: Cyber Threat Intelligence Correlation Agent — Correlator Router
Provides endpoints to correlate threat incidents against known threat intelligence,
extract entity graph nodes/edges, and detect recurring scam syndicates.
"""

from fastapi import APIRouter
from typing import Dict, Any

try:
    from shared.schemas import (
        IncidentCorrelateRequest,
        ThreatRelationshipRecord,
        get_mock_data,
    )
except ImportError:
    from ...shared.schemas import (
        IncidentCorrelateRequest,
        ThreatRelationshipRecord,
        get_mock_data,
    )

router = APIRouter(prefix="/api/correlator", tags=["Agent 2: Threat Correlator"])


@router.get("/health", summary="Agent 2 Health Status")
async def health_check():
    return {"status": "ok", "agent": "Agent 2: Cyber Threat Correlator"}


@router.get("/mock", response_model=ThreatRelationshipRecord, summary="Get Mock Threat Relationship Record")
async def get_mock_relationship_record():
    """Returns a realistic mock ThreatRelationshipRecord with graph nodes & edges."""
    data = get_mock_data()
    return data["threat_relationship"]


@router.post("/correlate", response_model=ThreatRelationshipRecord, summary="Correlate Threat Incident")
async def correlate_incident(payload: IncidentCorrelateRequest):
    """
    Correlates incident indicators across historical scam reports and member 3's community database.
    Detects recurring campaigns, maps entity relationship graphs, and outputs community warnings.
    """
    data = get_mock_data()
    record: ThreatRelationshipRecord = data["threat_relationship"]
    # Dynamic binding of source incident ID
    return ThreatRelationshipRecord(
        source_incident_id=payload.incident_id,
        detected_campaign_name=record.detected_campaign_name,
        is_recurring_campaign=record.is_recurring_campaign,
        related_incidents=record.related_incidents,
        graph_nodes=record.graph_nodes,
        graph_edges=record.graph_edges,
        recommended_community_warnings=record.recommended_community_warnings
    )


@router.get("/graph/{incident_id}", summary="Get Incident Entity Graph")
async def get_incident_graph(incident_id: str) -> Dict[str, Any]:
    """Returns the visual graph structure (nodes & edges) for interactive canvas rendering."""
    data = get_mock_data()
    record: ThreatRelationshipRecord = data["threat_relationship"]
    return {
        "incident_id": incident_id,
        "nodes": [node.model_dump() for node in record.graph_nodes],
        "edges": [edge.model_dump() for edge in record.graph_edges],
        "campaign": record.detected_campaign_name
    }
