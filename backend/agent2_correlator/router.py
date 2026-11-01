"""
Agent 2: Cyber Threat Intelligence Correlation Agent — Correlator Router
Provides endpoints to correlate threat incidents against known threat intelligence,
extract entity graph nodes/edges, and detect recurring scam syndicates using
our trained Random Forest ML model, NetworkX graph clustering, and LLM reasoning agent.
"""

import sys
from pathlib import Path
from typing import Dict, Any, Optional

# Ensure repository root is on sys.path for robust cross-module imports
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi import APIRouter
from shared.schemas import (
    IncidentCorrelateRequest,
    ThreatRelationshipRecord,
    ThreatIndicators,
    get_mock_data,
)
from backend.agent2_correlator.ai_correlator import ThreatCorrelationEngine
from backend.agent2_correlator.explainer_agent import LLMExplainerAgent

router = APIRouter(prefix="/api/correlator", tags=["Agent 2: Threat Correlator"])

# In-memory singletons and cache for high-performance inference
_engine: Optional[ThreatCorrelationEngine] = None
_explainer: Optional[LLMExplainerAgent] = None
_correlation_cache: Dict[str, ThreatRelationshipRecord] = {}


def get_engine() -> ThreatCorrelationEngine:
    """Lazy loader for ThreatCorrelationEngine singleton."""
    global _engine
    if _engine is None:
        _engine = ThreatCorrelationEngine()
    return _engine


def get_explainer() -> LLMExplainerAgent:
    """Lazy loader for LLMExplainerAgent singleton."""
    global _explainer
    if _explainer is None:
        _explainer = LLMExplainerAgent()
    return _explainer


@router.get("/health", summary="Agent 2 Health & AI Model Status")
def health_check():
    """Returns AI model readiness and total indexed threat incidents."""
    try:
        engine = get_engine()
        model_loaded = engine.model is not None
        return {
            "status": "ok" if model_loaded else "degraded",
            "agent": "Agent 2: Cyber Threat Correlator",
            "ml_model_loaded": model_loaded,
            "ml_model_error": None if model_loaded else "The correlation model did not load.",
            "indexed_historical_incidents": len(engine.historical_incidents),
            "feature_count": len(engine.feature_names)
        }
    except Exception as exc:
        return {
            "status": "degraded",
            "agent": "Agent 2: Cyber Threat Correlator",
            "ml_model_loaded": False,
            "ml_model_error": str(exc),
            "indexed_historical_incidents": 0,
            "feature_count": 0
        }


@router.get("/mock", response_model=ThreatRelationshipRecord, summary="Get Mock Threat Relationship Record")
def get_mock_relationship_record():
    """Returns a realistic mock ThreatRelationshipRecord with graph nodes & edges."""
    data = get_mock_data()
    return data["threat_relationship"]


@router.post("/correlate", response_model=ThreatRelationshipRecord, summary="Correlate Threat Incident with AI")
def correlate_incident(payload: IncidentCorrelateRequest):
    """
    Executes live Machine Learning pairwise correlation, NetworkX graph clustering,
    and LLM explainability over incoming incident indicators and Member 3's Community DB.
    """
    engine = get_engine()
    explainer = get_explainer()

    # Determine indicators to inspect
    if payload.extracted_indicators is not None:
        indicators: ThreatIndicators = payload.extracted_indicators
    else:
        # Fallback to realistic mock indicators if none provided
        data = get_mock_data()
        indicators = data["indicators"]

    # 1. Machine Learning Pairwise Inference & Graph Analytics
    base_record = engine.correlate(
        source_incident_id=payload.incident_id,
        indicators=indicators
    )

    # 2. Explain only evidence available in this correlation request. The mock
    # endpoint remains available for UI previews; don't attach mock victim data
    # to a live incident.
    enriched_record = explainer.explain_and_enrich(
        base_record=base_record,
        indicators=indicators
    )

    # Cache for graph canvas visualization
    _correlation_cache[payload.incident_id] = enriched_record

    return enriched_record


@router.get("/graph/{incident_id}", summary="Get Incident Entity Graph")
def get_incident_graph(incident_id: str) -> Dict[str, Any]:
    """Returns the visual graph structure (nodes & edges) for interactive canvas rendering."""
    # Check cache first
    if incident_id in _correlation_cache:
        record = _correlation_cache[incident_id]
    else:
        # Generate on the fly using default indicators
        engine = get_engine()
        explainer = get_explainer()
        mock_data = get_mock_data()
        base_record = engine.correlate(
            source_incident_id=incident_id,
            indicators=mock_data["indicators"]
        )
        record = explainer.explain_and_enrich(
            base_record=base_record,
            indicators=mock_data["indicators"]
        )
        _correlation_cache[incident_id] = record

    return {
        "incident_id": incident_id,
        "nodes": [node.model_dump() for node in record.graph_nodes],
        "edges": [edge.model_dump() for edge in record.graph_edges],
        "campaign": record.detected_campaign_name,
        "is_recurring": record.is_recurring_campaign,
        "total_nodes": len(record.graph_nodes),
        "total_edges": len(record.graph_edges)
    }
