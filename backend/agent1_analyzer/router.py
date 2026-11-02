"""
Agent 1: Cyber Threat Detection Agent — Analyzer Router
Provides endpoints to analyze incoming texts, URLs, OCR images, and repositories,
returning validated ThreatIntelligenceRecord objects with P.R.I.M.E. scoring
and the mandatory pre-action verification checklist.
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict
import uuid

from shared.schemas import (
    IncidentAnalyzeRequest,
    ThreatIntelligenceRecord,
    VerificationStep,
    ThreatIndicators,
    StudentScamFlags,
    get_mock_data,
)

from backend.agent1_analyzer.prime_scorer import PrimeNeuroSymbolicScorer

router = APIRouter(prefix="/api/analyzer", tags=["Agent 1: Threat Analyzer"])

# Singleton scorer instance combining ML, OSINT, OCR, and Student Registries
scorer = PrimeNeuroSymbolicScorer()

# In-memory store for generated checklists so students can query /checklist/{id}
INCIDENT_CACHE: Dict[str, ThreatIntelligenceRecord] = {}


@router.get("/health", summary="Agent 1 Health Status")
async def health_check():
    model_loaded = scorer.ml_detector is not None
    return {
        "status": "ok" if model_loaded else "degraded",
        "agent": "Agent 1: Cyber Threat Detection Analyzer",
        "ml_model_loaded": model_loaded,
        "ml_model_error": scorer.ml_model_error,
        "ugc_registry_active": True,
        "github_scanner_active": True
    }


@router.get("/mock", response_model=ThreatIntelligenceRecord, summary="Get Mock Threat Intelligence Record")
async def get_mock_threat_record():
    """Returns a realistic mock ThreatIntelligenceRecord for immediate frontend testing."""
    data = get_mock_data()
    return data["threat_intelligence"]


@router.post("/analyze", response_model=ThreatIntelligenceRecord, summary="Analyze Threat Payload")
async def analyze_threat(payload: IncidentAnalyzeRequest):
    """
    Ingests email text, WhatsApp/SMS copy, URL, OCR screenshot, or GitHub repo URL.
    Computes P.R.I.M.E. 6-criteria scores, fuzzy risk assessment, student scam flags,
    and returns an actionable verification checklist.
    """
    record = scorer.analyze_payload(payload)
    INCIDENT_CACHE[record.incident_id] = record
    return record


@router.get("/checklist/{incident_id}", response_model=List[VerificationStep], summary="Get Verification Checklist for Incident")
async def get_verification_checklist(incident_id: str):
    """Returns the mandatory pre-action checklist for a specific incident."""
    if incident_id in INCIDENT_CACHE:
        return INCIDENT_CACHE[incident_id].verify_before_proceeding_checklist
    # Fallback to default mock checklist
    data = get_mock_data()
    return data["threat_intelligence"].verify_before_proceeding_checklist
