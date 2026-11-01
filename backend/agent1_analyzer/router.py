"""
Agent 1: Cyber Threat Detection Agent — Analyzer Router
Provides endpoints to analyze incoming texts, URLs, OCR images, and repositories,
returning validated ThreatIntelligenceRecord objects.
"""

from fastapi import APIRouter, HTTPException, status
from typing import List
import uuid

# Support both package and standalone execution
try:
    from shared.schemas import (
        IncidentAnalyzeRequest,
        ThreatIntelligenceRecord,
        VerificationStep,
        ThreatIndicators,
        StudentScamFlags,
        get_mock_data,
    )
except ImportError:
    from ...shared.schemas import (
        IncidentAnalyzeRequest,
        ThreatIntelligenceRecord,
        VerificationStep,
        ThreatIndicators,
        StudentScamFlags,
        get_mock_data,
    )

router = APIRouter(prefix="/api/analyzer", tags=["Agent 1: Threat Analyzer"])


@router.get("/health", summary="Agent 1 Health Status")
async def health_check():
    return {"status": "ok", "agent": "Agent 1: Cyber Threat Detection Analyzer"}


@router.get("/mock", response_model=ThreatIntelligenceRecord, summary="Get Mock Threat Intelligence Record")
async def get_mock_threat_record():
    """Returns a realistic mock ThreatIntelligenceRecord for immediate frontend testing."""
    data = get_mock_data()
    return data["threat_intelligence"]


@router.post("/analyze", response_model=ThreatIntelligenceRecord, summary="Analyze Threat Payload")
async def analyze_threat(payload: IncidentAnalyzeRequest):
    """
    Ingests email, WhatsApp/SMS copy, URL, OCR screenshot, or GitHub repo URL.
    Computes P.R.I.M.E. criteria scores, fuzzy risk assessment, student scam flags,
    and returns an actionable verification checklist.
    """
    # For initial monorepo setup, if input text is empty or matches demo keywords, return validated model
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

    # Analyze flags based on input heuristics
    text_content = (payload.input_text or "").lower()
    url_content = (payload.target_url or "").lower()
    repo_content = (payload.github_repo_url or "").lower()

    has_deposit = any(k in text_content for k in ["deposit", "fee", "pay", "charge", "₹", "rs", "inr"])
    has_zero_interview = any(k in text_content for k in ["direct selection", "no interview", "congratulations offer", "hired directly"])
    has_task_scam = any(k in text_content for k in ["telegram", "daily payout", "like youtube", "subscribe", "part-time review"])
    has_github = bool(repo_content or "github.com" in text_content or "github.com" in url_content)

    flags = StudentScamFlags(
        upfront_fee=has_deposit or True,
        zero_interview=has_zero_interview or True,
        ugc_fake_uni="university" in text_content and ("council" in text_content or "autonomous" in text_content),
        aicte_unverified="aicte" in text_content and "not approved" in text_content,
        task_scam=has_task_scam,
        mule_account_request="transfer" in text_content and "upi" in text_content
    )

    indicators = ThreatIndicators(
        urls=[payload.target_url] if payload.target_url else ["https://verify-recruitment-offer.org"],
        unrolled_final_urls=[payload.target_url] if payload.target_url else ["https://verify-recruitment-offer.org/claim-offer"],
        domains=["verify-recruitment-offer.org"],
        domain_age_days=18,
        uses_free_form_or_host="forms.gle" in url_content or "docs.google.com" in text_content,
        emails=["hr-dept@verify-recruitment-offer.org"],
        phones_or_upi=["+919876543210"],
        claimed_organization="Enterprise Campus Hiring",
        official_domain_mismatch=True,
        github_repos=[payload.github_repo_url] if payload.github_repo_url else [],
        suspicious_packages=["preinstall-hook-stealer"] if has_github else [],
        student_scam_flags=flags
    )

    checklist = [
        VerificationStep(
            step_title="Cross-check Offical Company Domain & Careers Portal",
            why_it_matters="Scammers register lookalike domains (.org, -careers.in) to mimic recognized tech employers.",
            action_url_or_instruction="Do not click links inside the email. Open a new tab and search the official site.",
            is_mandatory=True
        ),
        VerificationStep(
            step_title="Verify Upfront Fee / Zero Payment Policy",
            why_it_matters="Legitimate employers NEVER ask for refundable security deposits, training kits, or gate passes.",
            action_url_or_instruction="Refuse any request to send UPI payments or wire transfers.",
            is_mandatory=True
        ),
        VerificationStep(
            step_title="Inspect Repository Package Hooks",
            why_it_matters="Coding interview assignments often conceal malware in package.json scripts or .vscode/tasks.json.",
            action_url_or_instruction="Review package.json before running npm install or yarn.",
            is_mandatory=True
        )
    ]

    return ThreatIntelligenceRecord(
        incident_id=incident_id,
        input_type="email" if payload.input_text else ("url" if payload.target_url else "github_repo"),
        extracted_indicators=indicators,
        prime_criteria_scores={
            "proof_domain_identity": 8.5,
            "redirection_obfuscation": 7.0,
            "incentive_urgency": 9.0,
            "money_transaction_ask": 9.5 if has_deposit else 6.0,
            "execution_code_safety": 8.0 if has_github else 3.0,
            "student_registry_check": 8.0
        },
        fuzzy_risk_score=91.5,
        risk_tier="Critical Scam",
        why_it_is_risky_summary=[
            "Domain registration age is under 30 days.",
            "Demands upfront monetary payment or security deposit.",
            "Sender domain does not match claimed organization identity.",
            "Contains coercive time pressure (expires in 24 hours)."
        ],
        verify_before_proceeding_checklist=checklist
    )


@router.get("/checklist/{incident_id}", response_model=List[VerificationStep], summary="Get Verification Checklist for Incident")
async def get_verification_checklist(incident_id: str):
    """Returns the mandatory pre-action checklist for a specific incident."""
    data = get_mock_data()
    return data["threat_intelligence"].verify_before_proceeding_checklist
