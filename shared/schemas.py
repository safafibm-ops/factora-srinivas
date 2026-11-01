"""
Factora - Shared Pydantic v2 Contracts & Schemas
Problem 1: Safety Tech — FAKE OR REAL
Locked Team Contract across Agent 1 (Analyzer), Agent 2 (Correlator), Member 3 (Community Hub), and Member 4 (Frontend).
"""

from typing import List, Dict, Optional, Literal
from pydantic import BaseModel, Field


# ==========================================
# 1. Indicator & Student Scam Flags
# ==========================================

class StudentScamFlags(BaseModel):
    """Flags specific to academic, scholarship, and campus recruitment fraud."""
    upfront_fee: bool = Field(
        default=False,
        description="Demands registration fee, security deposit, laptop bond, or training charge."
    )
    zero_interview: bool = Field(
        default=False,
        description="Direct selection letter without genuine assessment or technical interview."
    )
    ugc_fake_uni: bool = Field(
        default=False,
        description="Matches UGC (University Grants Commission) official fake university list."
    )
    aicte_unverified: bool = Field(
        default=False,
        description="Claims AICTE accreditation but is absent or flagged on official portals."
    )
    task_scam: bool = Field(
        default=False,
        description="Telegram/WhatsApp task fraud (e.g. YouTube like/subscribe, hotel reviews)."
    )
    mule_account_request: bool = Field(
        default=False,
        description="Asks student to receive funds in personal bank/UPI and transfer onward."
    )


class ThreatIndicators(BaseModel):
    """Atomic indicators extracted from incoming messages, links, repos, or documents."""
    urls: List[str] = Field(default_factory=list, description="Original URLs found in target payload")
    unrolled_final_urls: List[str] = Field(default_factory=list, description="Followed redirect destinations")
    domains: List[str] = Field(default_factory=list, description="Extracted fully-qualified domain names")
    domain_age_days: Optional[int] = Field(default=None, description="WHOIS registration age in days")
    uses_free_form_or_host: bool = Field(
        default=False, 
        description="Uses Google Forms, Microsoft Forms, Tally.so, Notion, or free hosting for official intake"
    )
    emails: List[str] = Field(default_factory=list, description="Extracted email addresses (check free mailers vs corporate)")
    phones_or_upi: List[str] = Field(default_factory=list, description="Extracted mobile numbers, WhatsApp lines, or UPI IDs")
    claimed_organization: Optional[str] = Field(default=None, description="Name of company, PSU, or college being impersonated")
    official_domain_mismatch: bool = Field(
        default=False, 
        description="Claimed brand does not match sender domain (e.g. Google HR sending from gmail.com or lookalike domain)"
    )
    github_repos: List[str] = Field(default_factory=list, description="Target or referenced GitHub repositories")
    suspicious_packages: List[str] = Field(
        default_factory=list, 
        description="npm/pip packages exhibiting typosquatting, hidden postinstall hooks, or malicious scripts"
    )
    student_scam_flags: StudentScamFlags = Field(
        default_factory=StudentScamFlags, 
        description="Fine-grained student-targeted scam indicators"
    )


# ==========================================
# 2. Agent 1: Threat Intelligence & Verification Checklist
# ==========================================

class VerificationStep(BaseModel):
    """Actionable step user MUST verify before clicking, paying, or installing anything."""
    step_title: str = Field(..., description="Short summary of verification action")
    why_it_matters: str = Field(..., description="Explanation of why this prevents compromise")
    action_url_or_instruction: str = Field(..., description="Direct link or step-by-step instruction")
    is_mandatory: bool = Field(default=True, description="Whether this is critical to avoid immediate loss")


class ThreatIntelligenceRecord(BaseModel):
    """Output contract for Agent 1 (Cyber Threat Detection Agent — Analyzer)."""
    incident_id: str = Field(..., description="Unique hash or UUID for this incident")
    input_type: str = Field(
        ..., 
        description="Type of ingested input: 'email', 'url', 'sms', 'screenshot_ocr', 'github_repo', 'document_pdf'"
    )
    extracted_indicators: ThreatIndicators = Field(..., description="Parsed indicators from the input")
    prime_criteria_scores: Dict[str, float] = Field(
        ..., 
        description="P.R.I.M.E. 6-criteria score normalized 0.0 to 10.0 (Proof, Redirection, Incentive, Money, Execution, Student Registry)"
    )
    fuzzy_risk_score: float = Field(
        ..., 
        ge=0.0, 
        le=100.0, 
        description="Aggregate fuzzy risk index from 0 (harmless) to 100 (lethal threat)"
    )
    risk_tier: Literal["Verified Safe", "Low Risk", "Caution", "High Risk", "Critical Scam"] = Field(
        ..., 
        description="Human-readable decision tier"
    )
    why_it_is_risky_summary: List[str] = Field(
        default_factory=list, 
        description="Key bullet points outlining red flags found"
    )
    verify_before_proceeding_checklist: List[VerificationStep] = Field(
        default_factory=list, 
        description="Mandatory interactive checklist displayed to the student before taking action"
    )


# ==========================================
# 3. Agent 2: Threat Correlation & Graph Relationships
# ==========================================

class GraphNode(BaseModel):
    """Node in the threat intelligence correlation network."""
    id: str = Field(..., description="Unique node identifier (e.g., domain:fake-tcs.com, upi:scammer@ybl)")
    label: str = Field(..., description="Display label for the graph visualization")
    node_type: str = Field(
        ..., 
        description="Category: 'incident', 'domain', 'phone_upi', 'github_repo', 'campaign', 'organization'"
    )


class GraphEdge(BaseModel):
    """Edge representing relationship between two threat entities."""
    source: str = Field(..., description="Source node id")
    target: str = Field(..., description="Target node id")
    relationship: str = Field(..., description="Predicate: 'shares_upi', 'resolves_to', 'part_of_campaign', 'impersonates'")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in connection")


class RelatedIncidentMatch(BaseModel):
    """Match details with a previously submitted or known threat incident."""
    matched_incident_id: str = Field(..., description="ID of previously indexed incident")
    shared_indicators: List[str] = Field(..., description="List of common indicators (e.g. same UPI, same registrant, same payload)")
    connection_explanation: str = Field(..., description="Plain-text explanation of how this campaign relates")
    relationship_confidence: float = Field(..., ge=0.0, le=1.0, description="Statistical confidence score")


class ThreatRelationshipRecord(BaseModel):
    """Output contract for Agent 2 (Cyber Threat Intelligence Correlation Agent — Correlator)."""
    source_incident_id: str = Field(..., description="ID of the current incident being correlated")
    detected_campaign_name: Optional[str] = Field(None, description="Identified syndicate or campaign name if known")
    is_recurring_campaign: bool = Field(default=False, description="Flag indicating repeated malicious patterns")
    related_incidents: List[RelatedIncidentMatch] = Field(default_factory=list, description="Correlated past incidents")
    graph_nodes: List[GraphNode] = Field(default_factory=list, description="Nodes for visual graph rendering")
    graph_edges: List[GraphEdge] = Field(default_factory=list, description="Edges for visual graph rendering")
    recommended_community_warnings: List[str] = Field(default_factory=list, description="Campus-wide or group alert suggestions")


# ==========================================
# 4. Member 3: Community Victim Network & Go-To Reporting Portals
# ==========================================

class ExternalPortalReport(BaseModel):
    """Represents data from external scam intelligence aggregators and official law enforcement reporting portals."""
    portal_name: str = Field(..., description="Portal name: CyberCrime.gov.in, ScamAdviser, PhishTank, Reddit r/Scams, CERT-In")
    portal_url: str = Field(..., description="Base or lookup link on that portal")
    external_report_summary: str = Field(..., description="Aggregated community reports or domain reputation verdict")
    direct_report_submission_url: str = Field(
        ..., 
        description="Go-to direct URL where a user can officially file a complaint or report the scam"
    )


class CommunityThreatLookupResponse(BaseModel):
    """Output contract for Member 3 (Community Victim Network & External Go-To Reporting Websites Hub)."""
    internal_victim_reports_count: int = Field(default=0, description="Count of confirmed student victim reports in Factora DB")
    total_reported_money_lost_inr: float = Field(default=0.0, description="Sum of monetary loss reported by victims in INR")
    victim_evidence_summaries: List[str] = Field(
        default_factory=list, 
        description="Anonymized statements and proof summaries submitted by students"
    )
    external_portal_matches: List[ExternalPortalReport] = Field(
        default_factory=list, 
        description="Threat data aggregated from external scam repositories + official reporting routes"
    )


# ==========================================
# 5. API Ingestion & Request Schemas
# ==========================================

class IncidentAnalyzeRequest(BaseModel):
    """Input payload to Agent 1 analyzer."""
    input_text: Optional[str] = Field(None, description="Raw email text, SMS message, WhatsApp copy, or job description")
    target_url: Optional[str] = Field(None, description="URL or internship link to inspect")
    screenshot_base64: Optional[str] = Field(None, description="Base64 encoded image/screenshot of offer letter or chat")
    github_repo_url: Optional[str] = Field(None, description="GitHub repository submitted for coding assessment or assignment")


class IncidentCorrelateRequest(BaseModel):
    """Input payload to Agent 2 correlator."""
    incident_id: str
    extracted_indicators: Optional[ThreatIndicators] = None


class CommunityLookupRequest(BaseModel):
    """Query payload for Member 3 community hub."""
    domain: Optional[str] = None
    upi_or_phone: Optional[str] = None
    email: Optional[str] = None
    claimed_organization: Optional[str] = None


class VictimReportSubmission(BaseModel):
    """Payload when a user or placement cell reports a scam directly."""
    incident_title: str
    claimed_organization: Optional[str] = ""
    scam_type: str = "recruitment_fraud"
    amount_demanded_or_lost_inr: float = 0.0
    financial_loss_occurred: bool = False
    scammer_contacts: List[str] = Field(default_factory=list)
    scammer_links: List[str] = Field(default_factory=list)
    suspicious_url_or_domain: Optional[str] = None
    github_repo_link: Optional[str] = None
    user_pseudonym: Optional[str] = None
    official_complaint_filed: bool = False
    complaint_ack_ref: Optional[str] = None
    description: str = ""
    evidence_filenames: List[str] = Field(default_factory=list)
    evidence_file_ids: List[str] = Field(default_factory=list)


class IncidentSubmissionResponse(BaseModel):
    """Standard response model after a victim report is submitted."""
    status: str = "success"
    incident_id: str
    database_id: Optional[int] = None
    user_pseudonym: Optional[str] = None
    verification_status: str = "SUBMITTED"
    message: Optional[str] = None
    complaint_draft_fir: Optional[str] = None
    emergency_freeze_checklist: Optional[List[str]] = Field(default_factory=list)


# ==========================================
# 6. Mock Data Helper Function
# ==========================================

def get_mock_data() -> Dict[str, BaseModel]:
    """
    Returns populated, realistic mock instances for every contract so no frontend
    or backend teammate is blocked while real services are being developed.
    """
    mock_indicators = ThreatIndicators(
        urls=["https://bit.ly/tcs-national-campus-internship", "https://tcs-careers-portal.in/register"],
        unrolled_final_urls=["https://tcs-careers-portal.in/register?ref=wa_bulk"],
        domains=["bit.ly", "tcs-careers-portal.in"],
        domain_age_days=12,
        uses_free_form_or_host=False,
        emails=["hr-onboarding@tcs-careers-portal.in", "tcsrecruitmentindia@gmail.com"],
        phones_or_upi=["+919876543210", "tcs.hrverification@oksbi"],
        claimed_organization="Tata Consultancy Services (TCS)",
        official_domain_mismatch=True,
        github_repos=["https://github.com/tcs-assessment-portal/coding-round-2026"],
        suspicious_packages=["cross-env-stealer", "node-fetch-override"],
        student_scam_flags=StudentScamFlags(
            upfront_fee=True,
            zero_interview=True,
            ugc_fake_uni=False,
            aicte_unverified=False,
            task_scam=False,
            mule_account_request=False
        )
    )

    mock_checklist = [
        VerificationStep(
            step_title="Cross-check TCS Official Careers Portal",
            why_it_matters="Legitimate enterprises never use domain variations like '-portal.in' or free Gmail addresses for recruiting.",
            action_url_or_instruction="Visit https://www.tcs.com/careers and use the NextStep Candidate Verification Tool.",
            is_mandatory=True
        ),
        VerificationStep(
            step_title="Validate Never-Pay Policy",
            why_it_matters="TCS and all NASSCOM-member companies have strict policies never to demand money for laptops, training, or onboarding.",
            action_url_or_instruction="Do NOT transfer money to 'tcs.hrverification@oksbi'. File an internal campus fraud alert.",
            is_mandatory=True
        ),
        VerificationStep(
            step_title="Verify GitHub Repo Tasks & Hooks",
            why_it_matters="The candidate assessment repository contains automatic 'postinstall' execution scripts designed to harvest browser cookies.",
            action_url_or_instruction="Do not run 'npm install' or open in VS Code with workspace trust enabled. Review package.json manually.",
            is_mandatory=True
        ),
        VerificationStep(
            step_title="Inspect AICTE/Campus Placement Cell Whitelist",
            why_it_matters="Any legitimate on-campus recruitment drive must be vetted by the college Training & Placement Officer (TPO).",
            action_url_or_instruction="Confirm with your campus TPO noticeboard before replying to WhatsApp offers.",
            is_mandatory=False
        )
    ]

    mock_threat_intel = ThreatIntelligenceRecord(
        incident_id="INC-2026-TCS-9021",
        input_type="email",
        extracted_indicators=mock_indicators,
        prime_criteria_scores={
            "proof_domain_identity": 9.5,
            "redirection_obfuscation": 8.0,
            "incentive_urgency": 9.0,
            "money_transaction_ask": 9.8,
            "execution_code_safety": 8.5,
            "student_registry_check": 7.0
        },
        fuzzy_risk_score=94.5,
        risk_tier="Critical Scam",
        why_it_is_risky_summary=[
            "High-confidence domain spoofing: 'tcs-careers-portal.in' registered only 12 days ago (official is tcs.com).",
            "Direct demand of ₹3,500 'Mandatory Security Deposit for Laptop Dispatch' via UPI ID 'tcs.hrverification@oksbi'.",
            "Direct offer letter issued with zero technical interview or coding assessment.",
            "Malicious 'package.json' hooks identified in companion GitHub test repository."
        ],
        verify_before_proceeding_checklist=mock_checklist
    )

    mock_nodes = [
        GraphNode(id="INC-2026-TCS-9021", label="Current Offer (TCS Spoof)", node_type="incident"),
        GraphNode(id="dom:tcs-careers-portal.in", label="tcs-careers-portal.in", node_type="domain"),
        GraphNode(id="upi:tcs.hrverification@oksbi", label="tcs.hrverification@oksbi", node_type="phone_upi"),
        GraphNode(id="camp:GhostRecruiter-Karnataka-Ring", label="Campaign: GhostRecruiter Ring", node_type="campaign"),
        GraphNode(id="INC-2026-INFY-4102", label="Past Incident: Infy Bond Scam", node_type="incident"),
        GraphNode(id="repo:tcs-assessment-portal", label="GitHub: tcs-assessment-portal", node_type="github_repo")
    ]

    mock_edges = [
        GraphEdge(source="INC-2026-TCS-9021", target="dom:tcs-careers-portal.in", relationship="uses_domain", confidence=1.0),
        GraphEdge(source="INC-2026-TCS-9021", target="upi:tcs.hrverification@oksbi", relationship="demands_payment_to", confidence=1.0),
        GraphEdge(source="dom:tcs-careers-portal.in", target="camp:GhostRecruiter-Karnataka-Ring", relationship="attributed_to", confidence=0.89),
        GraphEdge(source="upi:tcs.hrverification@oksbi", target="INC-2026-INFY-4102", relationship="shared_payout_receiver", confidence=0.96),
        GraphEdge(source="INC-2026-TCS-9021", target="repo:tcs-assessment-portal", relationship="distributes_malware_via", confidence=0.92)
    ]

    mock_related = [
        RelatedIncidentMatch(
            matched_incident_id="INC-2026-INFY-4102",
            shared_indicators=["tcs.hrverification@oksbi", "bit.ly/tcs-national-campus-internship"],
            connection_explanation="Identical SBI UPI receiver was used in 14 previous fake Infosys placement offers across 3 Karnataka engineering colleges.",
            relationship_confidence=0.96
        ),
        RelatedIncidentMatch(
            matched_incident_id="INC-2025-WIPRO-1108",
            shared_indicators=["+919876543210"],
            connection_explanation="Matching WhatsApp business phone number operated by same fake recruiter syndicate.",
            relationship_confidence=0.88
        )
    ]

    mock_correlator = ThreatRelationshipRecord(
        source_incident_id="INC-2026-TCS-9021",
        detected_campaign_name="GhostRecruiter Syndicate #4",
        is_recurring_campaign=True,
        related_incidents=mock_related,
        graph_nodes=mock_nodes,
        graph_edges=mock_edges,
        recommended_community_warnings=[
            "Broadcast high-priority alert to Campus Placement Group: Fake TCS recruitment emails soliciting ₹3,500 UPI deposits.",
            "Block incoming emails from '@tcs-careers-portal.in' at campus mail gateway.",
            "Flag UPI ID 'tcs.hrverification@oksbi' with NPCI / CyberCrime cell."
        ]
    )

    mock_external_portals = [
        ExternalPortalReport(
            portal_name="National Cyber Crime Reporting Portal (Govt of India)",
            portal_url="https://cybercrime.gov.in",
            external_report_summary="Official portal under Ministry of Home Affairs for lodging financial & job fraud complaints.",
            direct_report_submission_url="https://cybercrime.gov.in/Webform/Accept.aspx"
        ),
        ExternalPortalReport(
            portal_name="ScamAdviser",
            portal_url="https://www.scamadviser.com",
            external_report_summary="Trustscore: 1/100 (Extremely High Risk). Domain registered 12 days ago via privacy proxy.",
            direct_report_submission_url="https://www.scamadviser.com/check-website/tcs-careers-portal.in"
        ),
        ExternalPortalReport(
            portal_name="CERT-In (Indian Computer Emergency Response Team)",
            portal_url="https://www.cert-in.org.in",
            external_report_summary="Active phishing advisory regarding fake campus placement and task-based fraud.",
            direct_report_submission_url="https://www.cert-in.org.in/incident.jsp"
        ),
        ExternalPortalReport(
            portal_name="Reddit r/Scams India Community",
            portal_url="https://www.reddit.com/r/Scams/",
            external_report_summary="18 community threads reporting WhatsApp offers asking for ₹2,000–₹5,000 security deposits for IT jobs.",
            direct_report_submission_url="https://www.reddit.com/r/Scams/submit"
        )
    ]

    mock_community_hub = CommunityThreatLookupResponse(
        internal_victim_reports_count=14,
        total_reported_money_lost_inr=49000.0,
        victim_evidence_summaries=[
            "Student from Srinivas Inst transferred ₹3,500 for laptop security deposit; number blocked immediately after payment.",
            "Offer letter received on Telegram with TCS letterhead, signed by fake HR director.",
            "WhatsApp caller promised direct joining letter if UPI transfer completed within 30 minutes."
        ],
        external_portal_matches=mock_external_portals
    )

    return {
        "indicators": mock_indicators,
        "threat_intelligence": mock_threat_intel,
        "threat_relationship": mock_correlator,
        "community_hub": mock_community_hub
    }
