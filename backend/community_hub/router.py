"""



Member 3: Community Victim Network & External Go-To Reporting Websites Hub Router



Provides endpoints to query crowdsourced campus victim reports, submit new incident evidence,



aggregate intelligence from external reporting sites, generate copy-ready FIR complaints,



serve the live Community Dashboard UI, and expose structured threat records for Agent 2 correlation.



"""



from fastapi import APIRouter, Query, HTTPException, UploadFile, File, Header



from fastapi.responses import HTMLResponse, FileResponse



from typing import List, Dict, Any, Optional



from pydantic import BaseModel, Field



try:



    from shared.schemas import (



        CommunityLookupRequest,



        CommunityThreatLookupResponse,



        ExternalPortalReport,



        VictimReportSubmission,



        IncidentSubmissionResponse,



        get_mock_data,



    )



except ImportError:



    from ...shared.schemas import (



        CommunityLookupRequest,



        CommunityThreatLookupResponse,



        ExternalPortalReport,



        VictimReportSubmission,



        IncidentSubmissionResponse,



        get_mock_data,



    )



from backend.community_hub.storage import (



    init_db,



    lookup_threat_indicators,



    add_victim_report,



    get_community_summary_stats,



    get_all_records_for_correlator,



    get_dashboard_statistics,



    get_category_overview,



    get_recent_activity,
    get_recent_community_snapshot,



    get_trending_threats,



    get_community_alerts,



    get_incident_by_ref,



    get_full_dashboard_state,



    get_user_submitted_reports,



    generate_pseudonym,



    query_community_incident_feed,



    search_threat_indicators,



    get_feed_filter_options,



)



from backend.community_hub.evidence_storage import (



    sanitize_and_store_file,



    get_evidence_file_path,



)



from backend.community_hub.external_portals import (



    generate_external_portal_reports,



    get_all_external_portals_directory,



)



from backend.community_hub.legal_aid import (



    generate_cybercrime_fir_draft,



    generate_emergency_freeze_checklist,



    generate_campus_advisory_bulletin,



)



from backend.community_hub.dashboard_ui import get_community_dashboard_html



from backend.community_hub.agent_clients import (



    get_agents_config,



    probe_agent1_status,



    probe_agent2_status,



    request_agent1_analysis,



    request_agent2_correlation,



)



router = APIRouter(prefix="/api/community", tags=["Member 3: Community Hub & External Portals"])



# Ensure database is initialized at router load time



init_db()



class GenerateFIRDraftRequest(BaseModel):



    """Payload to generate a tailored cybercrime FIR draft on-the-fly."""



    claimed_organization: str = Field(..., description="Impersonated brand or organization")



    scam_type: str = Field(default="job_recruitment_scam", description="Type of scam")



    amount_inr: float = Field(default=0.0, description="Amount demanded or lost in INR")



    scammer_contacts: List[str] = Field(default_factory=list, description="Scammer phone numbers, emails, or UPI handles")



    scammer_links: List[str] = Field(default_factory=list, description="Scammer URLs, domains, or repos")



    incident_description: str = Field(..., description="Detailed statement of events")



# =========================================================



# 1. COMMUNITY DASHBOARD INTERFACE (HTML UI)



# =========================================================



@router.get("/ui", response_class=HTMLResponse, summary="Serve Live Community Threat Dashboard Webpage")



@router.get("/dashboard-ui", response_class=HTMLResponse, summary="Serve Live Community Threat Dashboard Webpage")



def serve_community_dashboard():



    """



    Renders the responsive tactile neumorphic Community Cyber Threat Intelligence Dashboard.



    Complies with the design tokens in frontend/AGENTS.md.



    """



    return HTMLResponse(content=get_community_dashboard_html(), status_code=200)



# =========================================================



# 2. COMPLETE DASHBOARD API ENDPOINTS



# =========================================================



@router.get("/dashboard", summary="Get Full Community Dashboard Aggregated State")



def get_full_dashboard():



    """



    Returns the complete aggregated data payload for the Community Dashboard:



    - statistics (total incidents, newly reported, corroborated, threat campaigns, active alerts)



    - categories (overview across the 6 official threat categories)



    - recent_activity (filter-ready feed of reported incidents)



    - trending_threats (multi-report indicators, related incident counts, risk assessments)



    - community_alerts (priority advisories and campus warnings)



    """



    state = get_full_dashboard_state()



    return {



        "status": "success",



        "agent_services": {



            "agent1_analyzer": probe_agent1_status(),



            "agent2_correlator": probe_agent2_status()



        },



        **state



    }



@router.get("/dashboard/stats", summary="Get Live Dashboard Statistics")



def get_dashboard_stats():



    """



    Returns the 5 primary community metrics directly from the database:



    - total_submitted_incidents



    - newly_reported_incidents (past 7 days)



    - corroborated_reports



    - potential_threat_campaigns



    - active_community_alerts



    """



    return get_dashboard_statistics()



@router.get("/dashboard/categories", summary="Get Threat Category Overview")



def get_dashboard_categories():



    """



    Returns threat category overview for the 6 core categories:



    Phishing, Recruitment fraud, Financial scams, GitHub package risks,



    Website impersonation, and Account compromise.



    """



    return get_category_overview()



@router.get("/dashboard/activity", summary="Get Recent Community Activity")



def get_dashboard_activity(



    category: Optional[str] = Query("all", description="Category filter (recruitment_fraud, financial_scam, etc.)"),



    limit: int = Query(20, ge=1, le=100)



):



    """



    Returns recently submitted incidents with submission date, category, and verification status.



    Supports filtering by category.



    """



    return get_recent_activity(limit=limit, category=category)



@router.get("/dashboard/trending-threats", summary="Get Trending Threat Indicators")



def get_dashboard_trending_threats():



    """



    Returns indicators (UPI VPAs, Domains, Phone numbers, GitHub Repos) appearing across



    multiple community reports, with related incident count, loss exposure, and risk assessment.



    """



    return get_trending_threats()



@router.get("/dashboard/alerts", summary="Get Active Community Advisories")



def get_dashboard_alerts():



    """



    Returns active high-priority community alerts and protective warnings generated from



    recurring threat syndicates.



    """



    return get_community_alerts()



@router.get("/dashboard/incident/{incident_ref}", summary="Get Incident Dossier Detail")



def get_incident_detail(incident_ref: str):



    """



    Fetches full dossier for a specific incident including extracted indicators,



    victim statement, auto-generated FIR complaint draft, and 1930 freeze guide.



    """



    incident = get_incident_by_ref(incident_ref)



    if not incident:



        raise HTTPException(status_code=404, detail=f"Incident {incident_ref} not found.")



    # Generate FIR draft and emergency checklist for this specific incident



    fir_draft = generate_cybercrime_fir_draft(



        claimed_organization=incident["claimed_organization"],



        scam_type=incident["scam_type"],



        amount_inr=incident["amount_demanded_or_lost_inr"],



        scammer_contacts=incident["scammer_contacts"],



        scammer_links=incident["scammer_links"],



        incident_description=incident["description"],



        incident_ref=incident["incident_ref"]



    )



    primary_contact = incident["scammer_contacts"][0] if incident["scammer_contacts"] else None



    freeze_steps = generate_emergency_freeze_checklist(



        amount_inr=incident["amount_demanded_or_lost_inr"],



        upi_or_phone=primary_contact



    )



    incident["complaint_draft_fir"] = fir_draft



    incident["emergency_freeze_checklist"] = freeze_steps



    # Probe Agent 2 correlation independently without faking



    a2_status = probe_agent2_status()



    incident["agent2_integration"] = {



        "status": a2_status["status"],



        "correlation_status": a2_status.get("correlation_status", "pending-analysis"),



        "message": a2_status["message"]



    }



    return incident



# =========================================================



# 3. INDEPENDENT AGENT 1 & AGENT 2 API INTEGRATION



# =========================================================



@router.get("/agents/status", summary="Probe Configured Agent 1 & Agent 2 Endpoints")



def get_agents_status():



    """



    Checks the availability of Agent 1 and Agent 2 over configurable HTTP endpoints.



    Does NOT start or launch either agent.



    If unavailable, reports explicit 'service-unavailable' / 'pending-analysis' status.



    """



    return {



        "configuration": get_agents_config(),



        "agent1_threat_analyzer": probe_agent1_status(),



        "agent2_correlator": probe_agent2_status()



    }



@router.post("/agents/analyze", summary="Forward to Agent 1 for Threat Analysis")



def forward_to_agent1(payload: Dict[str, Any]):



    """



    Forwards an analysis payload to Agent 1 over HTTP if available.



    If Agent 1 is unavailable, returns an explicit 'pending-analysis' status.



    DOES NOT generate fake AI analysis.



    """



    return request_agent1_analysis(payload)



@router.post("/agents/correlate", summary="Forward to Agent 2 for Threat Correlation")



def forward_to_agent2(incident_id: str = Query(...)):



    """



    Forwards an incident to Agent 2 over HTTP for campaign correlation if available.



    If Agent 2 is unavailable, returns an explicit 'pending-analysis' status.



    DOES NOT generate fake threat correlations or fake graph data.



    """



    inc = get_incident_by_ref(incident_id)



    indicators = None



    if inc:



        indicators = {



            "urls": inc.get("scammer_links", []),



            "domains": [l.replace("https://", "").replace("http://", "").split("/")[0] for l in inc.get("scammer_links", [])],



            "phones_or_upi": inc.get("scammer_contacts", []),



            "claimed_organization": inc.get("claimed_organization")



        }



    return request_agent2_correlation(incident_id=incident_id, indicators=indicators)



# =========================================================



# 4. EXISTING CORE CONTRACT & INTER-AGENT ENDPOINTS



# =========================================================



@router.get("/health", summary="Community Hub Health Status")



def health_check():



    """Confirms operational health of the Community Hub and SQLite victim datastore."""



    stats = get_dashboard_statistics()



    return {



        "status": "ok",



        "agent": "Member 3: Community Victim Network & External Portals Hub",



        "database": "sqlite_connected",



        "total_indexed_victim_reports": stats["total_submitted_incidents"],



        "cumulative_inr_loss_tallied": stats["total_financial_loss_inr"],



        "active_community_alerts": stats["active_community_alerts"]



    }



@router.get("/mock", response_model=CommunityThreatLookupResponse, summary="Get Mock Community Threat Lookup")



def get_mock_community_response():



    """Returns a realistic mock CommunityThreatLookupResponse for frontend development."""



    data = get_mock_data()



    return data["community_hub"]



@router.post("/lookup", response_model=CommunityThreatLookupResponse, summary="Lookup Indicator in Community & External Portals")



def lookup_community_threats(payload: CommunityLookupRequest):



    """



    Checks indicators against internal student victim reports and queries external reputation



    and threat reporting networks (ScamAdviser, PhishTank, Reddit r/Scams).



    Returns matched counts, cumulative financial damage, personalized external portal links,



    official FIR complaint drafts, and 1930 emergency freeze checklists.



    """



    db_result = lookup_threat_indicators(



        domain=payload.domain,



        upi_or_phone=payload.upi_or_phone,



        email=payload.email,



        claimed_organization=payload.claimed_organization



    )



    matched_count = db_result["matched_count"]



    total_loss = db_result["total_money_lost_inr"]



    evidence_summaries = db_result["evidence_summaries"]



    matched_tags = db_result["matched_indicators"]



    external_matches = generate_external_portal_reports(



        domain=payload.domain,



        claimed_organization=payload.claimed_organization,



        upi_or_phone=payload.upi_or_phone



    )



    target_org = payload.claimed_organization or (db_result["records"][0]["claimed_organization"] if db_result["records"] else "Suspected Scam Syndicate")



    sample_desc = evidence_summaries[0] if evidence_summaries else f"Fraudulent solicitation under pretext of {target_org} recruitment."



    contacts = [payload.upi_or_phone] if payload.upi_or_phone else []



    if payload.email:



        contacts.append(payload.email)



    links = [payload.domain] if payload.domain else []



    fir_draft = generate_cybercrime_fir_draft(



        claimed_organization=target_org,



        scam_type="recruitment_deposit_fraud",



        amount_inr=total_loss,



        scammer_contacts=contacts,



        scammer_links=links,



        incident_description=sample_desc



    )



    freeze_checklist = generate_emergency_freeze_checklist(



        amount_inr=total_loss,



        upi_or_phone=payload.upi_or_phone



    )



    campus_advisory = generate_campus_advisory_bulletin(



        claimed_organization=target_org,



        scam_type="recruitment_deposit_fraud",



        scammer_contacts=contacts,



        scammer_links=links



    )



    return CommunityThreatLookupResponse(



        internal_victim_reports_count=matched_count,



        total_reported_money_lost_inr=total_loss,



        victim_evidence_summaries=evidence_summaries,



        external_portal_matches=external_matches,



        matched_indicators=matched_tags,



        complaint_draft_fir=fir_draft,



        emergency_freeze_checklist=freeze_checklist,



        campus_broadcast_advisory=campus_advisory



    )



@router.get("/external-portals", response_model=List[ExternalPortalReport], summary="Get Go-To Scam Reporting Portals")



def get_external_reporting_portals(



    domain: Optional[str] = Query(None, description="Optional domain to customize lookup URLs"),



    organization: Optional[str] = Query(None, description="Optional organization to customize complaint text"),



    upi: Optional[str] = Query(None, description="Optional UPI ID to include NPCI dispute routing")



):



    """



    Provides a curated directory of official and community 'Go-To' scam reporting portals



    (CyberCrime.gov.in, CERT-In, ScamAdviser, Reddit r/Scams, NPCI, NCH) with direct links.



    """



    if domain or organization or upi:



        return generate_external_portal_reports(domain=domain, claimed_organization=organization, upi_or_phone=upi)



    return get_all_external_portals_directory()



@router.post("/upload-evidence", summary="Upload Supporting Incident Screenshots or Documents")



def upload_incident_evidence(files: List[UploadFile] = File(...)):



    """



    Uploads permitted evidence files (PNG, JPG, JPEG, WEBP, PDF, TXT) up to 10 MB each.



    Validates content, strips path traversal, and returns secure stored filenames.



    """



    if not files:



        raise HTTPException(status_code=400, detail="No files provided for upload.")



    results = []



    for f in files:



        meta = sanitize_and_store_file(f)



        results.append(meta)



    return {



        "status": "success",



        "uploaded_count": len(results),



        "files": results,



        "filenames": [r["stored_filename"] for r in results]



    }



@router.get("/evidence/{filename}", summary="Retrieve Uploaded Evidence File")



def get_evidence_file(filename: str):



    """



    Safely retrieves an uploaded evidence document or screenshot.



    Restricts access strictly within the isolated uploads directory.



    """



    path = get_evidence_file_path(filename)



    if not path:



        raise HTTPException(status_code=404, detail="Evidence file not found.")



    return FileResponse(path=str(path), filename=path.name)



@router.post("/report", response_model=IncidentSubmissionResponse, summary="Submit Student Victim Report")



def submit_victim_report(



    report: VictimReportSubmission,



    x_user_pseudonym: Optional[str] = Header(None, alias="X-User-Pseudonym")



) -> IncidentSubmissionResponse:



    """



    Allows a student or campus peer to report a suspicious cyber incident they personally encountered.



    Validates mandatory fields (title, category, description), enforces privacy, generates a unique incident ID,



    associates the report with a pseudonymous handle, and sets initial status to 'SUBMITTED'.



    Does not require an official complaint to submit.



    """



    # 1. Validate mandatory fields



    if not report.incident_title or len(report.incident_title.strip()) < 5:



        raise HTTPException(



            status_code=422,



            detail="Incident title is mandatory and must contain at least 5 characters."



        )



    if not report.description or len(report.description.strip()) < 10:



        raise HTTPException(



            status_code=422,



            detail="Description of what happened is mandatory and must contain at least 10 characters."



        )



    # 2. Determine pseudonym (from payload, header, or auto-generate)



    submitter_pseudonym = (



        report.user_pseudonym or



        x_user_pseudonym or



        generate_pseudonym()



    ).strip()



    # 3. Clean and aggregate links



    all_links = list(report.scammer_links or [])



    if report.suspicious_url_or_domain and report.suspicious_url_or_domain.strip():



        all_links.append(report.suspicious_url_or_domain.strip())



    if report.github_repo_link and report.github_repo_link.strip():



        all_links.append(report.github_repo_link.strip())



    # 4. Save to database with initial verification status SUBMITTED



    incident_ref, row_id, assigned_pseudonym, v_status = add_victim_report(



        incident_title=report.incident_title,



        claimed_organization=report.claimed_organization,



        scam_type=report.scam_type,



        amount_demanded_or_lost_inr=report.amount_demanded_or_lost_inr,



        scammer_contacts=report.scammer_contacts,



        scammer_links=all_links,



        description=report.description,



        evidence_filenames=report.evidence_filenames,



        user_pseudonym=submitter_pseudonym,



        financial_loss_occurred=report.financial_loss_occurred,



        suspicious_url_or_domain=report.suspicious_url_or_domain,



        github_repo_link=report.github_repo_link,



        official_complaint_filed=report.official_complaint_filed,



        complaint_ack_ref=report.complaint_ack_ref,



        verification_status="SUBMITTED"



    )



    # 5. Generate tailored legal and emergency guidance



    fir_draft = generate_cybercrime_fir_draft(



        claimed_organization=report.claimed_organization or "Unspecified Entity",



        scam_type=report.scam_type,



        amount_inr=report.amount_demanded_or_lost_inr if report.financial_loss_occurred else 0.0,



        scammer_contacts=report.scammer_contacts,



        scammer_links=all_links,



        incident_description=report.description,



        incident_ref=incident_ref



    )



    primary_contact = report.scammer_contacts[0] if report.scammer_contacts else None



    freeze_steps = generate_emergency_freeze_checklist(



        amount_inr=report.amount_demanded_or_lost_inr if report.financial_loss_occurred else 0.0,



        upi_or_phone=primary_contact



    )



    return IncidentSubmissionResponse(



        status="success",



        incident_id=incident_ref,



        database_id=row_id,



        user_pseudonym=assigned_pseudonym,



        verification_status=v_status,



        message=f"Incident {incident_ref} logged successfully with status '{v_status}'. Your submission is pseudonymous.",



        complaint_draft_fir=fir_draft,



        emergency_freeze_checklist=freeze_steps



    )



@router.get("/reports/my-submissions", summary="Get Current User Submitted Reports")



def get_my_submissions(



    pseudonym: Optional[str] = Query(None, description="User's pseudonymous public identifier"),



    x_user_pseudonym: Optional[str] = Header(None, alias="X-User-Pseudonym")



):



    """



    Retrieves all incident reports filed by the requesting user using their pseudonymous handle.



    Displays verification status (SUBMITTED, UNDER_REVIEW, Corroborated) and incident details.



    """



    target_pseudonym = (pseudonym or x_user_pseudonym or "").strip()



    if not target_pseudonym:



        return {



            "status": "success",



            "user_pseudonym": None,



            "submissions_count": 0,



            "submissions": []



        }



    user_reports = get_user_submitted_reports(target_pseudonym)



    return {



        "status": "success",



        "user_pseudonym": target_pseudonym,



        "submissions_count": len(user_reports),



        "submissions": user_reports



    }



@router.get("/feed", summary="Get Community Victim Feed & Loss Ticker")



def get_community_victim_feed(

    page: int = Query(1, ge=1, description="Page number (1-indexed)"),

    page_size: int = Query(10, ge=1, le=50, description="Items per page"),

    category: Optional[str] = Query(None, description="Threat category filter"),

    risk_level: Optional[str] = Query(None, description="Risk level filter"),

    verification_status: Optional[str] = Query(None, description="Verification status filter"),

    date_filter: Optional[str] = Query(None, description="Date filter ('all', 'today', 'past_7_days', 'past_30_days')"),

    incident_type: Optional[str] = Query(None, description="Incident type/scam_type filter"),

    q: Optional[str] = Query(None, description="Indicator or keyword search query"),

    limit: Optional[int] = Query(None, description="Backward-compatible limit param")

):

    """

    Returns searchable, filterable community-submitted incident reports with backend pagination.

    Supports filtering by threat category, risk level, verification status, date, incident type, and keyword.

    Includes overall loss metrics and summary counters.

    """

    page_val = page if isinstance(page, int) else 1

    page_size_val = page_size if isinstance(page_size, int) else 10

    if isinstance(limit, int) and limit > 0:

        page_size_val = min(limit, 50)



    stats = get_dashboard_statistics()

    result = query_community_incident_feed(

        page=page_val,

        page_size=page_size_val,

        category=category if isinstance(category, str) else None,

        risk_level=risk_level if isinstance(risk_level, str) else None,

        verification_status=verification_status if isinstance(verification_status, str) else None,

        date_filter=date_filter if isinstance(date_filter, str) else None,

        incident_type=incident_type if isinstance(incident_type, str) else None,

        query=q if isinstance(q, str) else None

    )



    return {

        "status": "success",

        "summary": {

            "total_victims_reported": stats["total_submitted_incidents"],

            "total_financial_loss_inr": stats["total_financial_loss_inr"],

            "newly_reported_incidents": stats["newly_reported_incidents"],

            "active_community_alerts": stats["active_community_alerts"]

        },

        "pagination": result["pagination"],

        "filters_applied": result["filters_applied"],

        "feed": result["items"]

    }



@router.get("/feed/filters", summary="Get Feed Filter Options")

def get_feed_filter_choices():

    """Returns available categories, risk levels, verification statuses, date filters, and incident types."""

    return {

        "status": "success",

        "options": get_feed_filter_options()

    }



@router.get("/search", summary="Search Threat Indicators & Correlated Campaigns")

def search_threat_network(

    q: str = Query(..., min_length=1, description="Company, domain, URL, email, GitHub repo, package, or keyword"),

    page: int = Query(1, ge=1, description="Page number"),

    page_size: int = Query(10, ge=1, le=50, description="Items per page"),

    category: Optional[str] = Query(None, description="Optional category filter"),

    verification_status: Optional[str] = Query(None, description="Optional status filter")

):

    """

    Dedicated Threat Search:

    1. Searches community incident DB.

    2. Identifies exact indicator matches.

    3. Retrieves potentially related incidents from relationship records.

    4. Displays matching reports with PII masked.

    5. Explains why each result matched.

    6. Displays verification status and confidence of the relationship.

    Distinguishes exact matches from approximate matches.

    """

    q_str = str(q).strip() if (isinstance(q, str) or (hasattr(q, '__str__') and not hasattr(q, 'default'))) else ""

    page_val = page if isinstance(page, int) else 1

    page_size_val = page_size if isinstance(page_size, int) else 10

    cat_str = category if isinstance(category, str) else None

    status_str = verification_status if isinstance(verification_status, str) else None



    return search_threat_indicators(

        query=q_str,

        page=page_val,

        page_size=page_size_val,

        category=cat_str,

        verification_status=status_str

    )



@router.get("/statistics", summary="Get Global Community Scam Statistics")



def get_community_statistics():



    """



    Detailed analytics on scam categories, financial losses, and targeted brands.



    """



    return get_dashboard_statistics()



@router.get("/reports-all", summary="Export All Incident Records for Agent 2 Correlator")



def get_all_reports_for_agent2():



    """



    Internal API for Member 2 (Agent 2 Correlator) to access all historical scam records



    and generate entity-relationship graphs.



    """



    return get_all_records_for_correlator()



@router.post("/generate-fir-draft", summary="Generate Copy-Ready CyberCrime FIR Complaint")



def create_fir_complaint_draft(payload: GenerateFIRDraftRequest):



    """



    Generates a pre-formatted, legally-cited formal complaint narrative ready to be copy-pasted



    into CyberCrime.gov.in or submitted at a Cyber Police Station.



    """



    draft = generate_cybercrime_fir_draft(



        claimed_organization=payload.claimed_organization,



        scam_type=payload.scam_type,



        amount_inr=payload.amount_inr,



        scammer_contacts=payload.scammer_contacts,



        scammer_links=payload.scammer_links,



        incident_description=payload.incident_description



    )



    



    primary_contact = payload.scammer_contacts[0] if payload.scammer_contacts else None



    freeze_steps = generate_emergency_freeze_checklist(



        amount_inr=payload.amount_inr,



        upi_or_phone=primary_contact



    )



    return {



        "status": "success",



        "complaint_draft_fir": draft,



        "emergency_freeze_checklist": freeze_steps,



        "submission_portal": "https://cybercrime.gov.in/Webform/Accept.aspx"



    }



# =====================================================================
# 1. COMMUNITY THREAT ALERTS ENDPOINTS (PROMPT 5 REQUIREMENT 1)
# =====================================================================

@router.get("/alerts", summary="Get Dynamic Community Threat Alerts")
def get_threat_alerts_endpoint():
    """
    Returns dynamically generated threat advisories derived from multi-victim
    indicator overlaps and recurring campaigns in SQLite.
    """
    from backend.community_hub.threat_alerts import generate_dynamic_community_alerts
    alerts = generate_dynamic_community_alerts()
    return {
        "status": "success",
        "total_active_alerts": len(alerts),
        "alerts": alerts,
        "disclaimer": "Potentially Related Incidents. Shared indicators alone do not prove a common perpetrator or company compromise."
    }


@router.get("/alerts/{alert_id}", summary="Get Specific Community Threat Alert with Connected Incidents")
def get_threat_alert_detail_endpoint(alert_id: str):
    """
    Returns full details for a specific threat advisory including all connected
    incident records for user inspection.
    """
    from backend.community_hub.threat_alerts import get_community_alert_by_id
    alert = get_community_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Threat alert '{alert_id}' not found.")
    return {
        "status": "success",
        "alert": alert
    }


# =====================================================================
# 2. CYBER AWARENESS & EDUCATION CENTRE ENDPOINTS (PROMPT 5 REQUIREMENT 3)
# =====================================================================

@router.get("/education", summary="Get Cyber Awareness & Education Modules")
def get_education_centre_endpoint():
    """
    Returns all 6 educational security topics enriched with live community
    incident counts and real-world loss statistics.
    """
    from backend.community_hub.education import get_all_education_topics
    topics = get_all_education_topics()
    return {
        "status": "success",
        "total_topics": len(topics),
        "topics": topics
    }


@router.get("/education/{topic_id}", summary="Get Specific Education Module Detail")
def get_education_topic_detail_endpoint(topic_id: str):
    """
    Returns detailed guidance, sanitized examples, warning signs, and prevention
    tips for a specific cyber threat topic.
    """
    from backend.community_hub.education import get_education_topic_by_id
    topic = get_education_topic_by_id(topic_id)
    if not topic:
        raise HTTPException(status_code=404, detail=f"Educational topic '{topic_id}' not found.")
    return {
        "status": "success",
        "topic": topic
    }


# =====================================================================
# 3. THREAT RELATIONSHIP GRAPH ENDPOINTS (PROMPT 5 REQUIREMENT 4)
# =====================================================================

@router.get("/graph", summary="Get Global Threat Relationship Graph")
def get_global_threat_graph_endpoint(max_nodes: int = Query(60)):
    """
    Returns the multi-incident indicator correlation graph adhering strictly
    to GraphNode and GraphEdge schemas.
    """
    from backend.community_hub.graph_engine import build_community_threat_graph
    return build_community_threat_graph(incident_ref="all", max_nodes=max_nodes)


@router.get("/recent", summary="Get Live Community Reports from the Last 30 Days")
def get_recent_community_endpoint(
    days: int = Query(30, ge=1, le=30),
    limit: int = Query(50, ge=1, le=100),
):
    """Return recent real submissions and window-scoped totals, excluding marked demo fixtures."""
    return get_recent_community_snapshot(days=days, limit=limit)


@router.get("/graph/model", summary="Correlate Recent Community Reports with Agent 2")
def get_recent_model_graph_endpoint(
    days: int = Query(30, ge=1, le=30),
    max_nodes: int = Query(80, ge=5, le=120),
):
    """Use the trained Agent 2 model to compare live reports submitted within the selected window."""
    from backend.community_hub.graph_engine import build_recent_model_correlation_graph
    return build_recent_model_correlation_graph(days=days, max_nodes=max_nodes)


@router.get("/graph/{incident_ref}", summary="Get Incident Targeted Threat Neighborhood Graph")
def get_incident_threat_graph_endpoint(incident_ref: str, max_nodes: int = Query(30)):
    """
    Returns the targeted neighborhood graph for a specific incident, mapping
    exact indicators, campaign syndication, and connected reports.
    """
    from backend.community_hub.graph_engine import build_community_threat_graph
    res = build_community_threat_graph(incident_ref=incident_ref, max_nodes=max_nodes)
    if res.get("status") == "not_found":
        raise HTTPException(status_code=404, detail=f"Incident '{incident_ref}' not found.")
    return res


# =====================================================================
# 4. MODERATION & VERIFICATION SYSTEM ENDPOINTS (PROMPT 5 REQUIREMENT 2)
# =====================================================================

class ModerationReviewPayload(BaseModel):
    new_status: Optional[str] = None
    moderator_id: str = "mod-reviewer-default"
    moderator_notes: Optional[str] = None
    is_public_approved: Optional[bool] = None
    moderation_flag: Optional[str] = None
    duplicate_of_ref: Optional[str] = None


def check_moderator_auth(x_moderator_key: Optional[str] = Header(None, alias="X-Moderator-Key")):
    """Dependency that enforces backend authorization for moderator-only endpoints."""
    from backend.community_hub.moderation import verify_moderator_access
    if not verify_moderator_access(x_moderator_key):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Valid 'X-Moderator-Key' header is required for moderator operations."
        )


@router.get("/moderation/reports", summary="Moderator Incident Review Queue (Auth Required)")
def get_moderation_queue_endpoint(
    status: Optional[str] = Query(None),
    flag: Optional[str] = Query(None),
    is_public: Optional[bool] = Query(None),
    page: int = Query(1),
    page_size: int = Query(20),
    x_moderator_key: Optional[str] = Header(None, alias="X-Moderator-Key")
):
    """
    Protected endpoint for moderators to inspect submitted incidents, verify evidence,
    and filter by moderation state.
    """
    check_moderator_auth(x_moderator_key)
    from backend.community_hub.moderation import get_moderation_queue
    p = page if isinstance(page, int) else 1
    ps = page_size if isinstance(page_size, int) else 20
    st = status if isinstance(status, str) else None
    fl = flag if isinstance(flag, str) else None
    ip = is_public if isinstance(is_public, bool) else None
    return get_moderation_queue(status=st, flag=fl, is_public=ip, page=p, page_size=ps)


@router.post("/moderation/review/{incident_ref}", summary="Apply Moderator Status Decision (Auth Required)")
def apply_moderation_review_endpoint(
    incident_ref: str,
    payload: ModerationReviewPayload,
    x_moderator_key: Optional[str] = Header(None, alias="X-Moderator-Key")
):
    """
    Updates incident verification status (SUBMITTED, UNDER_REVIEW, CORROBORATED,
    DISPUTED, CLOSED, ARCHIVED) and public visibility with audit logging.
    """
    check_moderator_auth(x_moderator_key)
    from backend.community_hub.moderation import apply_moderator_action
    ok, msg, data = apply_moderator_action(
        incident_ref=incident_ref,
        action="STATUS_REVIEW",
        moderator_id=payload.moderator_id,
        new_status=payload.new_status,
        moderator_notes=payload.moderator_notes,
        is_public_approved=payload.is_public_approved,
        duplicate_of_ref=payload.duplicate_of_ref,
        moderation_flag=payload.moderation_flag
    )
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    return {
        "status": "success",
        "message": msg,
        "moderation_record": data
    }


@router.post("/moderation/flag/{incident_ref}", summary="Flag Incident as Duplicate/Spam/Misleading (Auth Required)")
def flag_incident_endpoint(
    incident_ref: str,
    payload: ModerationReviewPayload,
    x_moderator_key: Optional[str] = Header(None, alias="X-Moderator-Key")
):
    """
    Allows moderators to flag reports as duplicate, spam, misleading, or request more information.
    """
    check_moderator_auth(x_moderator_key)
    from backend.community_hub.moderation import apply_moderator_action
    ok, msg, data = apply_moderator_action(
        incident_ref=incident_ref,
        action="FLAG_INCIDENT",
        moderator_id=payload.moderator_id,
        new_status=payload.new_status,
        moderator_notes=payload.moderator_notes,
        is_public_approved=payload.is_public_approved,
        duplicate_of_ref=payload.duplicate_of_ref,
        moderation_flag=payload.moderation_flag or "duplicate"
    )
    if not ok:
        raise HTTPException(status_code=404, detail=msg)
    return {
        "status": "success",
        "message": msg,
        "moderation_record": data
    }


@router.get("/moderation/logs/{incident_ref}", summary="Get Incident Moderation Audit Trail (Auth Required)")
def get_incident_audit_trail_endpoint(
    incident_ref: str,
    x_moderator_key: Optional[str] = Header(None, alias="X-Moderator-Key")
):
    """
    Returns complete immutable audit history for an incident showing all moderator decisions.
    """
    check_moderator_auth(x_moderator_key)
    from backend.community_hub.moderation import get_incident_audit_trail
    trail = get_incident_audit_trail(incident_ref)
    return {
        "status": "success",
        "incident_ref": incident_ref,
        "audit_trail": trail
    }

