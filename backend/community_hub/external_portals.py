"""
Factora Member 3: External "Go-To" Scam Reporting Portals & Threat Intelligence Aggregator
Integrates external scam repositories, reputation lookups, and direct complaint filing routes
(CyberCrime.gov.in, CERT-In, ScamAdviser, Reddit r/Scams, NPCI UPI dispute, and NCH).
"""

from typing import List, Optional, Dict, Any
import urllib.parse

try:
    from shared.schemas import ExternalPortalReport
except ImportError:
    from ...shared.schemas import ExternalPortalReport


# Curated master list of authoritative anti-scam & law enforcement portals
MASTER_PORTAL_CONFIGS = [
    {
        "id": "cybercrime_gov_in",
        "portal_name": "National Cyber Crime Reporting Portal (MHA, Govt of India)",
        "portal_url": "https://cybercrime.gov.in",
        "base_submission_url": "https://cybercrime.gov.in/Webform/Accept.aspx",
        "category": "law_enforcement",
        "description": "Official Ministry of Home Affairs portal for lodging cognizable FIRs on financial cyber fraud and job scams."
    },
    {
        "id": "cert_in",
        "portal_name": "CERT-In (Indian Computer Emergency Response Team)",
        "portal_url": "https://www.cert-in.org.in",
        "base_submission_url": "https://www.cert-in.org.in/s2cMainServlet?pageid=CONTACTUS",
        "category": "technical_incident",
        "description": "National nodal agency under MeitY for reporting phishing URLs, malware payloads, and code repository attacks."
    },
    {
        "id": "scamadviser",
        "portal_name": "ScamAdviser Global Domain Trust Engine",
        "portal_url": "https://www.scamadviser.com",
        "base_submission_url": "https://www.scamadviser.com/check-website",
        "category": "domain_reputation",
        "description": "Automated domain risk analyzer verifying domain age, server location, SSL certificates, and blacklist status."
    },
    {
        "id": "reddit_scams",
        "portal_name": "Reddit r/Scams & Student Cyber Watch Community",
        "portal_url": "https://www.reddit.com/r/Scams/",
        "base_submission_url": "https://www.reddit.com/r/Scams/submit",
        "category": "crowdsourced_discussions",
        "description": "Global peer-intelligence forum tracking emerging recruitment patterns, Telegram task syndicates, and interview fee traps."
    },
    {
        "id": "urlhaus",
        "portal_name": "URLhaus (Abuse.ch Malware Threat Tracker)",
        "portal_url": "https://urlhaus.abuse.ch",
        "base_submission_url": "https://urlhaus.abuse.ch/browse/",
        "category": "malware_phishing",
        "description": "Open database tracking malicious links, malicious GitHub payloads, and trojan installer downloads."
    },
    {
        "id": "npci_upi",
        "portal_name": "NPCI UPI Dispute Redressal Portal",
        "portal_url": "https://www.npci.org.in",
        "base_submission_url": "https://www.npci.org.in/what-we-do/upi/dispute-redressal-mechanism",
        "category": "financial_dispute",
        "description": "National Payments Corporation of India portal for flagging fraudulent UPI accounts and initiating payment chargebacks."
    },
    {
        "id": "consumer_helpline",
        "portal_name": "National Consumer Helpline (NCH - Ministry of Consumer Affairs)",
        "portal_url": "https://consumerhelpline.gov.in",
        "base_submission_url": "https://consumerhelpline.gov.in/user/index.php",
        "category": "consumer_protection",
        "description": "Department of Consumer Affairs portal for consumer grievances. Cybercrime and financial fraud should also be reported to the National Cyber Crime Reporting Portal."
    }
]


def generate_external_portal_reports(
    domain: Optional[str] = None,
    claimed_organization: Optional[str] = None,
    upi_or_phone: Optional[str] = None
) -> List[ExternalPortalReport]:
    """
    Builds personalized ExternalPortalReport objects with deep-link lookup and complaint filing URLs
    tailored to the specific suspected domain, organization, or UPI handle.
    """
    reports: List[ExternalPortalReport] = []

    # 1. CyberCrime.gov.in Report Card
    target_org = claimed_organization or "Suspected Recruitment Syndicate"
    cybercrime_summary = (
        f"Official route to file an e-Complaint under 'Report Other Cyber Crime -> Financial / Job Fraud'. "
        f"Direct evidence required: Accused Org ('{target_org}'), "
        f"Transaction UTR/Reference, and Scammer contact details."
    )
    reports.append(ExternalPortalReport(
        portal_name="National Cyber Crime Reporting Portal (Govt of India)",
        portal_url="https://cybercrime.gov.in",
        external_report_summary=cybercrime_summary,
        direct_report_submission_url="https://cybercrime.gov.in/Webform/Accept.aspx"
    ))

    # 2. ScamAdviser Report Card
    target_domain = domain or "target-website.com"
    clean_domain = target_domain.replace("https://", "").replace("http://", "").split("/")[0].strip()
    
    scamadviser_url = f"https://www.scamadviser.com/check-website/{clean_domain}" if clean_domain else "https://www.scamadviser.com"
    reports.append(ExternalPortalReport(
        portal_name="ScamAdviser",
        portal_url="https://www.scamadviser.com",
        external_report_summary=f"Open ScamAdviser to check the reputation of {clean_domain}. Factora does not estimate or invent a ScamAdviser score.",
        direct_report_submission_url=scamadviser_url
    ))

    # 3. CERT-In Incident Reporting
    reports.append(ExternalPortalReport(
        portal_name="CERT-In (Indian Computer Emergency Response Team)",
        portal_url="https://www.cert-in.org.in",
        external_report_summary="CERT-In incident reporting contact page. Reports can be sent to its incident response desk; follow the official instructions on the page.",
        direct_report_submission_url="https://www.cert-in.org.in/s2cMainServlet?pageid=CONTACTUS"
    ))

    # 4. Reddit r/Scams Community
    search_query = clean_domain if clean_domain and clean_domain != "target-website.com" else target_org
    encoded_query = urllib.parse.quote(f"{search_query} job scam")
    reddit_search_url = f"https://www.reddit.com/r/Scams/search/?q={encoded_query}&restrict_sr=1"
    reports.append(ExternalPortalReport(
        portal_name="Reddit r/Scams & Community Alert Threads",
        portal_url="https://www.reddit.com/r/Scams/",
        external_report_summary=f"Search public r/Scams discussions for '{search_query} job scam'. Community posts are anecdotal and should be independently verified.",
        direct_report_submission_url=reddit_search_url
    ))

    # 5. NPCI UPI Dispute Redressal (if UPI or financial ask detected)
    if upi_or_phone or "deposit" in target_org.lower() or "tcs" in target_org.lower():
        reports.append(ExternalPortalReport(
            portal_name="NPCI Official UPI Dispute Redressal Portal",
            portal_url="https://www.npci.org.in",
            external_report_summary="Official UPI dispute guidance. Start a transaction grievance in your UPI app or with your bank; use the listed escalation path if it remains unresolved.",
            direct_report_submission_url="https://www.npci.org.in/what-we-do/upi/dispute-redressal-mechanism"
        ))

    return reports


def get_all_external_portals_directory() -> List[ExternalPortalReport]:
    """Returns the static directory of all 7 Go-To reporting portals with comprehensive explanations."""
    return [
        ExternalPortalReport(
            portal_name=cfg["portal_name"],
            portal_url=cfg["portal_url"],
            external_report_summary=cfg["description"],
            direct_report_submission_url=cfg["base_submission_url"]
        )
        for cfg in MASTER_PORTAL_CONFIGS
    ]
