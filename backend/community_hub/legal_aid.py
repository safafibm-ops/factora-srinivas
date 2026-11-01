"""
Factora Member 3: Legal Aid & Incident Response Engine
Generates pre-formatted official cybercrime FIR complaint drafts (citable under Indian IT Act 66D & IPC/BNS),
emergency 1930 golden-hour UPI freeze action checklists, and campus placement early-warning advisories.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime


def generate_cybercrime_fir_draft(
    claimed_organization: str,
    scam_type: str,
    amount_inr: float,
    scammer_contacts: List[str],
    scammer_links: List[str],
    incident_description: str,
    incident_ref: Optional[str] = None
) -> str:
    """
    Constructs an official, legally structured complaint narrative compliant with the
    National Cyber Crime Reporting Portal (cybercrime.gov.in) requirements.
    """
    ref = incident_ref or f"FACT-CMPL-{datetime.now().strftime('%Y%m%d%H%M')}"
    today_str = datetime.now().strftime("%d-%B-%Y")
    
    contacts_str = ", ".join(scammer_contacts) if scammer_contacts else "Not provided"
    links_str = ", ".join(scammer_links) if scammer_links else "Not provided"
    amount_text = f"Rs. {amount_inr:,.2f} (INR)" if amount_inr > 0 else "Rs. 0.00 (Attempted Fraud / Malware Distribution)"

    draft = f"""================================================================================
FORMAL COMPLAINT OF ONLINE RECRUITMENT FRAUD & CYBER EXTORTION
TO BE LODGED AT: National Cyber Crime Reporting Portal (cybercrime.gov.in)
CATEGORY: Financial Cyber Fraud / Job & Recruitment Scam
REFERENCE TRACKING ID: {ref}
DATE OF NOTICE: {today_str}
================================================================================

TO,
THE NODAL OFFICER / INVESTIGATING OFFICER,
CYBER CRIME POLICE STATION / NATIONAL CYBER CRIME CELL,
MINISTRY OF HOME AFFAIRS, GOVT. OF INDIA.

SUBJECT: Formal complaint regarding deceptive recruitment fraud, unauthorized brand 
         impersonation of {claimed_organization}, and financial extortion / malicious execution.

RESPECTED SIR / MADAM,

I am writing to formally report a cognizable cyber crime incident perpetrated against me 
under the pretext of an internship / employment offer from "{claimed_organization}".

1. ACCUSED IDENTIFICATION & TECHNICAL ARTIFACTS:
--------------------------------------------------------------------------------
- Impersonated Entity: {claimed_organization}
- Suspect Contact Numbers / UPI VPAs: {contacts_str}
- Suspect Portals / Links / Repositories: {links_str}
- Modus Operandi Category: {scam_type.replace('_', ' ').title()}
- Direct Financial Loss: {amount_text}

2. CHRONOLOGICAL STATEMENT OF FACTS:
--------------------------------------------------------------------------------
{incident_description}

3. APPLICABLE PROVISIONS OF LAW:
--------------------------------------------------------------------------------
The accused individuals / syndicates have violated multiple statutory provisions under:
a) Section 66D of the Information Technology Act, 2000 (Punishment for cheating by 
   personation by using computer resource - Cognizable, imprisonment up to 3 years).
b) Section 66C of the Information Technology Act, 2000 (Identity theft and brand spoofing).
c) Section 419 & 420 of Indian Penal Code (IPC) / Sections 318 & 319 of Bharatiya Nyaya 
   Sanhita, 2023 (Cheating by personation and dishonestly inducing delivery of property).

4. PRAYER / RELIEF SOUGHT:
--------------------------------------------------------------------------------
In light of the documentary evidence attached, I earnestly pray that:
i.   An FIR / General Diary Entry be registered immediately under the relevant sections.
ii.  An emergency freeze directive / administrative lien be dispatched via the 1930 
     Citizen Financial Cyber Fraud Reporting System (CFCFRMS) to the beneficiary UPI/bank accounts.
iii. Domain registry and telecommunication operators be instructed to de-activate 
     and preserve server logs for the suspect infrastructure.

VERIFICATION:
I verify that the statements made above are true to the best of my knowledge and technical evidence.

Yours Faithfully,
Aggrieved Student / Job Applicant
(Evidence Attached via Factora Safety Tech Incident Dossier)
================================================================================
"""
    return draft.strip()


def generate_emergency_freeze_checklist(
    amount_inr: float,
    upi_or_phone: Optional[str] = None
) -> List[str]:
    """
    Generates time-critical 'Golden Hour' steps for students to prevent money siphon.
    """
    checklist = [
        "IMMEDIATE 1930 CALL: Dial national helpline 1930 (Citizen Financial Cyber Fraud Reporting System) within the first 2 hours. State your transaction UTR, beneficiary UPI ID, and bank account name to trigger auto-freeze across recipient banks.",
        "LOG TICKET IN UPI APP: Open Google Pay / PhonePe / Paytm -> Navigate to Transaction History -> Select the disputed payment -> Tap 'Report Fraud / Dispute Payment' and mark as 'Impersonation Scam'.",
        "NOTIFY BANK NODAL OFFICER: Contact your bank's 24/7 cyber fraud helpline immediately and request a formal chargeback dispute under NPCI dispute code 'Fraudulent Beneficiary'.",
        "FILE OFFICIAL CYBERCRIME.GOV.IN REPORT: Submit a complaint at https://cybercrime.gov.in within 24 hours to obtain an official Acknowledgement Number (required by your bank to process the refund escrow).",
        "BLOCK ALL CHANNELS: Do not engage in further contact or send 'cancellation fees'—scammers frequently demand a second transfer promising to refund the first."
    ]
    
    if upi_or_phone:
        checklist.insert(1, f"FLAG UPI VPA: File a direct payment fraud ticket against suspect handle '{upi_or_phone}' at NPCI Dispute Redressal Portal: https://www.npci.org.in/what-we-do/upi/dispute-redressal-mechanism")

    return checklist


def generate_campus_advisory_bulletin(
    claimed_organization: str,
    scam_type: str,
    scammer_contacts: List[str],
    scammer_links: List[str]
) -> str:
    """
    Generates ready-to-post campus placement cell warning announcement.
    """
    contacts_str = ", ".join(scammer_contacts) if scammer_contacts else "Unverified numbers"
    links_str = ", ".join(scammer_links) if scammer_links else "Suspicious URLs"

    return f"""📢 [CAMPUS FRAUD ALERT] Beware of Fake Recruitment for '{claimed_organization}'

The Campus Placement & Cyber Defense Cell has intercepted fraudulent recruitment messages targeting students.

⚠️ Modus Operandi: {scam_type.replace('_', ' ').title()}
🚫 Suspect Contact/UPI: {contacts_str}
🚫 Suspect Domains/Links: {links_str}

CRITICAL RULES:
1. Legitimate tier-1 companies (TCS, Infosys, Wipro, Accenture, Google) NEVER demand security deposits, laptop courier fees, or exam registration charges.
2. Always cross-verify offers directly on official enterprise career portals or with the College TPO.
3. Report any suspicious approaches immediately at the Factora Safety Tech Dashboard.
"""
