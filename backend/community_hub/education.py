"""
Factora Cyber Awareness & Education Centre
Module: backend.community_hub.education
Provides in-depth educational threat intelligence modules designed for students,
job seekers, and developers, connected to live SQLite community incident patterns.
"""

from typing import List, Dict, Any, Optional
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "community_defense.db"

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


EDUCATION_TOPICS: List[Dict[str, Any]] = [
    {
        "topic_id": "recruitment_fraud",
        "title": "Fake Internships & Campus Recruitment Scams",
        "threat_vector": "recruitment_fraud",
        "icon": "briefcase",
        "color": "#F59E0B",
        "summary": "Fraudulent hiring campaigns that issue fake job offers or internships under reputed enterprise brands, demanding upfront payments for laptop bonds, training charges, or document verification.",
        "common_warning_signs": [
            "Offer letters issued on WhatsApp or Telegram with zero prior technical interview or campus recruitment drive.",
            "Demands for upfront 'Laptop Security Deposit', 'Background Verification Fee', or 'Training Registration Fee'.",
            "Communications sent from free public mailboxes (@gmail.com) or lookalike domain variations (e.g., '@tcs-careers-portal.in').",
            "Urgency tactics threatening to cancel the offer within 30 to 60 minutes if UPI payment is not completed.",
            "Promises of unusually high stipends (e.g. ₹40,000/month) for entry-level tasks requiring no prior experience."
        ],
        "sanitized_examples": [
            {
                "title": "Laptop Security Deposit Offer Letter",
                "scenario": "A student receives an email purportedly from an IT major HR department offering a software engineering internship. The email includes a forged letterhead and requests a ₹3,500 refundable security deposit for laptop dispatch to an SBI UPI ID."
            },
            {
                "title": "Zero-Interview Selection on WhatsApp",
                "scenario": "A final-year engineering student receives a direct joining letter as 'Associate Software Engineer' on WhatsApp without any technical assessment. The scammer requests ₹4,500 for onboarding portal enrollment."
            }
        ],
        "potential_consequences": [
            "Direct monetary loss via untraceable UPI or bank transfers.",
            "Identity theft through the submission of Aadhaar cards, PAN cards, and university marksheets to fake portals.",
            "Emotional distress and missed opportunities for legitimate campus placements."
        ],
        "prevention_tips": [
            "Validate with your College Training & Placement Cell (TPO) before responding to off-campus offers.",
            "Remember the Never-Pay Policy: No NASSCOM-member or legitimate IT company ever charges candidate registration, laptop deposits, or training fees.",
            "Verify official company career portals independently (e.g., tcs.com/careers, infosys.com/careers) instead of clicking emailed links."
        ],
        "recommended_actions": [
            "If funds were transferred via UPI within the past 2 hours, call national cyber helpline 1930 immediately to initiate banking freeze.",
            "Lodge a formal cyber fraud complaint on cybercrime.gov.in.",
            "Submit the suspect UPI ID, phone number, and offer document to the Factora Community Incident Reporting portal to protect peer students.",
            "Notify your college placement cell to issue a campus-wide alert."
        ]
    },
    {
        "topic_id": "phishing_impersonation",
        "title": "Phishing & Institution Email Impersonation",
        "threat_vector": "phishing",
        "icon": "envelope-open",
        "color": "#EC4899",
        "summary": "Deceptive messages designed to steal student login credentials, portal access tokens, or financial information by spoofing university IT desks, government scholarship portals, or official exams.",
        "common_warning_signs": [
            "Emails claiming 'Institutional Mailbox Quota Exceeded' or 'Account Will Be Terminated in 24 Hours'.",
            "Links directing to spoofed Microsoft 365, Google Workspace, or college LMS login portals.",
            "SMS or WhatsApp blasts claiming pending scholarship or DBT disbursements requiring an immediate 'processing fee'.",
            "Generic salutations like 'Dear Student' or 'Valued Customer' lacking personal enrollment details.",
            "Misspelled sender domains or domain extensions ending in .site, .top, .online, or .cc."
        ],
        "sanitized_examples": [
            {
                "title": "Campus Webmail Quota Warning",
                "scenario": "An email claiming to be 'Campus IT Support' informs students that their cloud storage is full and will be deleted unless they log in via a linked portal (e.g., 'campus-owa-login.com') to upgrade quota."
            },
            {
                "title": "National Scholarship DBT Disbursal SMS",
                "scenario": "An SMS blast claiming a ₹25,000 government scholarship disbursal is pending, requesting the recipient to click a link and pay a ₹1,500 verification fee."
            }
        ],
        "potential_consequences": [
            "Compromised institutional email accounts used to send spam or attack other students.",
            "Loss of access to internal university portals, exam registrations, and grading systems.",
            "Unauthorized access to personal documents, research work, or private cloud storage."
        ],
        "prevention_tips": [
            "Always inspect the sender's full email address, not just the display name.",
            "Never enter login credentials on non-institutional domains.",
            "Enable Two-Factor Authentication (2FA/MFA) on all university and email accounts using authenticator apps."
        ],
        "recommended_actions": [
            "Immediately change your account password and invalidate active web sessions.",
            "Contact your college IT administrator to flag the phishing domain on campus firewalls.",
            "Report the spoofed domain to National Cyber Crime Reporting Portal (cybercrime.gov.in) and CERT-In (incident@cert-in.org.in)."
        ]
    },
    {
        "topic_id": "financial_scam",
        "title": "Financial Scams & Telegram Task Fraud",
        "threat_vector": "financial_scam",
        "icon": "coins",
        "color": "#EF4444",
        "summary": "Part-time job fraud and investment lures that promise quick returns for simple online tasks (e.g., liking YouTube videos, reviewing hotels) before trapping victims in escalating recharge tiers.",
        "common_warning_signs": [
            "Unsolicited messages on WhatsApp or Telegram offering ₹1,500–₹5,000 per day for 'work from home' tasks.",
            "Small initial payments (₹150–₹300) credited to the student's bank account to build false trust.",
            "Sudden demand to transfer 'VIP prepaid task deposit' or 'cryptocurrency security funds' to unlock higher earnings.",
            "Refusal to allow withdrawals until additional 'system repair fees' or 'tax clearance charges' are paid.",
            "Administrators communicating exclusively through encrypted Telegram groups with pseudonymous handles."
        ],
        "sanitized_examples": [
            {
                "title": "YouTube Video Like & Subscribe Scam",
                "scenario": "A student receives ₹200 for screenshotting 3 subscribed YouTube channels. The Telegram manager then directs the student to invest ₹2,000 for a guaranteed ₹3,500 return, followed by demands for ₹10,000 and ₹50,000."
            },
            {
                "title": "Google Maps Hotel Review Task Trap",
                "scenario": "Promised ₹50 per review, the student is migrated to a fake investment portal displaying fictitious wallet balances that require real money transfers to withdraw."
            }
        ],
        "potential_consequences": [
            "Severe financial loss, often draining student savings or borrowed funds.",
            "Student accounts flagged as accomplice mule accounts by banks during cyber police crackdowns.",
            "Continuous extortion and harassment from anonymous Telegram group operators."
        ],
        "prevention_tips": [
            "Recognize that genuine corporations never pay retail workers through Telegram bots or UPI recharges.",
            "Refuse any task scheme that requires paying money in order to receive earned money.",
            "Exit and report unsolicited Telegram groups promising quick investment or trading yields."
        ],
        "recommended_actions": [
            "Stop all communications and refuse any further recharge or withdrawal fee demands.",
            "Dial 1930 within the Golden Hour window to report suspect UPI receiver handles to the National Cybercrime Reporting Portal.",
            "Inform your bank manager to monitor your account against suspicious reverse chargebacks."
        ]
    },
    {
        "topic_id": "suspicious_urls",
        "title": "Suspicious Websites & Domain Spoofing",
        "threat_vector": "website_impersonation",
        "icon": "globe",
        "color": "#3B82F6",
        "summary": "Lookalike websites, fake universities, and typosquatted domains engineered to mimic legitimate educational institutions, government portals, or corporate recruiting gateways.",
        "common_warning_signs": [
            "Domains using hyphens, typos, or abnormal extensions (e.g., 'tcs-careers-portal.in', 'begc-degree.edu.in', 'infosys-campusdrive.online').",
            "Websites registered just a few days or weeks ago according to WHOIS records.",
            "Institutions offering accredited B.Tech or MBA degrees without mandatory entrance tests or classroom attendance.",
            "Absence of official AICTE approval or appearance on the official UGC Fake Universities Public Notice.",
            "Official application forms hosted on free services like Google Forms, Tally.so, or Typeform."
        ],
        "sanitized_examples": [
            {
                "title": "UGC Unrecognized Fake University Portal",
                "scenario": "An agent claims a backdated engineering degree can be obtained for ₹12,000 without attending classes. The university name matches the official University Grants Commission (UGC) list of 20+ fake institutions."
            },
            {
                "title": "Cloned Enterprise Careers Intake Site",
                "scenario": "A website replicating the corporate color scheme and logos of a leading IT consultancy prompts students to submit government IDs and pay ₹500 for a hall ticket."
            }
        ],
        "potential_consequences": [
            "Acquiring fraudulent degrees that are invalid for employment or higher studies, leading to termination.",
            "Exposure of identity documents (PAN, Aadhaar) on insecure servers for identity theft.",
            "Financial loss without any legitimate service rendered."
        ],
        "prevention_tips": [
            "Cross-verify academic institutions against the official UGC Fake University List (ugc.ac.in).",
            "Verify college accreditation on the official AICTE web portal (aicte-india.org).",
            "Check domain registration age using legitimate WHOIS lookup services before trusting new portals."
        ],
        "recommended_actions": [
            "Report fraudulent universities to the UGC Vigilance Cell (ugc.ac.in/vigilance).",
            "File an impersonation report on ScamAdviser and CyberCrime.gov.in.",
            "Share the spoofed domain URL on the Factora Threat Search engine to cross-reference related complaints."
        ]
    },
    {
        "topic_id": "github_repo_risks",
        "title": "GitHub Repository & Software Supply-Chain Risks",
        "threat_vector": "github_repo_risk",
        "icon": "code-branch",
        "color": "#8B5CF6",
        "summary": "Malicious code repositories and typosquatted dependencies distributed as technical hiring assignments or open-source libraries that execute malware upon installation.",
        "common_warning_signs": [
            "Candidate coding tests hosted on newly created, unverified GitHub accounts with zero commit history.",
            "Repositories requiring candidate to run 'npm install', 'pip install', or execute binary bash scripts before starting.",
            "Hidden 'postinstall' or 'preinstall' scripts in package.json downloading remote payloads (e.g. cross-env-stealer).",
            "Presence of obfuscated Base64 strings or child_process executions in dependency configuration files.",
            "Invitations to collaborate on private repositories from recruiters who insist on running code on your primary machine."
        ],
        "sanitized_examples": [
            {
                "title": "Candidate Assessment Info-Stealer Hook",
                "scenario": "A recruiter sends a GitHub link for a 'Full-Stack Take-Home Test'. Inside package.json, an obfuscated postinstall hook silently exfiltrates Chrome saved passwords and Discord/GitHub tokens to an external server."
            },
            {
                "title": "Typosquatted Package in Coding Assessment",
                "scenario": "A Python coding challenge references a dependency named 'node-fetch-override' or a typosquatted 'reqeusts' module that establishes a reverse shell upon import."
            }
        ],
        "potential_consequences": [
            "Total machine compromise, leading to extraction of SSH keys, crypto wallets, and browser session cookies.",
            "Compromise of developer GitHub accounts, leading to malicious commits injected into open-source projects.",
            "Ransomware encryption or deployment of persistent background miners."
        ],
        "prevention_tips": [
            "Always inspect package.json, setup.py, or requirements.txt BEFORE running package managers.",
            "Open candidate test repositories inside VS Code with Workspace Trust DISABLED or in an isolated VM / Docker container.",
            "Use secure developer tools like GitHub CodeQL and npm audit to detect malicious script hooks."
        ],
        "recommended_actions": [
            "Kill all running node/python processes and disconnect your machine from the local network.",
            "Revoke and rotate all GitHub personal access tokens (PAT), SSH keys, and stored browser passwords.",
            "Report the malicious repository to GitHub Support (github.com/contact/report-abuse).",
            "Add the repository URL to the Factora Community Threat Feed to alert peer developers."
        ]
    },
    {
        "topic_id": "account_compromise",
        "title": "Social Engineering & Money Mule Lures",
        "threat_vector": "account_compromise",
        "icon": "shield-halved",
        "color": "#10B981",
        "summary": "Recruitment of students to receive, hold, or forward illicit funds through personal UPI, Google Pay, or bank accounts in exchange for cash commissions, leading to frozen accounts and legal liability.",
        "common_warning_signs": [
            "Offers paying ₹500–₹1,000 per transaction to 'rent' your personal bank account, UPI VPA, or ATM debit card.",
            "Claims that an online foreign exchange or gaming platform needs 'local student collection agents'.",
            "Requests to withdraw received cash from ATMs and deposit it into cash deposit machines (CDM).",
            "Urgent pleas from online friends or acquaintances to receive emergency funds and forward via Google Pay.",
            "Account suddenly being blocked with a 'Cyber Police Lien' or Section 91 CrPC notice from law enforcement."
        ],
        "sanitized_examples": [
            {
                "title": "Campus Crypto Exchange Account Rental",
                "scenario": "A student is offered ₹1,000 per week to allow an online group to receive payments on their personal PhonePe. Days later, the student's SBI account is frozen under an FIR involving ₹5 lakh stolen from an extorted victim in another state."
            },
            {
                "title": "Commission-Based Task Fund Forwarding",
                "scenario": "A part-time job lures students into receiving daily UPI deposits and forwarding 90% onward while keeping 10% as commission. All accounts in the chain are subsequently frozen under 1930 Cyber Cell orders."
            }
        ],
        "potential_consequences": [
            "Freezing of all personal bank accounts across all banks under national CFCFRMS cyber policing protocols.",
            "Severe CIBIL/credit rating destruction and blacklisting from future banking and loan facilities.",
            "Criminal prosecution under IPC / Bharatiya Nyaya Sanhita and the Information Technology Act as an accomplice to financial fraud."
        ],
        "prevention_tips": [
            "Strictly NEVER allow anyone to receive or route money through your personal bank, UPI, or crypto wallet.",
            "Never share your ATM card, PIN, net banking credentials, or UPI MPIN with any third party.",
            "Treat any request to handle money for strangers as an immediate warning of criminal money laundering."
        ],
        "recommended_actions": [
            "Contact your bank branch manager immediately if you suspect your account has been used as an unwitting money mule.",
            "File a voluntary disclosure statement with the nearest Cyber Crime Police Station or via cybercrime.gov.in explaining that you were manipulated.",
            "Never attempt to withdraw or spend funds that were mistakenly or illicitly credited to your account."
        ]
    }
]


def get_all_education_topics() -> List[Dict[str, Any]]:
    """Returns all 6 educational modules augmented with live SQLite community incident counts."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        enriched_topics = []

        for topic in EDUCATION_TOPICS:
            t_copy = dict(topic)
            vector = topic["threat_vector"]

            # Query real incident stats from the database
            cursor.execute("""
                SELECT 
                    COUNT(*) as report_count,
                    COALESCE(SUM(amount_demanded_or_lost_inr), 0.0) as total_loss,
                    COALESCE(SUM(CASE WHEN verification_status = 'Corroborated' THEN 1 ELSE 0 END), 0) as corroborated_count
                FROM victim_reports
                WHERE category = ? OR scam_type = ?
            """, (vector, vector))
            row = cursor.fetchone()

            report_count = row["report_count"] if row else 0
            total_loss = float(row["total_loss"]) if row else 0.0
            corroborated_count = row["corroborated_count"] if row else 0

            # Fetch up to 2 real anonymized sample incident titles
            cursor.execute("""
                SELECT incident_ref, incident_title, reported_at, amount_demanded_or_lost_inr
                FROM victim_reports
                WHERE category = ? OR scam_type = ?
                ORDER BY id DESC
                LIMIT 2
            """, (vector, vector))
            sample_rows = cursor.fetchall()
            samples = [
                {
                    "incident_ref": r["incident_ref"],
                    "incident_title": r["incident_title"],
                    "reported_at": r["reported_at"],
                    "amount_lost": float(r["amount_demanded_or_lost_inr"])
                }
                for r in sample_rows
            ]

            t_copy["live_community_stats"] = {
                "community_reports_count": report_count,
                "total_monetary_loss_inr": total_loss,
                "corroborated_incidents_count": corroborated_count,
                "recent_incident_samples": samples
            }
            enriched_topics.append(t_copy)

        return enriched_topics
    finally:
        conn.close()


def get_education_topic_by_id(topic_id: str) -> Optional[Dict[str, Any]]:
    """Returns a single educational module enriched with real-time database telemetry."""
    topics = get_all_education_topics()
    for t in topics:
        if t["topic_id"] == topic_id:
            return t
    return None
