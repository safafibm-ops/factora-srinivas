"""

Factora Member 3: Community Victim Database Storage & Aggregate Engine

Provides persistent SQLite storage for student scam reports, cumulative INR financial loss calculations,

category breakdowns, trending threat indicators, and community alerts.

"""

import sqlite3

import json

import os

import math

from datetime import datetime, timedelta

from typing import List, Dict, Any, Optional, Tuple

from pathlib import Path

DB_FILE = Path(os.getenv("FACTORA_COMMUNITY_DB_PATH", str(Path(__file__).resolve().parent / "community_defense.db"))).expanduser()

_DB_INITIALIZED = False

# Six official threat categories

OFFICIAL_CATEGORIES = {

    "recruitment_fraud": {

        "id": "recruitment_fraud",

        "name": "Recruitment & Internship Fraud",

        "icon": "briefcase",

        "color": "#F59E0B", # amber

        "description": "Fake offer letters, laptop security deposits, and unvetted campus drives."

    },

    "financial_scam": {

        "id": "financial_scam",

        "name": "Financial Scams",

        "icon": "currency-rupee",

        "color": "#EF4444", # red

        "description": "Telegram YouTube tasks, rating scams, and upfront registration bonds."

    },

    "github_repo_risk": {

        "id": "github_repo_risk",

        "name": "GitHub Repository & Package Risks",

        "icon": "code-bracket",

        "color": "#8B5CF6", # purple

        "description": "Malicious coding test repositories with obfuscated postinstall token stealers."

    },

    "website_impersonation": {

        "id": "website_impersonation",

        "name": "Website Impersonation",

        "icon": "globe-alt",

        "color": "#3B82F6", # blue

        "description": "Spoofed enterprise career portals, UGC fake universities, and lookalike domains."

    },

    "phishing": {

        "id": "phishing",

        "name": "Phishing",

        "icon": "envelope-open",

        "color": "#EC4899", # pink

        "description": "Campus email credential harvesting, fake placement registration forms, and SMS links."

    },

    "account_compromise": {

        "id": "account_compromise",

        "name": "Account Compromise",

        "icon": "shield-exclamation",

        "color": "#10B981", # emerald

        "description": "Student bank account and UPI money mule recruiting, leading to police freezes."

    }

}

def map_to_official_category(scam_type: str) -> str:

    """Normalizes any scam type into one of the 6 official threat categories."""

    st = scam_type.lower()

    if any(k in st for k in ["laptop", "interview", "bond", "recruitment", "internship", "placement"]):

        return "recruitment_fraud"

    elif any(k in st for k in ["task", "financial", "crypto", "rating", "earn"]):

        return "financial_scam"

    elif any(k in st for k in ["github", "repo", "npm", "pip", "package", "code"]):

        return "github_repo_risk"

    elif any(k in st for k in ["impersonation", "spoof", "ugc", "domain", "portal", "fake_uni"]):

        return "website_impersonation"

    elif any(k in st for k in ["phish", "email", "sms", "credential"]):

        return "phishing"

    elif any(k in st for k in ["mule", "compromise", "takeover", "laundering"]):

        return "account_compromise"

    return "recruitment_fraud"

def get_db_connection() -> sqlite3.Connection:

    """Connects to SQLite with robust settings for Windows/OneDrive environments."""

    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE), timeout=10.0, check_same_thread=False)

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=MEMORY;")

    conn.execute("PRAGMA busy_timeout=5000;")

    return conn

def init_db():

    """Initializes the SQLite schema; demo fixtures are seeded only by explicit opt-in."""

    global _DB_INITIALIZED

    if _DB_INITIALIZED:

        return

    conn = get_db_connection()

    try:

        with conn:

            cursor = conn.cursor()

            cursor.execute("""

            CREATE TABLE IF NOT EXISTS victim_reports (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                incident_ref TEXT UNIQUE NOT NULL,

                incident_title TEXT NOT NULL,

                claimed_organization TEXT NOT NULL,

                scam_type TEXT NOT NULL,

                category TEXT NOT NULL DEFAULT 'recruitment_fraud',

                campaign_name TEXT DEFAULT NULL,

                verification_status TEXT NOT NULL DEFAULT 'Corroborated',

                amount_demanded_or_lost_inr REAL NOT NULL DEFAULT 0.0,

                scammer_contacts TEXT NOT NULL,      -- JSON list of strings (phone, UPI, email)

                scammer_links TEXT NOT NULL,         -- JSON list of strings (urls, domains, repos)

                description TEXT NOT NULL,

                evidence_filenames TEXT NOT NULL,    -- JSON list of filenames

                is_verified INTEGER NOT NULL DEFAULT 1,

                reported_at TEXT NOT NULL,
                data_source TEXT NOT NULL DEFAULT 'community'

            );

            """)

            cursor.execute("""

            CREATE INDEX IF NOT EXISTS idx_victim_org ON victim_reports (claimed_organization);

            """)

            cursor.execute("""

            CREATE INDEX IF NOT EXISTS idx_victim_scam_type ON victim_reports (scam_type);

            """)

            cursor.execute("""

            CREATE INDEX IF NOT EXISTS idx_victim_category ON victim_reports (category);

            """)

            # Schema migration in case columns don't exist in existing DB

            cursor.execute("PRAGMA table_info(victim_reports)")

            columns = [row["name"] for row in cursor.fetchall()]

            if "category" not in columns:

                cursor.execute("ALTER TABLE victim_reports ADD COLUMN category TEXT NOT NULL DEFAULT 'recruitment_fraud'")

            if "campaign_name" not in columns:

                cursor.execute("ALTER TABLE victim_reports ADD COLUMN campaign_name TEXT DEFAULT NULL")

            if "verification_status" not in columns:

                cursor.execute("ALTER TABLE victim_reports ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'Corroborated'")

            if "user_pseudonym" not in columns:

                cursor.execute("ALTER TABLE victim_reports ADD COLUMN user_pseudonym TEXT DEFAULT 'student-sentinel-anon'")

            if "financial_loss_occurred" not in columns:

                cursor.execute("ALTER TABLE victim_reports ADD COLUMN financial_loss_occurred INTEGER DEFAULT 0")

            if "official_complaint_filed" not in columns:

                cursor.execute("ALTER TABLE victim_reports ADD COLUMN official_complaint_filed INTEGER DEFAULT 0")

            if "complaint_ack_ref" not in columns:

                cursor.execute("ALTER TABLE victim_reports ADD COLUMN complaint_ack_ref TEXT DEFAULT NULL")

            if "suspicious_url_or_domain" not in columns:

                cursor.execute("ALTER TABLE victim_reports ADD COLUMN suspicious_url_or_domain TEXT DEFAULT NULL")

            if "github_repo_link" not in columns:

                cursor.execute("ALTER TABLE victim_reports ADD COLUMN github_repo_link TEXT DEFAULT NULL")

            if "data_source" not in columns:
                cursor.execute("ALTER TABLE victim_reports ADD COLUMN data_source TEXT NOT NULL DEFAULT 'community'")

            # The original demo seeder used a fixed pseudonym; keep those fixtures
            # out of live student report feeds while retaining them for mock workflows.
            cursor.execute("UPDATE victim_reports SET data_source = 'demo' WHERE user_pseudonym = 'student-sentinel-anon' AND data_source = 'community'")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_victim_user_pseudonym ON victim_reports (user_pseudonym);")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_victim_status ON victim_reports (verification_status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_victim_live_window ON victim_reports (data_source, reported_at);")

            # Check if baseline seeding is needed

            cursor.execute("SELECT COUNT(*) AS cnt FROM victim_reports")

            row = cursor.fetchone()

            if row["cnt"] == 0 and os.getenv("FACTORA_SEED_DEMO_DATA", "false").strip().lower() == "true":

                seed_baseline_reports(cursor)

        _DB_INITIALIZED = True

    finally:

        conn.close()

def seed_baseline_reports(cursor: sqlite3.Cursor):

    """Seeds verified student scam incidents across all 6 threat categories."""

    seed_data = [

        # Category 1: Recruitment & Internship Fraud

        (

            "COMM-REPORT-TCS-9021",

            "TCS National Qualifier Test Laptop Security Deposit Scam",

            "Tata Consultancy Services (TCS)",

            "laptop_security_deposit",

            "recruitment_fraud",

            "GhostRecruiter Syndicate #4",

            "Corroborated",

            3500.0,

            json.dumps(["+919876543210", "tcs.hrverification@oksbi", "hr-onboarding@tcs-careers-portal.in", "tcsrecruitmentindia@gmail.com"]),

            json.dumps(["https://bit.ly/tcs-national-campus-internship", "https://tcs-careers-portal.in/register", "tcs-careers-portal.in", "bit.ly"]),

            "Student from Srinivas Inst transferred Rs. 3,500 for laptop dispatch deposit; contact was blocked immediately after UPI receipt was shared.",

            json.dumps(["tcs_offer_letter_fake.pdf", "upi_payment_screenshot.jpg"]),

            1,

            "2026-10-31 14:32:00"

        ),

        (

            "COMM-REPORT-TCS-9022",

            "Fake TCS NextStep Direct Selection Offer",

            "Tata Consultancy Services (TCS)",

            "laptop_security_deposit",

            "recruitment_fraud",

            "GhostRecruiter Syndicate #4",

            "Corroborated",

            3500.0,

            json.dumps(["tcs.hrverification@oksbi", "+919876543210"]),

            json.dumps(["https://tcs-careers-portal.in", "tcs-careers-portal.in"]),

            "Offer letter received on Telegram with TCS letterhead signed by fake HR director, demanding Rs. 3,500 registration deposit within 30 minutes.",

            json.dumps(["telegram_hr_chat.png"]),

            1,

            "2026-10-30 11:15:00"

        ),

        (

            "COMM-REPORT-INFY-4102",

            "Infosys Direct Joining Letter Training Bond Fraud",

            "Infosys Limited",

            "training_bond_deposit",

            "recruitment_fraud",

            "GhostRecruiter Syndicate #4",

            "Corroborated",

            5000.0,

            json.dumps(["+919876543210", "infy.onboarding@icici", "careers-infosys@gmail.com"]),

            json.dumps(["https://infosys-campusdrive.online", "infosys-campusdrive.online"]),

            "Received direct selection letter without any coding round. Demanded Rs. 5,000 document verification fee refundable upon joining Mysore campus.",

            json.dumps(["infy_fake_bond_doc.pdf"]),

            1,

            "2026-10-28 16:45:00"

        ),

        (

            "COMM-REPORT-WIPRO-1108",

            "Wipro Campus Laptop Courier Charge Scam",

            "Wipro Technologies",

            "laptop_security_deposit",

            "recruitment_fraud",

            "ApexPlacement Phishing Ring",

            "Investigating",

            4200.0,

            json.dumps(["+919123456780", "wipro.courierverification@okhdfcbank"]),

            json.dumps(["https://wipro-campus-careers.in", "wipro-campus-careers.in"]),

            "Fake HR phone call with official-looking PDF letterhead asking for Rs. 4,200 courier clearance fee.",

            json.dumps(["wipro_receipt.jpg"]),

            1,

            "2026-10-27 10:20:00"

        ),

        # Category 2: Financial Scams

        (

            "COMM-REPORT-TASK-8812",

            "Amazon VIP YouTube Review & Subscribe Part-Time Task Scam",

            "Amazon Digital Ads",

            "task_scam",

            "financial_scam",

            "GlobalTask-VIP-Syndicate",

            "Corroborated",

            18500.0,

            json.dumps(["+918765432109", "taskpay2026@paytm", "@amazon_vip_task_manager"]),

            json.dumps(["https://t.me/amazon_parttime_jobs_2026", "amazon-vip-earn.cc"]),

            "Paid Rs. 1,000 got Rs. 1,300 back on Telegram task. Then deposited Rs. 18,500 for VIP Tier 2 task, after which admin locked account demanding Rs. 50,000 tax.",

            json.dumps(["task_dashboard_frozen.png", "telegram_task_log.pdf"]),

            1,

            "2026-10-31 18:05:00"

        ),

        (

            "COMM-REPORT-TASK-8813",

            "Google Maps Rating Work-From-Home Task Scam",

            "ReviewMedia Solutions",

            "task_scam",

            "financial_scam",

            "GlobalTask-VIP-Syndicate",

            "Corroborated",

            12000.0,

            json.dumps(["taskpay2026@paytm", "+918765432109"]),

            json.dumps(["https://t.me/google_maps_ratings_india"]),

            "Scammer invited via WhatsApp to review local businesses for Rs. 150 per review; transitioned to crypto tasks demanding upfront deposit.",

            json.dumps(["telegram_payment_flow.png"]),

            1,

            "2026-10-29 15:00:00"

        ),

        # Category 3: GitHub Repository & Package Risks

        (

            "COMM-REPORT-REPO-1105",

            "Accenture Recruitment Assessment Trojan Repository",

            "Accenture India",

            "github_malware_assessment",

            "github_repo_risk",

            "CodeStealer Trojan Campaign",

            "Corroborated",

            0.0,

            json.dumps(["accenture.technicalrounds@gmail.com", "+919765432198"]),

            json.dumps(["https://github.com/accenture-recruitment-round/frontend-assessment-2026", "github.com"]),

            "Student instructed to clone GitHub repo for online coding round. Review showed obfuscated postinstall hook stealing Chrome cookies & Discord tokens.",

            json.dumps(["package_json_hook.png", "malicious_script.js"]),

            1,

            "2026-10-29 20:10:00"

        ),

        (

            "COMM-REPORT-REPO-1106",

            "Campus Hiring Backend Challenge Backdoored NPM Package",

            "FinTech Labs",

            "github_repo_risk",

            "github_repo_risk",

            "CodeStealer Trojan Campaign",

            "Investigating",

            0.0,

            json.dumps(["dev-assessment@fintech-hiring.org"]),

            json.dumps(["https://github.com/fintech-campus-tests/node-payment-service", "cross-env-stealer"]),

            "Candidate challenge included typosquatted npm package 'cross-env-stealer' exfiltrating AWS keys and SSH credentials upon 'npm test'.",

            json.dumps(["package_lock_audit.txt"]),

            1,

            "2026-10-25 12:40:00"

        ),

        # Category 4: Website Impersonation

        (

            "COMM-REPORT-UGC-3301",

            "UGC Fake University Direct B.Tech Degree Certificate Scam",

            "Bio-Chemic Education Grant Commission",

            "ugc_fake_uni",

            "website_impersonation",

            "DiplomaMill Academic Syndicate",

            "Corroborated",

            12000.0,

            json.dumps(["admissions@begc-degree.edu.in", "begc.education@sbi", "+919345678901"]),

            json.dumps(["http://begc-degree.edu.in", "begc-degree.edu.in"]),

            "Agent offered backdated diploma and marksheet for Rs. 12,000 without exams. Institution matches official UGC 2026 Fake Universities Public Notice.",

            json.dumps(["ugc_fake_prospectus.pdf"]),

            1,

            "2026-10-26 13:00:00"

        ),

        (

            "COMM-REPORT-DOM-5510",

            "Infosys NextGen Careers Cloned Portal",

            "Infosys Limited",

            "website_impersonation",

            "website_impersonation",

            "GhostRecruiter Syndicate #4",

            "Corroborated",

            4500.0,

            json.dumps(["infy.onboarding@icici", "+919876543210"]),

            json.dumps(["https://infosys-campusdrive.online", "infosys-campusdrive.online"]),

            "Spoofed corporate intake portal replicating Infosys NextGen branding; collects student Aadhaar and PAN documents before demanding registration fee.",

            json.dumps(["cloned_portal_screen.png"]),

            1,

            "2026-10-31 09:30:00"

        ),

        # Category 5: Phishing

        (

            "COMM-REPORT-PHISH-2201",

            "College Mailbox Quota Exceeded Phishing Alert",

            "Campus IT Helpdesk Impersonation",

            "phishing",

            "phishing",

            "CampusHarvest Credential Phishing",

            "Corroborated",

            0.0,

            json.dumps(["admin-notice@campus-owa-login.com"]),

            json.dumps(["https://campus-owa-login.com/auth/login", "campus-owa-login.com"]),

            "Targeted email sent to engineering students claiming institutional email will be suspended in 24 hours. Links to fake Microsoft Outlook login page.",

            json.dumps(["phishing_email.eml", "fake_owa_login.png"]),

            1,

            "2026-10-30 08:45:00"

        ),

        (

            "COMM-REPORT-PHISH-2202",

            "State Scholarship Portal SMS Credential Phishing",

            "National Scholarship Portal (Impersonation)",

            "phishing",

            "phishing",

            "ScholarshipTrap SMS Ring",

            "Investigating",

            1500.0,

            json.dumps(["+919654321098", "scholarship-verify@paytm"]),

            json.dumps(["https://scholarship-gov-in-update.site", "scholarship-gov-in-update.site"]),

            "SMS blast sent to students claiming pending DBT disbursement of Rs. 25,000 requiring Rs. 1,500 KYC renewal charge.",

            json.dumps(["sms_screenshot.jpg"]),

            1,

            "2026-10-29 17:10:00"

        ),

        # Category 6: Account Compromise

        (

            "COMM-REPORT-MULE-7721",

            "CryptoPay Campus Student Bank Account Money Mule Request",

            "CryptoPay Global Exchange",

            "mule_account_request",

            "account_compromise",

            "MuleHarvest Syndicate #9",

            "Corroborated",

            8000.0,

            json.dumps(["+917890123456", "@cryptopay_support_bot"]),

            json.dumps(["https://cryptopay-earning.org", "cryptopay-earning.org"]),

            "Offered Rs. 500 commission per transaction to receive money into student SBI account and forward via UPI. Account frozen by Cyber Police under 1930 FIR.",

            json.dumps(["bank_lien_notice.jpg"]),

            1,

            "2026-10-29 17:30:00"

        ),

        (

            "COMM-REPORT-MULE-7722",

            "Student UPI VPA Laundering Syndicate (Commission Trap)",

            "Apex Remit Solutions",

            "account_compromise",

            "account_compromise",

            "MuleHarvest Syndicate #9",

            "Corroborated",

            15000.0,

            json.dumps(["+917890123456", "apexremit@ybl"]),

            json.dumps(["https://apex-remit.net"]),

            "Telegram bot lured students into renting their personal GPay / PhonePe VPAs. Recipient transfers flagged as cyber extortion proceeds.",

            json.dumps(["police_notice_letter.pdf"]),

            1,

            "2026-10-31 16:15:00"

        )

    ]

    cursor.executemany("""

    INSERT INTO victim_reports (

        incident_ref, incident_title, claimed_organization, scam_type,

        category, campaign_name, verification_status,

        amount_demanded_or_lost_inr, scammer_contacts, scammer_links,

        description, evidence_filenames, is_verified, reported_at

    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, seed_data)

    cursor.execute("UPDATE victim_reports SET data_source = 'demo' WHERE incident_ref LIKE 'COMM-REPORT-%'")

def mask_contact(contact: str) -> str:

    """

    Masks private identifiers (phone numbers, personal emails, UPI VPAs, Telegram handles)

    to prevent public exposure of sensitive victim or suspect details.

    """

    if not contact:

        return ""

    contact = contact.strip()

    digits = "".join(c for c in contact if c.isdigit())

    if len(digits) >= 10:

        # e.g. +919876543210 -> +9198765*****

        return contact[:-5] + "*****" if len(contact) > 5 else "*****"

    if contact.startswith("@"):

        # Telegram handle, e.g. @amazon_vip_task_manager -> @am***

        handle = contact[1:]

        return "@" + (handle[:2] + "***" if len(handle) > 2 else handle + "***")

    if "@" in contact:

        parts = contact.split("@", 1)

        user, domain = parts[0], parts[1]

        if not user:

            return f"***@{domain}"

        masked_user = user[:2] + "***" if len(user) > 2 else user[0] + "***"

        return f"{masked_user}@{domain}"

    return contact

def generate_pseudonym() -> str:

    """Generates a privacy-preserving pseudonymous handle for student submitters."""

    import random

    import uuid

    prefixes = ["student", "campus", "scholar", "coder", "peer", "cyber", "campus"]

    roles = ["guardian", "sentinel", "defender", "watcher", "scout", "ranger"]

    return f"{random.choice(prefixes)}-{random.choice(roles)}-{uuid.uuid4().hex[:4]}"

def add_victim_report(

    incident_title: str,

    claimed_organization: Optional[str] = None,

    scam_type: str = "recruitment_fraud",

    amount_demanded_or_lost_inr: float = 0.0,

    scammer_contacts: Optional[List[str]] = None,

    scammer_links: Optional[List[str]] = None,

    description: str = "",

    evidence_filenames: Optional[List[str]] = None,

    user_pseudonym: Optional[str] = None,

    financial_loss_occurred: bool = False,

    suspicious_url_or_domain: Optional[str] = None,

    github_repo_link: Optional[str] = None,

    official_complaint_filed: bool = False,

    complaint_ack_ref: Optional[str] = None,

    verification_status: str = "SUBMITTED"

) -> Tuple[str, int, str, str]:

    """

    Saves a student incident report to the database with pseudonymous attribution,

    validation, and initial 'SUBMITTED' verification status.

    Returns (incident_ref, row_id, user_pseudonym, verification_status).

    """

    init_db()

    conn = get_db_connection()

    try:

        with conn:

            cursor = conn.cursor()

            # Ensure clean claimed_organization (never automatically branded as fraudulent)

            org_name = (claimed_organization or "Unspecified Entity").strip()

            org_tag = "".join(c for c in org_name if c.isalnum()).upper()[:4] or "CYBER"

            import uuid

            rand_suffix = uuid.uuid4().hex[:6].upper()

            incident_ref = f"COMM-2026-{org_tag}-{rand_suffix}"

            # Normalise and validate threat category

            category = map_to_official_category(scam_type)

            # Assign or generate pseudonym

            pseudonym = (user_pseudonym or "").strip()

            if not pseudonym or pseudonym == "anonymous":

                pseudonym = generate_pseudonym()

            # Aggregate links and contacts

            all_links = list(scammer_links or [])

            if suspicious_url_or_domain and suspicious_url_or_domain.strip():

                all_links.append(suspicious_url_or_domain.strip())

            if github_repo_link and github_repo_link.strip():

                all_links.append(github_repo_link.strip())

            # Deduplicate links preserving order

            seen_links = set()

            dedup_links = []

            for l in all_links:

                if l and l not in seen_links:

                    seen_links.add(l)

                    dedup_links.append(l)

            # Enforce financial loss rule: if loss did not occur, amount is 0.0

            actual_loss = float(amount_demanded_or_lost_inr) if financial_loss_occurred else 0.0

            cursor.execute("""

            INSERT INTO victim_reports (

                incident_ref, incident_title, claimed_organization, scam_type,

                category, campaign_name, verification_status,

                amount_demanded_or_lost_inr, scammer_contacts, scammer_links,

                description, evidence_filenames, is_verified, reported_at,

                user_pseudonym, financial_loss_occurred, official_complaint_filed,

                complaint_ack_ref, suspicious_url_or_domain, github_repo_link

            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

            """, (

                incident_ref,

                incident_title.strip(),

                org_name,

                scam_type,

                category,

                "Under Automated Correlation",

                verification_status, # Initial status SUBMITTED per requirements

                actual_loss,

                json.dumps(scammer_contacts or []),

                json.dumps(dedup_links),

                description.strip(),

                json.dumps(evidence_filenames or []),

                0, # Unverified community submission

                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

                pseudonym,

                1 if financial_loss_occurred else 0,

                1 if official_complaint_filed else 0,

                (complaint_ack_ref or "").strip() or None,

                (suspicious_url_or_domain or "").strip() or None,

                (github_repo_link or "").strip() or None

            ))

            row_id = cursor.lastrowid

            return incident_ref, row_id, pseudonym, verification_status

    finally:

        conn.close()

def get_user_submitted_reports(pseudonym: str) -> List[Dict[str, Any]]:

    """

    Retrieves all reports submitted under a specific pseudonymous public identifier.

    Allows students to track their submissions and see updated verification statuses.

    """

    if not pseudonym:

        return []

    init_db()

    conn = get_db_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""

        SELECT * FROM victim_reports

        WHERE user_pseudonym = ?

        ORDER BY id DESC

        """, (pseudonym.strip(),))

        rows = cursor.fetchall()

        reports = []

        for r in rows:

            d = dict(r)

            d["scammer_contacts"] = json.loads(d.get("scammer_contacts") or "[]")

            d["scammer_links"] = json.loads(d.get("scammer_links") or "[]")

            d["evidence_filenames"] = json.loads(d.get("evidence_filenames") or "[]")

            cat_meta = OFFICIAL_CATEGORIES.get(d.get("category", "recruitment_fraud"), {

                "name": (d.get("category") or "recruitment_fraud").replace("_", " ").title(),

                "color": "#6B7280"

            })

            d["category_name"] = cat_meta["name"]

            d["category_color"] = cat_meta.get("color", "#6B7280")

            reports.append(d)

        return reports

    finally:

        conn.close()

def get_dashboard_statistics() -> Dict[str, Any]:

    """

    Returns live statistics computed directly from the database:

    - total_submitted_incidents

    - newly_reported_incidents (last 7 days)

    - corroborated_reports

    - potential_threat_campaigns

    - active_community_alerts

    - total_financial_loss_inr

    """

    init_db()

    conn = get_db_connection()

    try:

        cursor = conn.cursor()

        period_start = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            SELECT COUNT(*) AS total_incidents,
                   COALESCE(SUM(CASE WHEN financial_loss_occurred = 1 THEN amount_demanded_or_lost_inr ELSE 0 END), 0.0) AS total_lost_inr,
                   SUM(CASE WHEN UPPER(verification_status) IN ('CORROBORATED', 'CONFIRMED') OR is_verified = 1 THEN 1 ELSE 0 END) AS corroborated_count,
                   COUNT(DISTINCT CASE WHEN campaign_name IS NOT NULL AND campaign_name != '' AND campaign_name != 'Under Automated Correlation' THEN campaign_name END) AS campaign_count
            FROM victim_reports
            WHERE data_source = 'community' AND reported_at >= ?
        """, (period_start,))
        totals = dict(cursor.fetchone())

        # Newly reported incidents (within past 7 days based on reported_at)

        seven_days_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""

        SELECT COUNT(*) AS new_incidents

        FROM victim_reports

        WHERE data_source = 'community' AND reported_at >= ?

        """, (seven_days_ago,))

        new_row = dict(cursor.fetchone())

        try:
            from backend.community_hub.threat_alerts import generate_dynamic_community_alerts
            active_alerts = len(generate_dynamic_community_alerts())
        except Exception:
            active_alerts = 0

        return {

            "total_submitted_incidents": totals["total_incidents"],

            "newly_reported_incidents": int(new_row["new_incidents"] or 0),

            "corroborated_reports": int(totals["corroborated_count"] or 0),

            "potential_threat_campaigns": int(totals["campaign_count"] or 0),

            "active_community_alerts": active_alerts,

            "total_financial_loss_inr": float(totals["total_lost_inr"] or 0),
            "period_days": 30,
            "data_source": "community_reports_only"

        }

    finally:

        conn.close()

def get_category_overview() -> List[Dict[str, Any]]:

    """

    Returns threat category overview for the 6 core categories:

    - Phishing

    - Recruitment and internship fraud

    - Financial scams

    - GitHub repository and package risks

    - Website impersonation

    - Account compromise

    """

    init_db()

    conn = get_db_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""

        SELECT 

            category,

            COUNT(*) AS incident_count,

            COALESCE(SUM(amount_demanded_or_lost_inr), 0.0) AS total_lost_inr

        FROM victim_reports

        GROUP BY category

        """)

        rows = {r["category"]: dict(r) for r in cursor.fetchall()}

        overview = []

        for cat_id, meta in OFFICIAL_CATEGORIES.items():

            cat_data = rows.get(cat_id, {"incident_count": 0, "total_lost_inr": 0.0})

            

            # Determine dynamic risk level

            count = cat_data["incident_count"]

            loss = cat_data["total_lost_inr"]

            if count >= 3 or loss >= 10000.0:

                risk_level = "Critical Scam"

            elif count >= 1 or loss > 0.0:

                risk_level = "High Risk"

            else:

                risk_level = "Caution"

            overview.append({

                "category_id": cat_id,

                "name": meta["name"],

                "icon": meta["icon"],

                "color": meta["color"],

                "description": meta["description"],

                "incident_count": count,

                "total_lost_inr": loss,

                "risk_level": risk_level

            })

        return overview

    finally:

        conn.close()

def get_recent_activity(limit: int = 15, category: Optional[str] = None) -> List[Dict[str, Any]]:

    """

    Returns recent community activity items with category metadata, date, and verification status.

    Supports filtering by category.

    """

    init_db()

    conn = get_db_connection()

    try:

        cursor = conn.cursor()

        if category and category != "all":

            cursor.execute("""

            SELECT id, incident_ref, incident_title, claimed_organization, scam_type,

                   category, campaign_name, verification_status, amount_demanded_or_lost_inr,

                   scammer_contacts, scammer_links, description, reported_at

            FROM victim_reports

            WHERE category = ?

            ORDER BY id DESC

            LIMIT ?

            """, (category, limit))

        else:

            cursor.execute("""

            SELECT id, incident_ref, incident_title, claimed_organization, scam_type,

                   category, campaign_name, verification_status, amount_demanded_or_lost_inr,

                   scammer_contacts, scammer_links, description, reported_at

            FROM victim_reports

            ORDER BY id DESC

            LIMIT ?

            """, (limit,))

        rows = cursor.fetchall()

        activity = []

        for r in rows:

            d = dict(r)

            raw_contacts = json.loads(d.get("scammer_contacts") or "[]")

            # Mask PII in public activity feed

            d["scammer_contacts"] = [mask_contact(c) for c in raw_contacts]

            d["scammer_links"] = json.loads(d.get("scammer_links") or "[]")

            cat_meta = OFFICIAL_CATEGORIES.get(d["category"], {

                "name": d["category"].replace("_", " ").title(),

                "color": "#6B7280"

            })

            d["category_name"] = cat_meta["name"]

            d["category_color"] = cat_meta.get("color", "#6B7280")

            activity.append(d)

        return activity

    finally:

        conn.close()

def get_recent_community_snapshot(days: int = 30, limit: int = 50) -> Dict[str, Any]:
    """Return real community submissions from a bounded recent window, excluding demo fixtures."""
    init_db()
    days = max(1, min(int(days), 30))
    limit = max(1, min(int(limit), 100))
    cutoff = datetime.now() - timedelta(days=days)
    cutoff_text = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(CASE WHEN financial_loss_occurred = 1 THEN amount_demanded_or_lost_inr ELSE 0 END), 0) AS losses,
                   SUM(CASE WHEN UPPER(verification_status) IN ('CORROBORATED', 'CONFIRMED') OR is_verified = 1 THEN 1 ELSE 0 END) AS corroborated,
                   COUNT(DISTINCT CASE WHEN campaign_name IS NOT NULL AND campaign_name != '' AND campaign_name != 'Under Automated Correlation' THEN campaign_name END) AS campaigns
            FROM victim_reports
            WHERE data_source = 'community' AND reported_at >= ?
        """, (cutoff_text,))
        totals = dict(cursor.fetchone())

        cursor.execute("""
            SELECT incident_ref, incident_title, claimed_organization, scam_type, category,
                   campaign_name, verification_status, amount_demanded_or_lost_inr,
                   scammer_contacts, scammer_links, description, reported_at, is_verified
            FROM victim_reports
            WHERE data_source = 'community' AND reported_at >= ?
            ORDER BY reported_at DESC, id DESC LIMIT ?
        """, (cutoff_text, limit))

        activity = []
        for row in cursor.fetchall():
            item = dict(row)
            item["scammer_contacts"] = [mask_contact(c) for c in json.loads(item.get("scammer_contacts") or "[]")]
            item["scammer_links"] = json.loads(item.get("scammer_links") or "[]")
            category = OFFICIAL_CATEGORIES.get(item.get("category"), {})
            item["category_name"] = category.get("name", str(item.get("category", "")).replace("_", " ").title())
            item["category_color"] = category.get("color", "#6B7280")
            item["risk_level"], item["risk_color"] = compute_incident_risk_level(item)
            activity.append(item)

        return {
            "status": "success",
            "window_days": days,
            "period_start": cutoff_text,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "statistics": {
                "total_submitted_incidents": int(totals.get("total") or 0),
                "newly_reported_incidents": int(totals.get("total") or 0),
                "corroborated_reports": int(totals.get("corroborated") or 0),
                "potential_threat_campaigns": int(totals.get("campaigns") or 0),
                "total_financial_loss_inr": float(totals.get("losses") or 0),
                "active_community_alerts": 0,
                "period_days": days,
                "data_source": "community_reports_only",
            },
            "recent_activity": activity,
        }
    finally:
        conn.close()

def get_trending_threats() -> List[Dict[str, Any]]:

    """

    Extracts indicators that appear across multiple reports, calculating related incident counts,

    financial exposure, and risk assessments.

    """

    init_db()

    conn = get_db_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""

        SELECT incident_ref, claimed_organization, category, campaign_name,

               amount_demanded_or_lost_inr, scammer_contacts, scammer_links, reported_at

        FROM victim_reports

        """)

        rows = cursor.fetchall()

        # Map each indicator to its sightings

        indicator_map: Dict[str, Dict[str, Any]] = {}

        for r in rows:

            contacts = json.loads(r["scammer_contacts"])

            links = json.loads(r["scammer_links"])

            inc_ref = r["incident_ref"]

            loss = r["amount_demanded_or_lost_inr"]

            camp = r["campaign_name"] or "Unattributed Campaign"

            org = r["claimed_organization"]

            for c in contacts:

                c_clean = c.strip()

                if not c_clean:

                    continue

                # Determine type

                itype = "UPI VPA" if "@" in c_clean and not c_clean.endswith(".com") else ("Email" if "@" in c_clean else "Phone / WhatsApp")

                key = f"{itype}:{c_clean}"

                if key not in indicator_map:

                    indicator_map[key] = {

                        "indicator": c_clean,

                        "indicator_type": itype,

                        "related_incidents": [],

                        "total_loss_inr": 0.0,

                        "campaigns": set(),

                        "impersonated_orgs": set()

                    }

                indicator_map[key]["related_incidents"].append(inc_ref)

                indicator_map[key]["total_loss_inr"] += loss

                indicator_map[key]["campaigns"].add(camp)

                indicator_map[key]["impersonated_orgs"].add(org)

            for link in links:

                l_clean = link.replace("https://", "").replace("http://", "").split("/")[0].strip()

                if not l_clean or l_clean in ["bit.ly", "github.com"]:

                    continue

                itype = "GitHub Repo" if "github" in link else "Domain"

                key = f"{itype}:{l_clean}"

                if key not in indicator_map:

                    indicator_map[key] = {

                        "indicator": l_clean if itype == "Domain" else link,

                        "indicator_type": itype,

                        "related_incidents": [],

                        "total_loss_inr": 0.0,

                        "campaigns": set(),

                        "impersonated_orgs": set()

                    }

                indicator_map[key]["related_incidents"].append(inc_ref)

                indicator_map[key]["total_loss_inr"] += loss

                indicator_map[key]["campaigns"].add(camp)

                indicator_map[key]["impersonated_orgs"].add(org)

        # Filter indicators appearing in >= 2 incidents or high loss

        trending = []

        for _, data in indicator_map.items():

            inc_count = len(set(data["related_incidents"]))

            if inc_count >= 1: # Include all significant indicators, sorted by sightings

                # Determine Risk Assessment

                if inc_count >= 3 or data["total_loss_inr"] >= 10000.0:

                    risk = "Critical Scam"

                    risk_color = "#EF4444"

                elif inc_count >= 2 or data["total_loss_inr"] > 0:

                    risk = "High Risk"

                    risk_color = "#F59E0B"

                else:

                    risk = "Caution"

                    risk_color = "#3B82F6"

                trending.append({

                    "indicator": data["indicator"],

                    "indicator_type": data["indicator_type"],

                    "incident_count": inc_count,

                    "total_loss_inr": data["total_loss_inr"],

                    "risk_assessment": risk,

                    "risk_color": risk_color,

                    "campaign": list(data["campaigns"])[0] if data["campaigns"] else "Syndicate Pattern",

                    "target_organization": list(data["impersonated_orgs"])[0] if data["impersonated_orgs"] else "Multiple Brands"

                })

        # Sort by incident count descending, then loss descending

        trending.sort(key=lambda x: (x["incident_count"], x["total_loss_inr"]), reverse=True)

        return trending[:8]

    finally:

        conn.close()

def get_community_alerts() -> List[Dict[str, Any]]:
    """
    Returns active community threat warnings dynamically generated from
    high-risk recurring syndicates and indicator overlap in the database.
    """
    from backend.community_hub.threat_alerts import generate_dynamic_community_alerts
    return generate_dynamic_community_alerts()


def get_incident_by_ref(incident_ref: str) -> Optional[Dict[str, Any]]:

    """Fetches complete incident record including technical indicators, evidence, and legal draft."""

    init_db()

    conn = get_db_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""

        SELECT * FROM victim_reports

        WHERE incident_ref = ? OR id = ?

        """, (incident_ref, incident_ref if incident_ref.isdigit() else -1))

        row = cursor.fetchone()

        if not row:

            return None

        d = dict(row)

        d["scammer_contacts"] = json.loads(d["scammer_contacts"])

        d["scammer_links"] = json.loads(d["scammer_links"])

        d["evidence_filenames"] = json.loads(d["evidence_filenames"])

        cat_meta = OFFICIAL_CATEGORIES.get(d["category"], {

            "name": d["category"].replace("_", " ").title(),

            "color": "#6B7280"

        })

        d["category_name"] = cat_meta["name"]

        d["category_color"] = cat_meta.get("color", "#6B7280")

        return d

    finally:

        conn.close()

def lookup_threat_indicators(

    domain: Optional[str] = None,

    upi_or_phone: Optional[str] = None,

    email: Optional[str] = None,

    claimed_organization: Optional[str] = None

) -> Dict[str, Any]:

    """

    Searches the internal victim database for matching scammer indicators.

    Returns matched counts, cumulative financial damage (INR), anonymized evidence snippets,

    and matched indicator labels.

    """

    init_db()

    conn = get_db_connection()

    try:

        cursor = conn.cursor()

        queries = []

        params = []

        matched_tags = []

        # Clean and prepare search criteria

        clean_domain = domain.strip().lower() if domain else None

        clean_upi_phone = upi_or_phone.strip().lower() if upi_or_phone else None

        clean_email = email.strip().lower() if email else None

        clean_org = claimed_organization.strip() if claimed_organization else None

        if clean_domain:

            queries.append("LOWER(scammer_links) LIKE ?")

            params.append(f"%{clean_domain}%")

            matched_tags.append(f"domain:{clean_domain}")

        if clean_upi_phone:

            queries.append("LOWER(scammer_contacts) LIKE ?")

            params.append(f"%{clean_upi_phone}%")

            matched_tags.append(f"contact:{clean_upi_phone}")

        if clean_email:

            queries.append("LOWER(scammer_contacts) LIKE ?")

            params.append(f"%{clean_email}%")

            matched_tags.append(f"email:{clean_email}")

        if clean_org:

            queries.append("LOWER(claimed_organization) LIKE ?")

            params.append(f"%{clean_org.lower()}%")

            matched_tags.append(f"organization:{clean_org}")

        if queries:

            where_clause = " OR ".join(queries)

            sql = f"""

            SELECT * FROM victim_reports

            WHERE {where_clause}

            ORDER BY id DESC

            """

            cursor.execute(sql, params)

            rows = cursor.fetchall()

        else:

            # If no indicators provided, return recent incidents

            cursor.execute("SELECT * FROM victim_reports ORDER BY id DESC LIMIT 5")

            rows = cursor.fetchall()

            matched_tags.append("all_recent_indicators")

        matching_reports = [dict(r) for r in rows]

        total_count = len(matching_reports)

        total_loss = sum(r["amount_demanded_or_lost_inr"] for r in matching_reports)

        evidence_summaries = [r["description"] for r in matching_reports if r["description"]]

        return {

            "matched_count": total_count,

            "total_money_lost_inr": total_loss,

            "evidence_summaries": evidence_summaries,

            "matched_indicators": matched_tags,

            "records": matching_reports

        }

    finally:

        conn.close()

def get_community_summary_stats() -> Dict[str, Any]:

    """Returns platform-wide totals for frontend tickers and metrics."""

    return get_dashboard_statistics()

def get_all_records_for_correlator() -> List[Dict[str, Any]]:

    """Exposes all victim report records in parsed structure for Agent 2 Correlator graph construction."""

    init_db()

    conn = get_db_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("SELECT * FROM victim_reports ORDER BY id ASC")

        rows = cursor.fetchall()

        

        results = []

        for r in rows:

            d = dict(r)

            d["scammer_contacts"] = json.loads(d["scammer_contacts"])

            d["scammer_links"] = json.loads(d["scammer_links"])

            d["evidence_filenames"] = json.loads(d["evidence_filenames"])

            results.append(d)

        return results

    finally:

        conn.close()

def get_full_dashboard_state() -> Dict[str, Any]:

    """

    Computes all 5 dashboard sections using a single optimized SQLite connection

    for sub-100ms response times.

    """

    init_db()

    conn = get_db_connection()

    try:

        cursor = conn.cursor()

        # 1. Statistics use only actual community reports and confirmed losses.
        stats = get_dashboard_statistics()

        # 2. Categories

        cursor.execute("""

        SELECT category, COUNT(*) AS incident_count, COALESCE(SUM(amount_demanded_or_lost_inr), 0.0) AS total_lost_inr

        FROM victim_reports GROUP BY category

        """)

        cat_rows = {r["category"]: dict(r) for r in cursor.fetchall()}

        categories = []

        for cat_id, meta in OFFICIAL_CATEGORIES.items():

            cat_data = cat_rows.get(cat_id, {"incident_count": 0, "total_lost_inr": 0.0})

            cnt = cat_data["incident_count"]

            lss = cat_data["total_lost_inr"]

            risk = "Critical Scam" if cnt >= 3 or lss >= 10000.0 else ("High Risk" if cnt >= 1 else "Caution")

            categories.append({

                "category_id": cat_id,

                "name": meta["name"],

                "icon": meta["icon"],

                "color": meta["color"],

                "description": meta["description"],

                "incident_count": cnt,

                "total_lost_inr": lss,

                "risk_level": risk

            })

        # 3. Recent Activity (all records for feed)

        cursor.execute("""

        SELECT id, incident_ref, incident_title, claimed_organization, scam_type,

               category, campaign_name, verification_status, amount_demanded_or_lost_inr,

               scammer_contacts, scammer_links, description, reported_at

        FROM victim_reports ORDER BY id DESC LIMIT 30

        """)

        all_rows = cursor.fetchall()

        recent_activity = []

        indicator_map: Dict[str, Dict[str, Any]] = {}

        for r in all_rows:

            d = dict(r)

            contacts = json.loads(d["scammer_contacts"])

            links = json.loads(d["scammer_links"])

            d["scammer_contacts"] = contacts

            d["scammer_links"] = links

            cat_meta = OFFICIAL_CATEGORIES.get(d["category"], {

                "name": d["category"].replace("_", " ").title(),

                "color": "#6B7280"

            })

            d["category_name"] = cat_meta["name"]

            d["category_color"] = cat_meta.get("color", "#6B7280")

            recent_activity.append(d)

            # Accumulate for trending indicators

            inc_ref = d["incident_ref"]

            loss = d["amount_demanded_or_lost_inr"]

            camp = d["campaign_name"] or "Syndicate Pattern"

            org = d["claimed_organization"]

            for c in contacts:

                c_clean = c.strip()

                if not c_clean:

                    continue

                itype = "UPI VPA" if "@" in c_clean and not c_clean.endswith(".com") else ("Email" if "@" in c_clean else "Phone / WhatsApp")

                key = f"{itype}:{c_clean}"

                if key not in indicator_map:

                    indicator_map[key] = {

                        "indicator": c_clean, "indicator_type": itype, "related_incidents": [],

                        "total_loss_inr": 0.0, "campaigns": set(), "impersonated_orgs": set()

                    }

                indicator_map[key]["related_incidents"].append(inc_ref)

                indicator_map[key]["total_loss_inr"] += loss

                indicator_map[key]["campaigns"].add(camp)

                indicator_map[key]["impersonated_orgs"].add(org)

            for l in links:

                l_clean = l.replace("https://", "").replace("http://", "").split("/")[0].strip()

                if not l_clean or l_clean in ["bit.ly", "github.com"]:

                    continue

                itype = "GitHub Repo" if "github" in l else "Domain"

                key = f"{itype}:{l_clean}"

                if key not in indicator_map:

                    indicator_map[key] = {

                        "indicator": l_clean if itype == "Domain" else l, "indicator_type": itype,

                        "related_incidents": [], "total_loss_inr": 0.0, "campaigns": set(), "impersonated_orgs": set()

                    }

                indicator_map[key]["related_incidents"].append(inc_ref)

                indicator_map[key]["total_loss_inr"] += loss

                indicator_map[key]["campaigns"].add(camp)

                indicator_map[key]["impersonated_orgs"].add(org)

        # 4. Trending Threats

        trending = []

        for _, data in indicator_map.items():

            inc_count = len(set(data["related_incidents"]))

            if inc_count >= 1:

                if inc_count >= 3 or data["total_loss_inr"] >= 10000.0:

                    risk = "Critical Scam"

                    risk_color = "#EF4444"

                elif inc_count >= 2 or data["total_loss_inr"] > 0:

                    risk = "High Risk"

                    risk_color = "#F59E0B"

                else:

                    risk = "Caution"

                    risk_color = "#3B82F6"

                trending.append({

                    "indicator": data["indicator"],

                    "indicator_type": data["indicator_type"],

                    "incident_count": inc_count,

                    "total_loss_inr": data["total_loss_inr"],

                    "risk_assessment": risk,

                    "risk_color": risk_color,

                    "campaign": list(data["campaigns"])[0] if data["campaigns"] else "Syndicate Pattern",

                    "target_organization": list(data["impersonated_orgs"])[0] if data["impersonated_orgs"] else "Multiple Brands"

                })

        trending.sort(key=lambda x: (x["incident_count"], x["total_loss_inr"]), reverse=True)

        # 5. Community Alerts

        alerts = [

            {

                "alert_id": "ALT-2026-TCS-01",

                "title": "GhostRecruiter Ring #4: Fraudulent TCS & Infosys Laptop Deposits",

                "severity": "CRITICAL",

                "severity_color": "#EF4444",

                "category": "Recruitment & Internship Fraud",

                "affected_students": "Engineering Colleges (Karnataka, Maharashtra, TN)",

                "summary": "Coordinated recruitment ring sending fake offer letters with valid-looking letterheads demanding Rs. 3,500 - Rs. 5,000 security deposits to 'tcs.hrverification@oksbi'.",

                "protective_action": "Do NOT transfer funds. Enterprise recruiters (TCS/Infosys) NEVER ask for hardware deposits or badge fees.",

                "related_incidents_count": 4,

                "issued_at": "2026-10-31"

            },

            {

                "alert_id": "ALT-2026-REPO-02",

                "title": "CodeStealer Trojan: Malicious NPM Postinstall Hooks in Coding Challenges",

                "severity": "HIGH",

                "severity_color": "#F59E0B",

                "category": "GitHub Repository & Package Risks",

                "affected_students": "Computer Science applicants & Open-Source contributors",

                "summary": "Attackers disguise trojan repositories as hiring coding tests. Running 'npm install' or 'npm test' triggers an obfuscated postinstall hook harvesting browser cookies.",

                "protective_action": "Inspect package.json dependencies and scripts before installing. Open in VS Code with Workspace Trust disabled.",

                "related_incidents_count": 2,

                "issued_at": "2026-10-29"

            },

            {

                "alert_id": "ALT-2026-TASK-03",

                "title": "VIP Task Scam: Telegram YouTube Review & Ratings Ponzi",

                "severity": "HIGH",

                "severity_color": "#F59E0B",

                "category": "Financial Scams",

                "affected_students": "Students seeking remote part-time / work-from-home gigs",

                "summary": "Victims are paid Rs. 300 for simple initial reviews, then lured into depositing Rs. 10,000+ for 'VIP tasks' that lock withdrawals.",

                "protective_action": "No legitimate marketing firm requires upfront deposits to perform review tasks. File an immediate 1930 dispute.",

                "related_incidents_count": 2,

                "issued_at": "2026-10-31"

            },

            {

                "alert_id": "ALT-2026-MULE-04",

                "title": "MuleHarvest Syndicate: Student UPI & Bank Account Money Laundering",

                "severity": "CRITICAL",

                "severity_color": "#EF4444",

                "category": "Account Compromise",

                "affected_students": "Campus students targeted on Telegram & Discord",

                "summary": "Scammers offer Rs. 500-1,000 commission for students to receive third-party funds and forward them. Victim accounts are frozen by State Cyber Police under Section 66D IT Act.",

                "protective_action": "Never allow anyone to use your bank account or UPI VPA. Account holders are held legally liable for receiving crime proceeds.",

                "related_incidents_count": 2,

                "issued_at": "2026-10-31"

            },

            {

                "alert_id": "ALT-2026-UGC-05",

                "title": "DiplomaMill Academic Syndicate: Unaccredited B.Tech Certificate Fraud",

                "severity": "WARNING",

                "severity_color": "#3B82F6",

                "category": "Website Impersonation",

                "affected_students": "Lateral entry & diploma transfer students",

                "summary": "Unrecognized institutions issuing worthless degrees for Rs. 12,000 without coursework, matching the UGC Official 2026 Fake Universities bulletin.",

                "protective_action": "Always verify university recognition on the UGC (ugc.ac.in) and AICTE portals before enrolling or transferring fees.",

                "related_incidents_count": 1,

                "issued_at": "2026-10-26"

            }

        ]

        return {

            "statistics": stats,

            "categories": categories,

            "recent_activity": recent_activity,

            "trending_threats": trending[:8],

            "community_alerts": alerts

        }

    finally:

        conn.close()

# =========================================================

# COMMUNITY INCIDENT FEED & THREAT SEARCH ENGINE

# =========================================================

def compute_incident_risk_level(row: Dict[str, Any], related_count: int = 0) -> Tuple[str, str]:
    if hasattr(row, "keys") and not isinstance(row, dict):
        row = dict(row)

    """

    Computes risk tier and badge color based on financial loss, category, campaign syndication, and related count.

    Returns (risk_level, risk_color).

    Tiers: 'Critical Scam', 'High Risk', 'Caution', 'Low Risk', 'Verified Safe'

    """

    loss = float(row.get("amount_demanded_or_lost_inr") or 0.0)

    category = row.get("category", "")

    campaign = row.get("campaign_name", "")

    has_campaign = bool(campaign and campaign != "Under Automated Correlation")

    v_status = row.get("verification_status", "")

    if v_status == "Verified Safe":

        return "Verified Safe", "#10B981"

    if loss >= 5000.0 or related_count >= 3 or (has_campaign and loss > 0):

        return "Critical Scam", "#EF4444"

    elif loss > 0.0 or category in ["recruitment_fraud", "financial_scam", "account_compromise", "github_repo_risk"] or related_count >= 1:

        return "High Risk", "#F59E0B"

    elif category in ["website_impersonation", "phishing"]:

        return "Caution", "#3B82F6"

    else:

        return "Low Risk", "#10B981"

def extract_row_indicators(row: Dict[str, Any]) -> Dict[str, Any]:
    if hasattr(row, "keys") and not isinstance(row, dict):
        row = dict(row)

    """Extracts parsed atomic indicators (domains, emails, phones, repos, org) from a DB row."""

    contacts = row.get("scammer_contacts")

    if isinstance(contacts, str):

        try:

            contacts = json.loads(contacts or "[]")

        except Exception:

            contacts = []

    elif not contacts:

        contacts = []

    links = row.get("scammer_links")

    if isinstance(links, str):

        try:

            links = json.loads(links or "[]")

        except Exception:

            links = []

    elif not links:

        links = []

    domains = set()

    urls = set()

    repos = set()

    packages = set()

    for l in links:

        if not l:

            continue

        l_str = str(l).strip()

        urls.add(l_str.lower())

        if "github.com" in l_str.lower():

            repos.add(l_str.lower())

        clean_d = l_str.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0].lower()

        if clean_d:

            domains.add(clean_d)

        if any(pkg in l_str.lower() for pkg in ["cross-env", "stealer", "override", "fetch"]):

            packages.add(l_str.lower())

    s_url = row.get("suspicious_url_or_domain")

    if s_url:

        s_str = str(s_url).strip()

        urls.add(s_str.lower())

        clean_d = s_str.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0].lower()

        if clean_d:

            domains.add(clean_d)

    gh = row.get("github_repo_link")

    if gh:

        gh_str = str(gh).strip()

        repos.add(gh_str.lower())

        urls.add(gh_str.lower())

    emails = set()

    phones = set()

    upis = set()

    for c in contacts:

        if not c:

            continue

        c_str = str(c).strip()

        if "@" in c_str and not c_str.startswith("@") and any(d in c_str.lower() for d in [".com", ".in", ".edu", ".org", ".net", ".io", ".site"]):

            emails.add(c_str.lower())

        elif "@" in c_str:

            upis.add(c_str.lower())

        digits = "".join(ch for ch in c_str if ch.isdigit())

        if len(digits) >= 10:

            phones.add(digits[-10:])

    return {

        "domains": domains,

        "urls": urls,

        "repos": repos,

        "packages": packages,

        "emails": emails,

        "phones": phones,

        "upis": upis,

        "contacts": contacts,

        "links": links,

        "claimed_org": (row.get("claimed_organization") or "").lower(),

        "campaign": (row.get("campaign_name") or "")

    }

def get_distinct_incident_types() -> List[Dict[str, str]]:

    """Returns distinct scam_type identifiers from the database for feed filtering."""

    init_db()

    conn = get_db_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("SELECT DISTINCT scam_type FROM victim_reports ORDER BY scam_type ASC")

        rows = cursor.fetchall()

        types = []

        for r in rows:

            st = r["scam_type"]

            display = st.replace("_", " ").title()

            types.append({"type_id": st, "display_name": display})

        return types

    finally:

        conn.close()

def get_feed_filter_options() -> Dict[str, Any]:

    """Provides available filter choices for the community incident feed."""

    cats = [

        {"id": k, "name": v["name"], "color": v["color"], "icon": v.get("icon", "shield")}

        for k, v in OFFICIAL_CATEGORIES.items()

    ]

    return {

        "categories": cats,

        "risk_levels": [

            {"id": "Critical Scam", "name": "Critical Scam", "color": "#EF4444"},

            {"id": "High Risk", "name": "High Risk", "color": "#F59E0B"},

            {"id": "Caution", "name": "Caution", "color": "#3B82F6"},

            {"id": "Low Risk", "name": "Low Risk", "color": "#10B981"},

            {"id": "Verified Safe", "name": "Verified Safe", "color": "#22C55E"}

        ],

        "verification_statuses": [

            {"id": "Corroborated", "name": "Corroborated (Multi-Victim Verified)"},

            {"id": "UNDER_REVIEW", "name": "Under Review"},

            {"id": "SUBMITTED", "name": "Newly Submitted"}

        ],

        "date_filters": [

            {"id": "all", "name": "All Time"},

            {"id": "today", "name": "Today"},

            {"id": "past_7_days", "name": "Past 7 Days"},

            {"id": "past_30_days", "name": "Past 30 Days"}

        ],

        "incident_types": get_distinct_incident_types()

    }

def _index_all_incidents(conn: sqlite3.Connection) -> List[Dict[str, Any]]:

    """Internal helper to load and index all incidents with parsed indicators and related counts."""

    cursor = conn.cursor()

    cursor.execute("""

    SELECT id, incident_ref, incident_title, claimed_organization, scam_type,

           category, campaign_name, verification_status, amount_demanded_or_lost_inr,

           scammer_contacts, scammer_links, description, evidence_filenames,

           is_verified, reported_at, user_pseudonym, financial_loss_occurred,

           official_complaint_filed, complaint_ack_ref, suspicious_url_or_domain, github_repo_link

    FROM victim_reports

    ORDER BY id DESC

    """)

    raw_rows = [dict(r) for r in cursor.fetchall()]

    for r in raw_rows:

        r["_ind"] = extract_row_indicators(r)

    # Compute cross-incident related counts and shared references

    for r in raw_rows:

        related_refs = []

        t_camp = r["_ind"]["campaign"]

        has_camp = bool(t_camp and t_camp != "Under Automated Correlation")

        for o in raw_rows:

            if o["incident_ref"] == r["incident_ref"]:

                continue

            if (has_camp and o["_ind"]["campaign"] == t_camp) or                r["_ind"]["domains"].intersection(o["_ind"]["domains"]) or                r["_ind"]["upis"].intersection(o["_ind"]["upis"]) or                r["_ind"]["emails"].intersection(o["_ind"]["emails"]) or                (r["_ind"]["repos"] and r["_ind"]["repos"].intersection(o["_ind"]["repos"])):

                related_refs.append(o["incident_ref"])

        r["related_incidents_count"] = len(related_refs)

        r["related_incident_refs"] = related_refs

        risk, r_color = compute_incident_risk_level(r, len(related_refs))

        r["risk_level"] = risk

        r["risk_color"] = r_color

    return raw_rows

def query_community_incident_feed(

    page: int = 1,

    page_size: int = 10,

    category: Optional[str] = None,

    risk_level: Optional[str] = None,

    verification_status: Optional[str] = None,

    date_filter: Optional[str] = None,

    incident_type: Optional[str] = None,

    query: Optional[str] = None

) -> Dict[str, Any]:

    """

    Searches and filters community incidents with backend pagination.

    Supports filtering by threat category, risk level, verification status, date, incident type, and keyword.

    Masks PII on all returned contacts.

    """

    init_db()

    conn = get_db_connection()

    try:

        all_incidents = _index_all_incidents(conn)

        filtered = all_incidents

        # 1. Category Filter

        if category and category != "all":

            filtered = [r for r in filtered if r["category"] == category]

        # 2. Risk Level Filter

        if risk_level and risk_level != "all":

            filtered = [r for r in filtered if r["risk_level"].lower() == risk_level.lower()]

        # 3. Verification Status Filter

        if verification_status and verification_status != "all":

            filtered = [r for r in filtered if r["verification_status"].lower() == verification_status.lower()]

        # 4. Date Filter

        now = datetime.now()

        if date_filter == "today":

            today_str = now.strftime("%Y-%m-%d")

            filtered = [r for r in filtered if (r["reported_at"] or "").startswith(today_str)]

        elif date_filter == "past_7_days":

            cutoff = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

            filtered = [r for r in filtered if (r["reported_at"] or "") >= cutoff]

        elif date_filter == "past_30_days":

            cutoff = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

            filtered = [r for r in filtered if (r["reported_at"] or "") >= cutoff]

        # 5. Incident Type Filter

        if incident_type and incident_type != "all":

            filtered = [r for r in filtered if r["scam_type"] == incident_type]

        # 6. Keyword / Indicator Search

        if query and isinstance(query, str) and query.strip():

            clean_q = query.strip().lower()

            matched = []

            for r in filtered:

                ind = r["_ind"]

                # Check domain / url / repo / pkg / email / phone

                has_exact = (

                    clean_q in ind["domains"] or

                    any(clean_q in u for u in ind["urls"]) or

                    any(clean_q in e for e in ind["emails"]) or

                    any(clean_q in p for p in ind["packages"]) or

                    any(clean_q in r_item for r_item in ind["repos"])

                )

                # Check organization / text

                has_approx = (

                    clean_q in ind["claimed_org"] or

                    clean_q in (r["incident_title"] or "").lower() or

                    clean_q in (r["description"] or "").lower()

                )

                if has_exact or has_approx:

                    matched.append(r)

            filtered = matched

        total_items = len(filtered)

        page = max(1, page if isinstance(page, int) else 1)

        page_size = max(1, min(page_size if isinstance(page_size, int) else 10, 50))

        total_pages = max(1, math.ceil(total_items / page_size)) if total_items > 0 else 1

        offset = (page - 1) * page_size

        page_items = filtered[offset : offset + page_size]

        formatted_items = []

        for r in page_items:

            cat_meta = OFFICIAL_CATEGORIES.get(r["category"], {

                "name": r["category"].replace("_", " ").title(),

                "color": "#6B7280"

            })

            raw_contacts = r["_ind"]["contacts"]

            masked_contacts = [mask_contact(c) for c in raw_contacts]

            item = {

                "id": r["id"],

                "incident_ref": r["incident_ref"],

                "incident_title": r["incident_title"],

                "claimed_organization": r["claimed_organization"],

                "scam_type": r["scam_type"],

                "category": r["category"],

                "category_name": cat_meta["name"],

                "category_color": cat_meta["color"],

                "campaign_name": r["campaign_name"],

                "verification_status": r["verification_status"],

                "risk_level": r["risk_level"],

                "risk_color": r["risk_color"],

                "amount_demanded_or_lost_inr": r["amount_demanded_or_lost_inr"],

                "scammer_contacts": masked_contacts,

                "scammer_links": r["_ind"]["links"],

                "description": r["description"],

                "reported_at": r["reported_at"],

                "related_incidents_count": r["related_incidents_count"]

            }

            formatted_items.append(item)

        return {

            "status": "success",

            "pagination": {

                "page": page,

                "page_size": page_size,

                "total_items": total_items,

                "total_pages": total_pages,

                "has_next": page < total_pages,

                "has_prev": page > 1

            },

            "filters_applied": {

                "category": category,

                "risk_level": risk_level,

                "verification_status": verification_status,

                "date_filter": date_filter or "all",

                "incident_type": incident_type,

                "query": query

            },

            "items": formatted_items

        }

    finally:

        conn.close()

def search_threat_indicators(

    query: str,

    page: int = 1,

    page_size: int = 10,

    category: Optional[str] = None,

    verification_status: Optional[str] = None

) -> Dict[str, Any]:

    """

    Dedicated Threat Search engine adhering to the 6-step search mandate:

    1. Searches community incident DB.

    2. Identifies exact indicator matches (domain, email, phone/UPI, repo, package).

    3. Retrieves potentially related incidents from relationship records.

    4. Displays matching reports with PII masked.

    5. Explains why each result matched.

    6. Displays verification status and confidence of the relationship.

    Distinguishes exact matches from approximate matches.

    """

    query_str = str(query).strip() if (isinstance(query, str) or (hasattr(query, '__str__') and not hasattr(query, 'default'))) else ''

    if not query_str:

        return {

            "status": "success",

            "query": "",

            "pagination": {"page": 1, "page_size": 10, "total_items": 0, "total_pages": 1, "has_next": False, "has_prev": False},

            "exact_matches_count": 0,

            "related_matches_count": 0,

            "approximate_matches_count": 0,

            "results": []

        }

    clean_q = query_str.lower()

    init_db()

    conn = get_db_connection()

    try:

        all_incidents = _index_all_incidents(conn)

        exact_results = []

        related_results = []

        approximate_results = []

        seen_refs = set()

        # Step 1 & 2: Identify exact indicator matches

        for r in all_incidents:

            ind = r["_ind"]

            matched_target = None

            explanation = None

            # Check domain match

            matched_dom = [d for d in ind["domains"] if clean_q == d or clean_q in d]

            if matched_dom:

                matched_target = "Domain / Website Link"

                explanation = f"Exact indicator match on suspect domain '{matched_dom[0]}'"

            # Check email match

            if not matched_target:

                matched_em = [e for e in ind["emails"] if clean_q == e]

                if matched_em:

                    matched_target = "Email Address"

                    explanation = f"Exact indicator match on suspect email '{mask_contact(matched_em[0])}'"

            # Check phone / UPI match

            if not matched_target:

                matched_u = [u for u in ind["upis"] if clean_q in u]

                matched_p = [p for p in ind["phones"] if clean_q in p or clean_q.endswith(p)]

                if matched_u:

                    matched_target = "Payment UPI Handle"

                    explanation = f"Exact indicator match on payment receiver '{mask_contact(matched_u[0])}'"

                elif matched_p:

                    matched_target = "Contact Phone"

                    explanation = f"Exact indicator match on suspect phone ending in {matched_p[0][-5:]}"

            # Check GitHub repo match

            if not matched_target:

                matched_rep = [rep for rep in ind["repos"] if clean_q in rep]

                if matched_rep:

                    matched_target = "GitHub Repository"

                    explanation = f"Exact indicator match on GitHub repository '{matched_rep[0]}'"

            # Check package name match

            if not matched_target:

                matched_pkg = [pkg for pkg in ind["packages"] if clean_q in pkg]

                if matched_pkg:

                    matched_target = "Malicious Package"

                    explanation = f"Exact indicator match on malicious package '{matched_pkg[0]}'"

            if matched_target:

                r_item = dict(r)

                r_item["match_type"] = "exact"

                r_item["match_target"] = matched_target

                r_item["match_explanation"] = explanation

                r_item["relationship_confidence"] = 1.0

                r_item["confidence_label"] = "Confirmed Exact Match (100%)"

                r_item["is_exact_match"] = True

                exact_results.append(r_item)

                seen_refs.add(r["incident_ref"])

        # Step 3: Retrieve potentially related incidents from relationship records of exact matches

        for exact_r in exact_results:

            related_refs = exact_r.get("related_incident_refs", [])

            camp = exact_r["_ind"]["campaign"]

            for rel_ref in related_refs:

                if rel_ref in seen_refs:

                    continue

                other = next((x for x in all_incidents if x["incident_ref"] == rel_ref), None)

                if other:

                    o_item = dict(other)

                    o_item["match_type"] = "related"

                    o_item["match_target"] = "Correlated Campaign / Syndicate"

                    if camp and camp != "Under Automated Correlation":

                        o_item["match_explanation"] = f"Correlated with exact match {exact_r['incident_ref']} via shared syndicate campaign '{camp}'"

                    else:

                        o_item["match_explanation"] = f"Correlated with exact match {exact_r['incident_ref']} via common technical indicators"

                    o_item["relationship_confidence"] = 0.88

                    o_item["confidence_label"] = "High Syndicate Correlation (88%)"

                    o_item["is_exact_match"] = False

                    related_results.append(o_item)

                    seen_refs.add(rel_ref)

        # Step 4: Identify approximate keyword & company matches

        for r in all_incidents:

            if r["incident_ref"] in seen_refs:

                continue

            ind = r["_ind"]

            is_approx = False

            target = None

            explanation = None

            confidence = 0.60

            # Check claimed company / organization

            if clean_q in ind["claimed_org"] or ind["claimed_org"] in clean_q:

                is_approx = True

                target = "Claimed Organization"

                explanation = f"Approximate match in claimed company '{r['claimed_organization']}'. Note: Similar company names do NOT prove a syndicate connection."

                confidence = 0.70

            elif clean_q in (r["incident_title"] or "").lower():

                is_approx = True

                target = "Incident Title Keyword"

                explanation = f"Approximate keyword match in title '{r['incident_title']}'. Content similarity does NOT prove a connection."

                confidence = 0.65

            elif clean_q in (r["description"] or "").lower():

                is_approx = True

                target = "Incident Description Text"

                explanation = f"Approximate text match in victim narrative. Content similarity does NOT prove a connection."

                confidence = 0.60

            if is_approx:

                r_item = dict(r)

                r_item["match_type"] = "approximate"

                r_item["match_target"] = target

                r_item["match_explanation"] = explanation

                r_item["relationship_confidence"] = confidence

                r_item["confidence_label"] = f"Approximate Context Match ({int(confidence * 100)}%)"

                r_item["is_exact_match"] = False

                approximate_results.append(r_item)

                seen_refs.add(r["incident_ref"])

        # Combine results: exact first, then related, then approximate

        combined_results = exact_results + related_results + approximate_results

        # Optional filters applied to search results

        if category and category != "all":

            combined_results = [r for r in combined_results if r["category"] == category]

        if verification_status and verification_status != "all":

            combined_results = [r for r in combined_results if r["verification_status"].lower() == verification_status.lower()]

        total_items = len(combined_results)

        page_val = max(1, page if isinstance(page, int) else 1)

        page_size_val = max(1, min(page_size if isinstance(page_size, int) else 10, 50))

        total_pages = max(1, math.ceil(total_items / page_size_val)) if total_items > 0 else 1

        offset = (page_val - 1) * page_size_val

        page_items = combined_results[offset : offset + page_size_val]

        formatted_results = []

        for r in page_items:

            cat_meta = OFFICIAL_CATEGORIES.get(r["category"], {

                "name": r["category"].replace("_", " ").title(),

                "color": "#6B7280"

            })

            raw_contacts = r["_ind"]["contacts"]

            masked_contacts = [mask_contact(c) for c in raw_contacts]

            formatted_results.append({

                "incident_ref": r["incident_ref"],

                "incident_title": r["incident_title"],

                "claimed_organization": r["claimed_organization"],

                "scam_type": r["scam_type"],

                "category": r["category"],

                "category_name": cat_meta["name"],

                "category_color": cat_meta["color"],

                "description": r["description"],

                "reported_at": r["reported_at"],

                "risk_level": r["risk_level"],

                "risk_color": r["risk_color"],

                "verification_status": r["verification_status"],

                "related_incidents_count": r["related_incidents_count"],

                "amount_demanded_or_lost_inr": r["amount_demanded_or_lost_inr"],

                "scammer_contacts": masked_contacts,

                "scammer_links": r["_ind"]["links"],

                "match_type": r["match_type"],

                "match_target": r["match_target"],

                "match_explanation": r["match_explanation"],

                "relationship_confidence": r["relationship_confidence"],

                "confidence_label": r["confidence_label"],

                "is_exact_match": r["is_exact_match"]

            })

        return {

            "status": "success",

            "query": query_str,

            "exact_matches_count": len(exact_results),

            "related_matches_count": len(related_results),

            "approximate_matches_count": len(approximate_results),

            "total_results": total_items,

            "pagination": {

                "page": page_val,

                "page_size": page_size_val,

                "total_items": total_items,

                "total_pages": total_pages,

                "has_next": page_val < total_pages,

                "has_prev": page_val > 1

            },

            "results": formatted_results

        }

    finally:

        conn.close()

