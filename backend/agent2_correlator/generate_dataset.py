"""
Factora - Agent 2: Cyber Threat Correlator Dataset Generator
Problem 1: Safety Tech — FAKE OR REAL (Hackathon 2026)

Generates:
1. historical_incidents.json: 25 realistic student/developer threat incidents
   (covering fake AICTE scholarships, recruiter impersonation, GitHub malware, task scams).
2. training_pairs.csv: 300 labeled pairs (25 * 24 / 2 = 300) with similarity features
   for training our ML Threat Correlation model.
"""

import json
import csv
import difflib
from pathlib import Path
from itertools import combinations
from typing import List, Dict, Any, Tuple


# Define the 25 realistic historical incidents across 5 organized syndicates + 5 independent scams
HISTORICAL_INCIDENTS: List[Dict[str, Any]] = [
    # --- SYNDICATE 1: GhostRecruiter Ring (Corporate Campus Impersonation) ---
    {
        "incident_id": "INC-2026-TCS-9021",
        "incident_title": "Fake TCS NextStep Offer with UPI Deposit",
        "campaign_name": "GhostRecruiter Syndicate",
        "description": "WhatsApp and email recruitment offer pretending to be TCS campus drive, demanding 3500 INR laptop bond.",
        "claimed_organization": "Tata Consultancy Services (TCS)",
        "domains": ["tcs-careers-portal.in", "bit.ly"],
        "urls": ["https://bit.ly/tcs-campus-2026", "https://tcs-careers-portal.in/register"],
        "emails": ["hr-onboarding@tcs-careers-portal.in", "tcsrecruitmentindia@gmail.com"],
        "phones_or_upi": ["+919876543210", "tcs.hrverification@oksbi"],
        "github_repos": ["https://github.com/tcs-assessment-portal/coding-round-2026"],
        "suspicious_packages": ["cross-env-stealer", "node-fetch-override"],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-INFY-4102",
        "incident_title": "Infosys Special Entry Security Deposit Scam",
        "campaign_name": "GhostRecruiter Syndicate",
        "description": "Direct selection letter under Infosys banner demanding 4000 INR refundable hardware clearance fee.",
        "claimed_organization": "Infosys Limited",
        "domains": ["infosys-careers-portal.in", "bit.ly"],
        "urls": ["https://bit.ly/infy-campus-drive", "https://infosys-careers-portal.in/deposit"],
        "emails": ["onboarding@infosys-careers-portal.in", "tcsrecruitmentindia@gmail.com"],
        "phones_or_upi": ["+919876543210", "tcs.hrverification@oksbi"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2025-WIPRO-1108",
        "incident_title": "Wipro Elite National Talent Fake Offer",
        "campaign_name": "GhostRecruiter Syndicate",
        "description": "Fake Wipro Elite direct appointment letter requesting 3200 INR training module fee via SBI UPI.",
        "claimed_organization": "Wipro Technologies",
        "domains": ["wipro-hiring-portal.in"],
        "urls": ["https://wipro-hiring-portal.in/join"],
        "emails": ["recruitment@wipro-hiring-portal.in"],
        "phones_or_upi": ["+919876543210", "wipro.onboarding@oksbi"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-COGN-3310",
        "incident_title": "Cognizant GenC Fake Offer Letter",
        "campaign_name": "GhostRecruiter Syndicate",
        "description": "WhatsApp dispatch of forged Cognizant GenC onboarding letter requiring 3500 INR courier and ID badge charge.",
        "claimed_organization": "Cognizant Technology Solutions",
        "domains": ["cognizant-genc-portal.in", "bit.ly"],
        "urls": ["https://bit.ly/cogn-genc-2026"],
        "emails": ["hr@cognizant-genc-portal.in"],
        "phones_or_upi": ["+919876543210", "tcs.hrverification@oksbi"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-HCL-5520",
        "incident_title": "HCL TechBee Fresher Registration Fee",
        "campaign_name": "GhostRecruiter Syndicate",
        "description": "Fake campus recruitment portal for HCL asking students to transfer 2800 INR for entry exam hall ticket.",
        "claimed_organization": "HCL Technologies",
        "domains": ["hcl-freshers-portal.in"],
        "urls": ["https://hcl-freshers-portal.in/hallticket"],
        "emails": ["careers@hcl-freshers-portal.in", "tcsrecruitmentindia@gmail.com"],
        "phones_or_upi": ["+919876543210", "hcl.verify@oksbi"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },

    # --- SYNDICATE 2: RepoBackdoor APT (Developer Supply-Chain Attacks) ---
    {
        "incident_id": "INC-2026-REPO-0101",
        "incident_title": "React Internship Test with Obfuscated Postinstall",
        "campaign_name": "RepoBackdoor APT",
        "description": "Technical coding challenge repository containing cross-env-stealer package in package.json targeting student tokens.",
        "claimed_organization": "MetaDev Labs",
        "domains": ["dev-assessment-check.net"],
        "urls": ["https://dev-assessment-check.net/challenge-1"],
        "emails": ["devrel-hiring@protonmail.com"],
        "phones_or_upi": [],
        "github_repos": ["https://github.com/tcs-assessment-portal/coding-round-2026"],
        "suspicious_packages": ["cross-env-stealer", "node-fetch-override"],
        "student_scam_flags": {
            "upfront_fee": False,
            "zero_interview": False,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-REPO-0102",
        "incident_title": "Python FastAPI Assessment with Poisoned Setup.py",
        "campaign_name": "RepoBackdoor APT",
        "description": "Take-home backend assessment with malicious setup.py executing base64 encoded payload to harvest browser passwords.",
        "claimed_organization": "CloudScale Systems",
        "domains": ["dev-assessment-check.net"],
        "urls": ["https://dev-assessment-check.net/python-task"],
        "emails": ["devrel-hiring@protonmail.com"],
        "phones_or_upi": [],
        "github_repos": ["https://github.com/capgemini-hire-test/takehome-task"],
        "suspicious_packages": ["requests-ratelimit-bypass", "cross-env-stealer"],
        "student_scam_flags": {
            "upfront_fee": False,
            "zero_interview": False,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-REPO-0103",
        "incident_title": "Fullstack Coding Round with VSCode Tasks Backdoor",
        "campaign_name": "RepoBackdoor APT",
        "description": "GitHub coding assessment with hidden .vscode/tasks.json configured to trigger curl payload upon folder open.",
        "claimed_organization": "FinTech Dev Challenge",
        "domains": ["code-eval-verify.io"],
        "urls": ["https://code-eval-verify.io/repo-eval"],
        "emails": ["devrel-hiring@protonmail.com"],
        "phones_or_upi": [],
        "github_repos": ["https://github.com/fintech-dev-challenge/intern-eval"],
        "suspicious_packages": ["node-fetch-override", "discord-token-logger"],
        "student_scam_flags": {
            "upfront_fee": False,
            "zero_interview": False,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-REPO-0104",
        "incident_title": "Web3 Smart Contract Assessment Credential Stealer",
        "campaign_name": "RepoBackdoor APT",
        "description": "Web3 Solidity internship test repo importing malicious ethers-helper-v2 dependency to siphon crypto wallets.",
        "claimed_organization": "ChainPulse Foundation",
        "domains": ["code-eval-verify.io"],
        "urls": ["https://code-eval-verify.io/web3-task"],
        "emails": ["devrel-hiring@protonmail.com"],
        "phones_or_upi": [],
        "github_repos": ["https://github.com/web3-dev-challenge/smart-contract-task"],
        "suspicious_packages": ["ethers-helper-v2", "cross-env-stealer"],
        "student_scam_flags": {
            "upfront_fee": False,
            "zero_interview": False,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },

    # --- SYNDICATE 3: BharatGov Scholarship Syndicate (Academic Grant Impersonation) ---
    {
        "incident_id": "INC-2026-SCHOLAR-201",
        "incident_title": "AICTE Pragati Scholarship Verification Fee Fraud",
        "campaign_name": "BharatGov Scholarship Syndicate",
        "description": "SMS phishing campaign claiming approved 50,000 INR AICTE Pragati scholarship requiring 1200 INR stamp registration.",
        "claimed_organization": "AICTE (All India Council for Technical Education)",
        "domains": ["aicte-scholarship-gov.in"],
        "urls": ["https://aicte-scholarship-gov.in/verify"],
        "emails": ["support@aicte-scholarship-gov.in"],
        "phones_or_upi": ["+919123456780", "aicte.helpdesk@upi"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": False,
            "ugc_fake_uni": False,
            "aicte_unverified": True,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-SCHOLAR-202",
        "incident_title": "NSP Central Sector Scheme Biometric Fee Phish",
        "campaign_name": "BharatGov Scholarship Syndicate",
        "description": "Spoofed National Scholarship Portal claiming pending grant disbursement upon payment of 1500 INR processing fee.",
        "claimed_organization": "National Scholarship Portal (NSP)",
        "domains": ["nsp-portal-grant.org", "aicte-scholarship-gov.in"],
        "urls": ["https://nsp-portal-grant.org/disbursement"],
        "emails": ["officer@nsp-portal-grant.org"],
        "phones_or_upi": ["+919123456780", "aicte.helpdesk@upi"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": False,
            "ugc_fake_uni": False,
            "aicte_unverified": True,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-SCHOLAR-203",
        "incident_title": "UGC Merit Fellowship Stamp Duty Extortion",
        "campaign_name": "BharatGov Scholarship Syndicate",
        "description": "Phony UGC letterhead certifying research fellowship grant provided 2000 INR stamp duty is deposited to official UPI.",
        "claimed_organization": "UGC (University Grants Commission)",
        "domains": ["ugc-merit-fellowship.co.in"],
        "urls": ["https://ugc-merit-fellowship.co.in/claim"],
        "emails": ["ugc.disbursement@gmail.com"],
        "phones_or_upi": ["+919123456780", "fellowship.gov@upi"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": False,
            "ugc_fake_uni": True,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-SCHOLAR-204",
        "incident_title": "State Post-Matric Scholarship Gateway Trap",
        "campaign_name": "BharatGov Scholarship Syndicate",
        "description": "Cloned state scholarship portal directing students to pay 1000 INR verification charge via QR code.",
        "claimed_organization": "State Directorate of Technical Education",
        "domains": ["scholarship-disbursement.org.in"],
        "urls": ["https://scholarship-disbursement.org.in/pay"],
        "emails": ["officer@nsp-portal-grant.org"],
        "phones_or_upi": ["+919123456780", "aicte.helpdesk@upi"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": False,
            "ugc_fake_uni": False,
            "aicte_unverified": True,
            "task_scam": False,
            "mule_account_request": False
        }
    },

    # --- SYNDICATE 4: QuickTask Telegram Guild (Part-time Student Task Fraud) ---
    {
        "incident_id": "INC-2026-TASK-301",
        "incident_title": "YouTube Like & Subscribe Daily Salary Scam",
        "campaign_name": "QuickTask Telegram Guild",
        "description": "WhatsApp outreach promising 1500 INR daily for liking YouTube videos, requires 3000 INR VIP upgrade deposit.",
        "claimed_organization": "Apex Media Marketing",
        "domains": ["t.me", "telegram.org"],
        "urls": ["https://t.me/quicktask_india", "https://chat.whatsapp.com/taskrecruit2026"],
        "emails": [],
        "phones_or_upi": ["+919988776655", "dailyrewards@paytm"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": True,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-TASK-302",
        "incident_title": "Google Maps 5-Star Rating Student Bounty Scam",
        "campaign_name": "QuickTask Telegram Guild",
        "description": "Telegram group paying 50 INR per Google Maps rating, then freezing funds until 5000 INR unlock deposit is sent.",
        "claimed_organization": "StarRank Media",
        "domains": ["t.me"],
        "urls": ["https://t.me/google_review_bounty"],
        "emails": [],
        "phones_or_upi": ["+919988776655", "dailyrewards@paytm"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": True,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-TASK-303",
        "incident_title": "Hotel Booking Review Campus Part-Time Job",
        "campaign_name": "QuickTask Telegram Guild",
        "description": "Hostel student group targeted with fake TripAdvisor review tasks, demanding UPI deposit to release accumulated payout.",
        "claimed_organization": "TravelPromo Global",
        "domains": ["bit.ly"],
        "urls": ["https://bit.ly/tripadvisor-review-job", "https://chat.whatsapp.com/taskrecruit2026"],
        "emails": [],
        "phones_or_upi": ["+919988776655", "instanttask@ybl"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": True,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-TASK-304",
        "incident_title": "Crypto Micro-Arbitrage Task Ring for College Students",
        "campaign_name": "QuickTask Telegram Guild",
        "description": "Telegram bot offering automated USDT trading tasks, requiring 4500 INR initial collateral transfer.",
        "claimed_organization": "BitArbitrage Bot",
        "domains": ["t.me"],
        "urls": ["https://t.me/quicktask_india"],
        "emails": [],
        "phones_or_upi": ["+919988776655", "dailyrewards@paytm"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": True,
            "mule_account_request": False
        }
    },

    # --- SYNDICATE 5: EduAffiliate Money Mule Network (Laundering via Student Accounts) ---
    {
        "incident_id": "INC-2026-MULE-401",
        "incident_title": "Campus Payment Partner Money Mule Recruitment",
        "campaign_name": "EduAffiliate Money Mule Network",
        "description": "Recruits engineering students to receive third-party bank deposits on UPI and forward them in return for 5% commission.",
        "claimed_organization": "EduFin Remittance Club",
        "domains": ["campus-finance-network.in"],
        "urls": ["https://campus-finance-network.in/partner"],
        "emails": ["campus-partner@edu-fin.club"],
        "phones_or_upi": ["+919811223344", "mule.escrow@icici"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": False,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": True
        }
    },
    {
        "incident_id": "INC-2026-MULE-402",
        "incident_title": "Crypto P2P Student Account Rental Scheme",
        "campaign_name": "EduAffiliate Money Mule Network",
        "description": "Offers college students 2000 INR daily rent for using their GooglePay/PhonePe handles for crypto peer-to-peer exchanges.",
        "claimed_organization": "P2P Swift Exchange",
        "domains": ["campus-finance-network.in"],
        "urls": ["https://campus-finance-network.in/rent"],
        "emails": ["recruiter@edu-fin.club"],
        "phones_or_upi": ["+919811223344", "mule.escrow@icici"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": False,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": True
        }
    },
    {
        "incident_id": "INC-2026-MULE-403",
        "incident_title": "Campus Ambassador Forex Commission Syndicate",
        "campaign_name": "EduAffiliate Money Mule Network",
        "description": "Solicits student bank accounts to receive overseas educational loans, diverting stolen cybercrime funds.",
        "claimed_organization": "Global EduPay Link",
        "domains": ["campus-finance-network.in"],
        "urls": ["https://campus-finance-network.in/apply"],
        "emails": ["campus-partner@edu-fin.club"],
        "phones_or_upi": ["+919811223344", "fastpayout@icici"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": False,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": True
        }
    },

    # --- ISOLATED INDEPENDENT INCIDENTS (Negative Correlation Baseline) ---
    {
        "incident_id": "INC-2026-SOLO-501",
        "incident_title": "Chegg Fake Online Subject Tutor Scam",
        "campaign_name": "Isolated Incident",
        "description": "Fake recruitment for online computer science tutor asking 999 INR onboarding fee to dispatch answer key tablet.",
        "claimed_organization": "Chegg India Unofficial",
        "domains": ["chegg-tutors-onboard.com"],
        "urls": ["https://chegg-tutors-onboard.com/register"],
        "emails": ["hr@chegg-tutors-onboard.com"],
        "phones_or_upi": ["+917711223344", "tutorpay@okhdfcbank"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-SOLO-502",
        "incident_title": "Techno Global Unaccredited Fast-Track Degree",
        "campaign_name": "Isolated Incident",
        "description": "Offers direct backdated B.Tech degree certificates for 45,000 INR without attending exams; matches UGC fake list.",
        "claimed_organization": "Techno Global Deemed University",
        "domains": ["techno-global-univ.edu.in"],
        "urls": ["https://techno-global-univ.edu.in/degrees"],
        "emails": ["admissions@techno-global-univ.edu.in"],
        "phones_or_upi": ["+918800112233"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": True,
            "aicte_unverified": True,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-SOLO-503",
        "incident_title": "HackerEarth Spoofed Campus Contest Phishing",
        "campaign_name": "Isolated Incident",
        "description": "Phishing portal imitating HackerEarth campus assessment to harvest GitHub tokens and college portal credentials.",
        "claimed_organization": "HackerEarth Impersonator",
        "domains": ["hackerearth-liveassessment.net"],
        "urls": ["https://hackerearth-liveassessment.net/contest/campus2026"],
        "emails": ["support@hackerearth-liveassessment.net"],
        "phones_or_upi": [],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": False,
            "zero_interview": False,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-SOLO-504",
        "incident_title": "IndiGo Student Ground Crew Training Deposit",
        "campaign_name": "Isolated Incident",
        "description": "Bogus airline airport customer service job offer asking final-year students for 2500 INR medical clearance fee.",
        "claimed_organization": "IndiGo Airlines Fake HR",
        "domains": ["indigo-campus-ground.in"],
        "urls": ["https://indigo-campus-ground.in/offer"],
        "emails": ["careers@indigo-campus-ground.in"],
        "phones_or_upi": ["+919001122334", "indigo.interview@axisbank"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    },
    {
        "incident_id": "INC-2026-SOLO-505",
        "incident_title": "Freelance Form Filling Software License Charge",
        "campaign_name": "Isolated Incident",
        "description": "Student work-from-home data entry job demanding 1800 INR upfront software key fee prior to project assignment.",
        "claimed_organization": "Apex Freelance Portal",
        "domains": ["freelance-entry-work.org"],
        "urls": ["https://freelance-entry-work.org/jobs"],
        "emails": ["jobs@freelance-entry-work.org"],
        "phones_or_upi": ["dataentry.verify@sbi"],
        "github_repos": [],
        "suspicious_packages": [],
        "student_scam_flags": {
            "upfront_fee": True,
            "zero_interview": True,
            "ugc_fake_uni": False,
            "aicte_unverified": False,
            "task_scam": False,
            "mule_account_request": False
        }
    }
]


def calculate_text_similarity(text1: str, text2: str) -> float:
    """Computes combined word Jaccard and Levenshtein similarity between two texts."""
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())
    if not words1 or not words2:
        jaccard = 0.0
    else:
        jaccard = len(words1 & words2) / len(words1 | words2)
    
    seq_ratio = difflib.SequenceMatcher(None, text1.lower(), text2.lower()).ratio()
    return round((0.5 * jaccard) + (0.5 * seq_ratio), 4)


def calculate_domain_similarity(domains1: List[str], domains2: List[str]) -> float:
    """Calculates max fuzzy domain similarity across two lists of domains."""
    if not domains1 or not domains2:
        return 0.0
    max_sim = 0.0
    for d1 in domains1:
        for d2 in domains2:
            sim = difflib.SequenceMatcher(None, d1.lower(), d2.lower()).ratio()
            if sim > max_sim:
                max_sim = sim
    return round(max_sim, 4)


def extract_pair_features(inc_a: Dict[str, Any], inc_b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes statistical similarity features between two threat incidents.
    """
    # 1. Semantic / text similarity of descriptions and titles
    full_text_a = f"{inc_a['incident_title']} {inc_a['description']} {inc_a['claimed_organization']}"
    full_text_b = f"{inc_b['incident_title']} {inc_b['description']} {inc_b['claimed_organization']}"
    desc_sim = calculate_text_similarity(full_text_a, full_text_b)

    # 2. Domain similarity (fuzzy Levenshtein)
    domain_sim = calculate_domain_similarity(inc_a["domains"], inc_b["domains"])

    # 3. Exact matching counts
    shared_domains = set(inc_a["domains"]) & set(inc_b["domains"])
    # Ignore generic shorteners for shared exact domain match
    shared_domains_cleaned = {d for d in shared_domains if d not in {"bit.ly", "t.me", "telegram.org"}}
    shared_domains_count = len(shared_domains_cleaned)

    # Contacts (emails + phone/upi)
    contacts_a = set(inc_a["emails"] + inc_a["phones_or_upi"])
    contacts_b = set(inc_b["emails"] + inc_b["phones_or_upi"])
    shared_contacts = contacts_a & contacts_b
    shared_contacts_count = len(shared_contacts)

    # GitHub Repos & Suspicious Packages
    shared_repos = set(inc_a["github_repos"]) & set(inc_b["github_repos"])
    shared_repos_count = len(shared_repos)

    shared_packages = set(inc_a["suspicious_packages"]) & set(inc_b["suspicious_packages"])
    shared_packages_count = len(shared_packages)

    # Student scam flag agreement (Hamming overlap)
    flags_a = inc_a["student_scam_flags"]
    flags_b = inc_b["student_scam_flags"]
    matching_flags = sum(1 for k in flags_a if flags_a[k] and flags_b[k])

    # Ground truth connection label
    # Connected if they belong to same recognized syndicate (not 'Isolated Incident')
    # or have shared financial/domain/repo indicators
    same_syndicate = (
        inc_a["campaign_name"] == inc_b["campaign_name"] 
        and inc_a["campaign_name"] != "Isolated Incident"
    )
    has_shared_indicator = (shared_contacts_count > 0 or shared_domains_count > 0 or shared_repos_count > 0 or shared_packages_count > 0)
    
    is_connected = 1 if (same_syndicate or has_shared_indicator) else 0

    return {
        "incident_id_a": inc_a["incident_id"],
        "incident_id_b": inc_b["incident_id"],
        "campaign_a": inc_a["campaign_name"],
        "campaign_b": inc_b["campaign_name"],
        "desc_similarity": desc_sim,
        "domain_similarity": domain_sim,
        "shared_domains_count": shared_domains_count,
        "shared_contacts_count": shared_contacts_count,
        "shared_repos_count": shared_repos_count,
        "shared_packages_count": shared_packages_count,
        "shared_scam_flags_count": matching_flags,
        "is_connected_label": is_connected
    }


def generate_all_datasets() -> Tuple[Path, Path]:
    """Generates historical_incidents.json and training_pairs.csv in the data directory."""
    base_dir = Path(__file__).resolve().parent
    data_dir = base_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    json_path = data_dir / "historical_incidents.json"
    csv_path = data_dir / "training_pairs.csv"

    # Also keep a copy directly inside agent2_correlator for direct access
    json_path_direct = base_dir / "historical_incidents.json"
    csv_path_direct = base_dir / "training_pairs.csv"

    # 1. Save historical_incidents.json
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(HISTORICAL_INCIDENTS, f, indent=2)
    with open(json_path_direct, "w", encoding="utf-8") as f:
        json.dump(HISTORICAL_INCIDENTS, f, indent=2)
    print(f"Generated {len(HISTORICAL_INCIDENTS)} realistic student threat incidents.")

    # 2. Generate all unique pairs: 25 * 24 / 2 = 300 pairs!
    all_pairs = list(combinations(HISTORICAL_INCIDENTS, 2))
    training_rows = [extract_pair_features(inc_a, inc_b) for inc_a, inc_b in all_pairs]

    fieldnames = [
        "incident_id_a",
        "incident_id_b",
        "campaign_a",
        "campaign_b",
        "desc_similarity",
        "domain_similarity",
        "shared_domains_count",
        "shared_contacts_count",
        "shared_repos_count",
        "shared_packages_count",
        "shared_scam_flags_count",
        "is_connected_label"
    ]

    for target_csv in [csv_path, csv_path_direct]:
        with open(target_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(training_rows)

    pos_count = sum(1 for r in training_rows if r["is_connected_label"] == 1)
    neg_count = sum(1 for r in training_rows if r["is_connected_label"] == 0)

    print(f"Generated {len(training_rows)} training pairs for ML model training.")
    print(f"Class Distribution: {pos_count} Connected (Positive), {neg_count} Non-Connected (Negative).")
    print(f"Saved JSON: {json_path}")
    print(f"Saved CSV:  {csv_path}")

    return json_path, csv_path


if __name__ == "__main__":
    generate_all_datasets()

