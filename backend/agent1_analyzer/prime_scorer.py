"""
Factora Agent 1: P.R.I.M.E. Neuro-Symbolic Risk Scorer & Verification Checklist Generator
Synthesizes:
1. Trained Real ML Model probability & behavioral triggers.
2. OSINT Domain & URL forensics (WHOIS age, redirect hops, free forms, brand mismatches).
3. GitHub assessment repository & dependency hook audits.
4. Indian Student Registry checks (UGC Fake Uni, AICTE, scholarships.gov.in).
Outputs deterministic P.R.I.M.E. scores (0-10), fuzzy risk score (0-100), risk tier,
and mandatory interactive verification steps.
"""

import uuid
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path

from shared.schemas import (
    ThreatIndicators,
    StudentScamFlags,
    VerificationStep,
    ThreatIntelligenceRecord,
    IncidentAnalyzeRequest
)

try:
    from backend.agent1_analyzer.train_real_model import FactoraThreatDetector
except (ImportError, Exception):
    FactoraThreatDetector = None
from backend.agent1_analyzer.osint_scanners import (
    unroll_redirect_chain,
    get_domain_whois_age,
    check_wayback_history,
    detect_free_form_or_host,
    detect_brand_domain_mismatch,
    extract_text_from_screenshot,
    verify_indian_institution,
    verify_aicte_legitimacy,
    verify_government_scholarship_url
)
from backend.agent1_analyzer.github_scanner import GitHubAssessmentScanner


class PrimeNeuroSymbolicScorer:
    """Combines statistical ML predictions with deterministic symbolic cyber rules."""

    def __init__(self):
        try:
            self.ml_detector = FactoraThreatDetector.load_default() if FactoraThreatDetector is not None else None
        except Exception as e:
            print(f"[Warning] Could not load ML model ({e}). Fallback heuristic will be used.")
            self.ml_detector = None
        self.github_scanner = GitHubAssessmentScanner()

    def analyze_payload(self, req: IncidentAnalyzeRequest) -> ThreatIntelligenceRecord:
        """Master orchestrator analyzing any combination of text, URL, screenshot, or GitHub repo."""
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

        # 1. Ingestion Normalization
        text = (req.input_text or "").strip()
        url = (req.target_url or "").strip()
        repo_url = (req.github_repo_url or "").strip()
        screenshot_data = req.screenshot_base64

        ocr_result = None
        if screenshot_data:
            ocr_result = extract_text_from_screenshot(screenshot_data)
            if ocr_result.get("extracted_text"):
                text = f"{text}\n{ocr_result['extracted_text']}".strip()

        # Determine primary input type
        if repo_url:
            input_type = "github_repo"
        elif screenshot_data and not req.input_text:
            input_type = "screenshot_ocr"
        elif url and not req.input_text:
            input_type = "url"
        else:
            input_type = "email"

        # 2. Extract Base Entities from text & URL
        urls_found = list(set([url] if url else []))
        if ocr_result:
            urls_found.extend(ocr_result["detected_entities"]["urls"])

        # Also search text for URLs
        import re
        urls_found.extend(re.findall(r"https?://[^\s<>\"']+", text))
        urls_found = list(set(urls_found))

        # Unroll primary URL if present
        target_eval_url = url or (urls_found[0] if urls_found else None)
        redirect_info = unroll_redirect_chain(target_eval_url) if target_eval_url else None
        final_url = redirect_info["final_url"] if redirect_info else target_eval_url

        # Domains
        import tldextract
        domains_found = []
        if final_url:
            ext = tldextract.extract(final_url)
            if ext.domain:
                domains_found.append(f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain)

        # WHOIS Age
        domain_age = None
        is_young_domain = False
        if domains_found:
            whois_info = get_domain_whois_age(domains_found[0])
            domain_age = whois_info.get("age_days")
            is_young_domain = whois_info.get("is_new_domain", False)

        # Free form detection
        free_form_info = detect_free_form_or_host(final_url) if final_url else {"is_free_form_or_host": False}

        # Contacts & UPI
        phones_or_upi = []
        emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)
        upi_matches = re.findall(r"[\w\.\-]+@(?:okhdfcbank|oksbi|okaxis|ybl|paytm|upi|ibl|axl)", text, re.IGNORECASE)
        phones = re.findall(r"(?:\+91[\-\s]?)?[6789]\d{9}\b", text)
        phones_or_upi.extend(upi_matches)
        phones_or_upi.extend(phones)
        if ocr_result:
            phones_or_upi.extend(ocr_result["detected_entities"]["upi_handles"])
            phones_or_upi.extend(ocr_result["detected_entities"]["phones"])
            emails.extend(ocr_result["detected_entities"]["emails"])
        phones_or_upi = list(set(phones_or_upi))
        emails = list(set(emails))

        # Claimed Organization & Domain Mismatch
        claimed_org = None
        for brand in ["tcs", "tata consultancy services", "infosys", "wipro", "google", "microsoft", "amazon", "accenture", "ibm", "cognizant"]:
            if brand in text.lower():
                claimed_org = brand.upper()
                break

        mismatch_info = {"is_domain_mismatch": False}
        if claimed_org and (domains_found or emails):
            sender_check = domains_found[0] if domains_found else emails[0]
            mismatch_info = detect_brand_domain_mismatch(claimed_org, sender_check)

        # 3. GitHub Supply Chain Audit
        github_audit = None
        if repo_url or "github.com" in text:
            target_repo = repo_url or re.search(r"https?://github\.com/[\w\.\-]+/[\w\.\-]+", text)
            if target_repo:
                target_repo_str = target_repo if isinstance(target_repo, str) else target_repo.group(0)
                github_audit = self.github_scanner.audit_repository(target_repo_str)

        # 4. Indian Student Registries Check
        ugc_check = verify_indian_institution(text)
        aicte_check = verify_aicte_legitimacy(text)
        sch_check = verify_government_scholarship_url(final_url) if final_url else {"is_scholarship_phishing": False}

        # 5. ML Model Inference
        ml_prob = 0.0
        ml_signals = []
        if self.ml_detector and text:
            pred = self.ml_detector.predict_detailed(text)
            ml_prob = pred["threat_probability"]
            ml_signals = pred["triggered_signals"]

        # 6. Student Scam Flags Synthesis
        has_fee = (
            "f01_upfront_fee_signals" in ml_signals or
            any(k in text.lower() for k in ["deposit", "registration fee", "laptop fee", "caution money", "pay ₹", "pay rs"]) or
            bool(re.search(r"(?:₹|rs\.?|inr)\s*\d+", text, re.IGNORECASE))
        )
        has_zero_interview = (
            "f02_zero_interview_signals" in ml_signals or
            any(k in text.lower() for k in ["direct selection", "no interview", "without interview", "direct offer"])
        )
        has_task_scam = (
            "f03_task_scam_signals" in ml_signals or
            any(k in text.lower() for k in ["rate task", "telegram vip", "like youtube", "hotel review", "daily task"])
        )
        has_mule = (
            "f04_money_mule_signals" in ml_signals or
            any(k in text.lower() for k in ["rent bank account", "receive payment into your", "mule account", "forward 90%"])
        )

        flags = StudentScamFlags(
            upfront_fee=has_fee,
            zero_interview=has_zero_interview,
            ugc_fake_uni=ugc_check.get("is_fake_university", False),
            aicte_unverified=aicte_check.get("is_suspicious_claim", False),
            task_scam=has_task_scam,
            mule_account_request=has_mule
        )

        # 7. Compute P.R.I.M.E. 6-Criteria Scores (0.0 to 10.0)
        # P: Proof & Domain Identity
        score_p = 2.0
        if is_young_domain: score_p += 4.0
        if mismatch_info.get("is_domain_mismatch"): score_p += 4.5
        if mismatch_info.get("is_free_webmail"): score_p += 3.0
        score_p = min(10.0, score_p)

        # R: Redirection & Obfuscation
        score_r = 1.0
        if redirect_info and redirect_info.get("hop_count", 0) > 0: score_r += 3.5
        if free_form_info.get("is_free_form_or_host"): score_r += 5.0
        score_r = min(10.0, score_r)

        # I: Incentive & Urgency
        score_i = 1.0
        if "f05_urgency_pressure_signals" in ml_signals: score_i += 3.5
        if "f06_unrealistic_stipend_claims" in ml_signals: score_i += 4.0
        if has_zero_interview: score_i += 2.5
        score_i = min(10.0, score_i)

        # M: Money & Transaction Ask
        score_m = 1.0
        if has_fee: score_m += 6.5
        if upi_matches or "f11_upi_or_payment_keyword_found" in ml_signals: score_m += 3.0
        score_m = min(10.0, score_m)

        # E: Execution & Code Safety
        score_e = 1.0
        if github_audit:
            if github_audit.get("is_compromised_repo"): score_e = 9.8
            elif github_audit.get("red_flags"): score_e = 6.5
            else: score_e = 2.0
        elif "f15_assessment_script_or_package_lure" in ml_signals:
            score_e = 7.0
        score_e = min(10.0, score_e)

        # S: Student Registry & Compliance
        score_s = 1.0
        if flags.ugc_fake_uni: score_s = 10.0
        elif sch_check.get("is_scholarship_phishing"): score_s = 10.0
        elif flags.task_scam or flags.mule_account_request: score_s = 8.5
        elif flags.aicte_unverified: score_s = 6.0
        score_s = min(10.0, score_s)

        prime_scores = {
            "proof_domain_identity": round(score_p, 1),
            "redirection_obfuscation": round(score_r, 1),
            "incentive_urgency": round(score_i, 1),
            "money_transaction_ask": round(score_m, 1),
            "execution_code_safety": round(score_e, 1),
            "student_registry_check": round(score_s, 1)
        }

        # 8. Fuzzy Risk Index Calculation (0 to 100)
        # Weights: P: 20%, R: 15%, I: 15%, M: 25%, E: 15%, S: 10%
        base_fuzzy = (
            score_p * 2.0 +
            score_r * 1.5 +
            score_i * 1.5 +
            score_m * 2.5 +
            score_e * 1.5 +
            score_s * 1.0
        )
        # Factor in ML probability
        fuzzy_risk = (base_fuzzy * 0.70) + (ml_prob * 100.0 * 0.30)

        # Hard overrides for critical student hazards
        if flags.ugc_fake_uni or sch_check.get("is_scholarship_phishing") or (github_audit and github_audit.get("is_compromised_repo")):
            fuzzy_risk = max(fuzzy_risk, 94.0)
        elif flags.upfront_fee and mismatch_info.get("is_domain_mismatch"):
            fuzzy_risk = max(fuzzy_risk, 88.0)
        elif flags.upfront_fee or flags.task_scam or flags.mule_account_request:
            fuzzy_risk = max(fuzzy_risk, 76.0)

        fuzzy_risk = round(min(100.0, max(0.0, fuzzy_risk)), 1)

        # Risk Tier
        if fuzzy_risk >= 85.0:
            risk_tier = "Critical Scam"
        elif fuzzy_risk >= 70.0:
            risk_tier = "High Risk"
        elif fuzzy_risk >= 45.0:
            risk_tier = "Caution"
        elif fuzzy_risk >= 20.0:
            risk_tier = "Low Risk"
        else:
            risk_tier = "Verified Safe"

        # 9. Evidence Bullet Summary (Why It Is Risky)
        why_risky = []
        if mismatch_info.get("is_domain_mismatch"):
            why_risky.append(mismatch_info.get("alert"))
        if is_young_domain:
            why_risky.append(f"Domain registered only {domain_age} days ago (temporary phishing infrastructure).")
        if free_form_info.get("is_free_form_or_host"):
            why_risky.append(free_form_info.get("risk_explanation"))
        if flags.upfront_fee:
            why_risky.append("Demands upfront monetary payment (security deposit, registration, or kit charges) which violates employment laws.")
        if flags.zero_interview:
            why_risky.append("Direct selection letter issued with zero technical interview or standard applicant vetting.")
        if flags.task_scam:
            why_risky.append("Task-based fraud pattern: promise of daily payout for YouTube likes/ratings via Telegram channel.")
        if flags.mule_account_request:
            why_risky.append("Student money-mule solicitation: asking to receive and transfer funds via personal UPI/bank account.")
        if flags.ugc_fake_uni:
            why_risky.append(f"CRITICAL: Institution matches official UGC Fake University registry ({ugc_check.get('matched_institution')}).")
        if sch_check.get("is_scholarship_phishing"):
            why_risky.append(sch_check.get("warning"))
        if github_audit and github_audit.get("red_flags"):
            why_risky.extend(github_audit["red_flags"])

        if not why_risky:
            if ml_prob < 0.20:
                why_risky.append("No active malicious indicators detected across domain, ML threat classification, or registry checks.")
            else:
                why_risky.append("Contains generic recruitment copy with elevated linguistic urgency patterns.")

        # 10. Mandatory Interactive Verification Checklist
        checklist = self._build_verification_checklist(flags, mismatch_info, github_audit, sch_check, target_eval_url)

        # Assembled Threat Indicators
        indicators = ThreatIndicators(
            urls=urls_found,
            unrolled_final_urls=[final_url] if final_url else [],
            domains=domains_found,
            domain_age_days=domain_age,
            uses_free_form_or_host=free_form_info.get("is_free_form_or_host", False),
            emails=emails,
            phones_or_upi=phones_or_upi,
            claimed_organization=claimed_org,
            official_domain_mismatch=mismatch_info.get("is_domain_mismatch", False),
            github_repos=[repo_url] if repo_url else ([] if not github_audit else [github_audit["repo_url"]]),
            suspicious_packages=github_audit.get("npm_manifest_scan", {}).get("suspicious_packages", []) if github_audit else [],
            student_scam_flags=flags
        )

        return ThreatIntelligenceRecord(
            incident_id=incident_id,
            input_type=input_type,
            extracted_indicators=indicators,
            prime_criteria_scores=prime_scores,
            fuzzy_risk_score=fuzzy_risk,
            risk_tier=risk_tier,
            why_it_is_risky_summary=why_risky,
            verify_before_proceeding_checklist=checklist
        )

    def _build_verification_checklist(
        self,
        flags: StudentScamFlags,
        mismatch_info: Dict[str, Any],
        github_audit: Optional[Dict[str, Any]],
        sch_check: Dict[str, Any],
        url: Optional[str]
    ) -> List[VerificationStep]:
        """Constructs customized, actionable pre-action verification steps for the student."""
        steps = []

        # Step 1: Upfront Payment & Never-Pay Rule
        if flags.upfront_fee:
            steps.append(VerificationStep(
                step_title="Enforce Never-Pay Policy (Zero Monetary Transfer)",
                why_it_matters="Legitimate employers and campus recruiters NEVER demand refundable laptop deposits, gateway fees, or training bonds.",
                action_url_or_instruction="Do NOT initiate any UPI or net-banking transfer. Immediately block the payment request.",
                is_mandatory=True
            ))

        # Step 2: Domain & Official Careers Portal Check
        if mismatch_info.get("is_domain_mismatch"):
            brand = mismatch_info.get("matched_brand", "company").upper()
            steps.append(VerificationStep(
                step_title=f"Verify on Official {brand} Careers Portal",
                why_it_matters=f"The sender used an unofficial domain ('{mismatch_info.get('sender_domain')}'). Scammers impersonate recognized brands using lookalike domains.",
                action_url_or_instruction=f"Open a new browser tab, go directly to the verified corporate site ({', '.join(mismatch_info.get('official_domains', []))}), and verify candidate status in the hiring portal.",
                is_mandatory=True
            ))
        else:
            steps.append(VerificationStep(
                step_title="Cross-check Sender Email & Official Domain",
                why_it_matters="Always confirm that communication originates from the authentic corporate domain, not public webmail like @gmail.com.",
                action_url_or_instruction="Inspect the raw email headers (SPF and DKIM pass) before downloading attachments.",
                is_mandatory=False
            ))

        # Step 3: GitHub Code & Workspace Trust Check
        if github_audit:
            steps.append(VerificationStep(
                step_title="Audit Repository Tasks & Do NOT Open in VS Code with Workspace Trust",
                why_it_matters="Coding interview assignments often conceal remote code execution hooks in .vscode/tasks.json or package.json postinstall scripts.",
                action_url_or_instruction="Do not run 'npm install' or 'yarn'. Review package.json scripts and .vscode folder in a plain text editor first.",
                is_mandatory=True
            ))

        # Step 4: Campus Placement Officer (TPO) Validation
        steps.append(VerificationStep(
            step_title="Consult College Training & Placement Cell (TPO)",
            why_it_matters="Any genuine on-campus or pooled campus recruitment drive is officially scheduled and vetted by your college TPO office.",
            action_url_or_instruction="Forward the message or offer letter to your college TPO desk or placement coordinator for whitelist verification.",
            is_mandatory=True
        ))

        # Step 5: Official Govt Portal Check for Scholarships
        if sch_check.get("is_scholarship_phishing") or "scholarship" in (url or "").lower():
            steps.append(VerificationStep(
                step_title="Verify National Scholarship Portal (scholarships.gov.in)",
                why_it_matters="All legitimate Indian central and state government scholarships are administered exclusively through scholarships.gov.in.",
                action_url_or_instruction="Visit https://scholarships.gov.in and check your application ID directly on the official portal.",
                is_mandatory=True
            ))

        # Step 6: Cyber Crime Reporting Step
        steps.append(VerificationStep(
            step_title="File Pre-emptive Report on CyberCrime.gov.in If Money Was Demanded",
            why_it_matters="Reporting scammer UPI IDs and WhatsApp numbers helps law enforcement freeze fraudulent bank accounts before other students are victimized.",
            action_url_or_instruction="Visit https://cybercrime.gov.in or dial National Cyber Crime Helpline 1930.",
            is_mandatory=False
        ))

        return steps

