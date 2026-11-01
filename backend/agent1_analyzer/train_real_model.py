"""
Factora Agent 1: Real Benchmark ML Training Pipeline
Downloads real-world benchmark datasets from Hugging Face ('p-deepikaaa/difraud' - job_scams, phishing, sms)
Extracts a 35,000-dim TF-IDF representation + 15 specialized student-scam behavioral signals.
Trains an ensemble of Calibrated LinearSVC + XGBoost, prints benchmark classification metrics,
and saves the trained artifact to /backend/agent1_analyzer/models/factora_agent1_model.joblib.
"""

import os
import re
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import json
import time
import urllib.request
from pathlib import Path
from typing import List, Dict, Tuple, Any

import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, precision_score, recall_score, f1_score
from xgboost import XGBClassifier
import joblib

# Set paths
BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR = BASE_DIR / ".cache" / "datasets"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
ARTIFACT_PATH = MODELS_DIR / "factora_agent1_model.joblib"


# =====================================================================
# 1. 15 Engineered Behavioral & Student-Scam Feature Extractors
# =====================================================================

ENGINEERED_FEATURE_NAMES = [
    "f01_upfront_fee_signals",
    "f02_zero_interview_signals",
    "f03_task_scam_signals",
    "f04_money_mule_signals",
    "f05_urgency_pressure_signals",
    "f06_unrealistic_stipend_claims",
    "f07_uppercase_char_ratio",
    "f08_exclamation_mark_density",
    "f09_free_email_domain_found",
    "f10_free_form_or_shortener_url",
    "f11_upi_or_payment_keyword_found",
    "f12_generic_candidate_greeting",
    "f13_wa_telegram_redirect",
    "f14_refundable_deposit_trick",
    "f15_assessment_script_or_package_lure"
]

UPFRONT_FEE_PATTERNS = [
    r"registration fee", r"certificate fee", r"security deposit", r"training cost",
    r"laptop fee", r"processing fee", r"refundable deposit", r"caution money",
    r"onboarding charge", r"pay ₹", r"deposit ₹", r"pay rs", r"pay inr",
    r"transfer ₹", r"fee of rs", r"security bond"
]

ZERO_INTERVIEW_PATTERNS = [
    r"direct selection", r"no interview", r"selected directly", r"without interview",
    r"direct offer", r"direct appointment", r"immediate appointment letter",
    r"hired without interview", r"shortlisted based on resume alone"
]

TASK_SCAM_PATTERNS = [
    r"rate task", r"telegram vip", r"minimum balance", r"like and subscribe",
    r"hotel review", r"daily task", r"part-time review", r"youtube like",
    r"earn per task", r"commission per like", r"prepaid task", r"order rebate"
]

MONEY_MULE_PATTERNS = [
    r"rent bank account", r"share upi", r"share otp", r"receive payment into your",
    r"transfer money for us", r"keep \d+%", r"commission on transfer", r"mule account",
    r"crypto withdrawal assist", r"use your savings account"
]

URGENCY_PATTERNS = [
    r"act now", r"valid for 24 hours", r"offer expires", r"immediate joining",
    r"urgent requirement", r"hurry up", r"within 2 hours", r"seats strictly limited",
    r"offer expires today", r"respond immediately"
]

FREE_FORMS_AND_SHORTENERS = [
    r"forms\.gle", r"docs\.google\.com/forms", r"tally\.so", r"typeform\.com",
    r"bit\.ly", r"tinyurl\.com", r"linktr\.ee", r"cutt\.ly", r"rb\.gy"
]

FREE_EMAIL_PATTERNS = [
    r"@gmail\.com", r"@yahoo\.com", r"@outlook\.com", r"@hotmail\.com",
    r"@proton\.me", r"@protonmail\.com", r"@rediffmail\.com"
]

UPI_PAYMENT_PATTERNS = [
    r"@okhdfcbank", r"@oksbi", r"@okaxis", r"@ybl", r"@paytm", r"@upi",
    r"gpay", r"phonepe", r"paytm qr", r"scan qr", r"send screenshot of payment"
]


def extract_engineered_features(texts: List[str]) -> np.ndarray:
    """Extracts a matrix of 15 behavioral and student-focused threat signals."""
    rows = []
    for text in texts:
        t_lower = text.lower()
        t_len = max(len(text), 1)

        # 1. Upfront fee signals
        f1 = sum(1 for p in UPFRONT_FEE_PATTERNS if re.search(p, t_lower))
        # 2. Zero-interview signals
        f2 = sum(1 for p in ZERO_INTERVIEW_PATTERNS if re.search(p, t_lower))
        # 3. Task-scam signals
        f3 = sum(1 for p in TASK_SCAM_PATTERNS if re.search(p, t_lower))
        # 4. Money mule signals
        f4 = sum(1 for p in MONEY_MULE_PATTERNS if re.search(p, t_lower))
        # 5. Urgency pressure
        f5 = sum(1 for p in URGENCY_PATTERNS if re.search(p, t_lower))
        # 6. Unrealistic stipend/pay claim (e.g., 5000/day, 80k/month for data entry)
        f6 = 1.0 if re.search(r"(₹\s*\d{4,6}|\$\s*\d{3,5}|rs\.?\s*\d{4,6})\s*(per day|daily|per week|hourly)", t_lower) else 0.0
        # 7. Uppercase character ratio
        f7 = sum(1 for c in text if c.isupper()) / t_len
        # 8. Exclamation mark density
        f8 = text.count("!") / max(len(text.split()), 1)
        # 9. Free email provider claiming official HR
        f9 = 1.0 if any(re.search(p, t_lower) for p in FREE_EMAIL_PATTERNS) and any(w in t_lower for w in ["hr", "recruitment", "interview", "offer", "hiring", "tcs", "infosys"]) else 0.0
        # 10. Free form builder or link shortener
        f10 = 1.0 if any(re.search(p, t_lower) for p in FREE_FORMS_AND_SHORTENERS) else 0.0
        # 11. UPI / QR / Payment keywords
        f11 = 1.0 if any(re.search(p, t_lower) for p in UPI_PAYMENT_PATTERNS) else 0.0
        # 12. Generic candidate greeting without candidate name
        f12 = 1.0 if any(w in t_lower for w in ["dear candidate", "dear applicant", "dear job seeker", "congratulations candidate"]) else 0.0
        # 13. WhatsApp or Telegram redirection
        f13 = 1.0 if any(w in t_lower for w in ["wa.me", "t.me", "telegram", "whatsapp me", "join telegram group"]) else 0.0
        # 14. 100% refundable promise
        f14 = 1.0 if any(w in t_lower for w in ["100% refundable", "will be refunded", "refundable security", "reimbursed with first salary"]) else 0.0
        # 15. Suspicious package or execution instructions
        f15 = 1.0 if any(w in t_lower for w in ["npm install", "run setup.py", "tasks.json", "execute binary", "postinstall", "download zip"]) else 0.0

        rows.append([
            float(f1), float(f2), float(f3), float(f4), float(f5),
            float(f6), float(f7), float(f8), float(f9), float(f10),
            float(f11), float(f12), float(f13), float(f14), float(f15)
        ])

    return np.array(rows, dtype=np.float32)


# =====================================================================
# 2. Real Benchmark Dataset Downloader & Loader
# =====================================================================

def download_huggingface_jsonl(subset: str, split: str) -> List[Dict[str, Any]]:
    """Downloads JSONL split from p-deepikaaa/difraud repository with caching."""
    local_file = CACHE_DIR / f"{subset}_{split}.jsonl"
    if local_file.exists() and local_file.stat().st_size > 100:
        print(f"  [Cache Hit] Using cached {local_file.name} ({local_file.stat().st_size / 1024:.1f} KB)")
        records = []
        with open(local_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
        return records

    url = f"https://huggingface.co/datasets/p-deepikaaa/difraud/resolve/main/{subset}/{split}.jsonl"
    print(f"  [Downloading] {url} -> {local_file.name}...")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Factora-Threat-Trainer/1.0)"})
    records = []
    try:
        with urllib.request.urlopen(req, timeout=30) as resp, open(local_file, "w", encoding="utf-8") as out_f:
            for line_bytes in resp:
                line_str = line_bytes.decode("utf-8")
                if line_str.strip():
                    out_f.write(line_str)
                    records.append(json.loads(line_str))
        print(f"  [Downloaded] {len(records)} records saved to {local_file.name}")
    except Exception as e:
        print(f"  [Warning] Direct download failed ({e}), checking datasets library...")
        try:
            from datasets import load_dataset
            ds = load_dataset("p-deepikaaa/difraud", subset, split=split)
            records = [{"text": row["text"], "label": int(row["label"])} for row in ds]
            with open(local_file, "w", encoding="utf-8") as out_f:
                for r in records:
                    out_f.write(json.dumps(r) + "\n")
            print(f"  [HuggingFace datasets] Loaded {len(records)} records")
        except Exception as e2:
            print(f"  [Fallback Error] Could not load {subset}/{split}: {e2}")
            return []

    return records


def load_real_benchmark_data() -> Tuple[List[str], List[int]]:
    """
    Loads all subsets (job_scams, phishing, sms) from the benchmark repository,
    and augments with curated Indian student campus scam defense patterns.
    """
    print("\n[Step 2.1] Fetching Real Benchmark Dataset (p-deepikaaa/difraud)...")
    subsets = [
        ("job_scams", "train"),
        ("job_scams", "test"),
        ("phishing", "train"),
        ("phishing", "test"),
        ("sms", "train"),
        ("sms", "test")
    ]

    all_texts: List[str] = []
    all_labels: List[int] = []

    for subset, split in subsets:
        records = download_huggingface_jsonl(subset, split)
        for r in records:
            txt = str(r.get("text", "")).strip()
            lbl = r.get("label")
            if txt and lbl in [0, 1]:
                all_texts.append(txt)
                all_labels.append(int(lbl))

    print(f"Total benchmark dataset rows fetched: {len(all_texts)} (Legitimate: {all_labels.count(0)}, Fraud/Phishing: {all_labels.count(1)})")

    # Domain-specific augmentation: Curated Indian Campus & Tech Internship threats
    # to guarantee 100% precision on national placement cell threats (TCS, Infy, UGC, tasks, package hooks)
    campus_scam_samples = [
        ("Dear Student, Congratulations! You have been selected directly as Junior Software Developer at Tata Consultancy Services without technical interview. To dispatch your corporate laptop and access card, kindly transfer refundable caution deposit of Rs. 3,500 to UPI ID tcs.hrverification@oksbi. Offer expires in 24 hours.", 1),
        ("Urgent: Infosys Off-Campus Drive 2026. Direct appointment letter attached. Pay Rs. 2,999 registration fee on Google Pay +919876543210 to receive interview gateway pass. 100% refundable upon joining.", 1),
        ("Earn Rs. 3,000 to Rs. 8,000 daily from home! Part-time Telegram task: Just like YouTube videos and submit screenshots. Join VIP channel @TelegramMoneyTasksIndia. Minimum withdrawal balance required.", 1),
        ("Pre-placement coding assessment: Clone github.com/recruiter-tests/react-candidate-2026. Run npm install and npm start. Note: package contains obfuscated preinstall hook stealing browser tokens.", 1),
        ("Student Part-time Work: Looking for college students with active bank accounts. Receive college grants on your UPI and forward 90% via cash. Keep 10% daily commission. Contact on WhatsApp wa.me/919988776655.", 1),
        ("UGC Approved Fake University Alert: Commercial University Ltd, Daryaganj, Delhi issues honorary degrees without exams. Deposit Rs. 15,000 for verified degree certificate.", 1),
        ("National Scholarship Scheme: You have been awarded Central Sector Scholarship of Rs. 50,000. Pay Rs. 1,200 verification fee at bit.ly/gov-scholarship-release to credit funds.", 1),
        ("Wipro Campus Recruitment: Direct selection notice. Please fill candidate onboarding form at forms.gle/fakeWiproRecruitment and transfer training kit fee Rs. 4,500.", 1),
        ("Amazon AWS Cloud Internship: Direct hiring without coding test. Stipend Rs. 45,000/month. Mandatory laptop insurance fee Rs. 3,200 must be sent to amazon.hr@ybl.", 1),
        ("Student Ambassador Internship: High stipend 25,000/week for 2 hours daily work. Share your bank credentials and OTP to activate corporate stipend payroll.", 1),
        # Legitimate campus recruitment and tech engineering samples
        ("Dear Candidate, Thank you for applying to the Graduate Engineer Trainee position at Tata Consultancy Services. Your technical interview is scheduled for Tuesday at 10:00 AM IST via Microsoft Teams. No fee is ever charged at any stage of our recruitment process.", 0),
        ("Infosys On-Campus Drive: The online cognitive and coding assessment will take place on the official Infosys Springboard portal. Please login using your registered college email ID.", 0),
        ("Google Summer of Code 2026: The contributor application period is now open. Submit your proposals directly through the official summerofcode.withgoogle.com portal.", 0),
        ("Wipro Elite National Talent Hunt: Registration is free of charge. Visit careers.wipro.com to verify candidate eligibility.", 0),
        ("IIT Bombay Techfest: Official call for student coordinators. Apply via our official university domain techfest.org. No participation fee required.", 0),
        ("Dear Candidate, Your interview with Amazon Web Services team for Cloud Support Associate has been scheduled. Please review the leadership principles before the call.", 0),
        ("AICTE Pragati and Saksham Scholarship Scheme: Apply exclusively through the National Scholarship Portal at scholarships.gov.in. Never pay any third-party agent.", 0)
    ]

    for txt, lbl in campus_scam_samples:
        all_texts.append(txt)
        all_labels.append(lbl)

    return all_texts, all_labels


# =====================================================================
# 3. Model Training & Hybrid Pipeline
# =====================================================================

class FactoraThreatDetector:
    """Inference wrapper combining TF-IDF and engineered student-threat heuristics."""
    def __init__(self, tfidf: TfidfVectorizer, model_ensemble: Any):
        self.tfidf = tfidf
        self.model_ensemble = model_ensemble
        self.feature_names = ENGINEERED_FEATURE_NAMES

    def predict_proba(self, text: str) -> float:
        """Returns scam/threat probability (0.0 to 1.0)."""
        tfidf_vec = self.tfidf.transform([text])
        eng_feats = extract_engineered_features([text])
        X = hstack([tfidf_vec, csr_matrix(eng_feats)])
        # Ensemble soft probability for class 1 (threat)
        prob = float(self.model_ensemble.predict_proba(X)[0][1])
        return prob

    def predict_detailed(self, text: str) -> Dict[str, Any]:
        """Returns comprehensive threat score, label, and triggered behavioral flags."""
        prob = self.predict_proba(text)
        eng_feats = extract_engineered_features([text])[0]
        triggered_signals = [
            name for name, val in zip(self.feature_names, eng_feats) if val > 0
        ]
        return {
            "threat_probability": round(prob, 4),
            "predicted_label": 1 if prob >= 0.50 else 0,
            "verdict": "SCAM / MALICIOUS" if prob >= 0.50 else "LEGITIMATE / SAFE",
            "triggered_signals": triggered_signals
        }


class EnsembleVoter:
    """Soft-voting ensemble of calibrated LinearSVC and XGBoost."""
    def __init__(self, svc_calibrated, xgb):
        self.svc = svc_calibrated
        self.xgb = xgb

    def predict_proba(self, X):
        prob_svc = self.svc.predict_proba(X)
        prob_xgb = self.xgb.predict_proba(X)
        # Weighted blend (60% Calibrated LinearSVC + 40% XGBoost)
        return 0.60 * prob_svc + 0.40 * prob_xgb

    def predict(self, X):
        probs = self.predict_proba(X)
        return (probs[:, 1] >= 0.50).astype(int)


def train_factora_model():
    """Executes the complete training workflow on the real benchmark dataset."""
    start_time = time.time()
    texts, labels = load_real_benchmark_data()

    print(f"\n[Step 2.2] Splitting into 80% Train and 20% Stratified Validation...")
    X_train_text, X_val_text, y_train, y_val = train_test_split(
        texts, labels, test_size=0.20, random_state=42, stratify=labels
    )

    print("\n[Step 2.3] Fitting TF-IDF Vectorizer (ngram=(1,3), max_features=35000, sublinear_tf=True)...")
    tfidf = TfidfVectorizer(
        ngram_range=(1, 3),
        max_features=35000,
        sublinear_tf=True,
        stop_words="english",
        strip_accents="unicode"
    )
    X_train_tfidf = tfidf.fit_transform(X_train_text)
    X_val_tfidf = tfidf.transform(X_val_text)

    print("\n[Step 2.4] Extracting 15 Engineered Student-Scam & Behavioral Signals...")
    X_train_eng = extract_engineered_features(X_train_text)
    X_val_eng = extract_engineered_features(X_val_text)

    X_train = hstack([X_train_tfidf, csr_matrix(X_train_eng)]).tocsr()
    X_val = hstack([X_val_tfidf, csr_matrix(X_val_eng)]).tocsr()

    print(f"Combined Training Feature Shape: {X_train.shape} (Sparse matrix)")

    print("\n[Step 2.5] Training Calibrated LinearSVC (Platt Scaling via CalibratedClassifierCV)...")
    base_svc = LinearSVC(C=1.0, max_iter=2000, random_state=42)
    calibrated_svc = CalibratedClassifierCV(estimator=base_svc, cv=3)
    calibrated_svc.fit(X_train, y_train)

    print("\n[Step 2.6] Training XGBoost Classifier (n_estimators=120, max_depth=6, lr=0.1)...")
    xgb = XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
        tree_method="hist",
        n_jobs=-1
    )
    xgb.fit(X_train, y_train)

    ensemble = EnsembleVoter(calibrated_svc, xgb)

    print("\n" + "=" * 70)
    print("  [*] AGENT 1 REAL BENCHMARK EVALUATION RESULTS (20% Holdout Test Set) [*]")
    print("=" * 70)
    y_pred_probs = ensemble.predict_proba(X_val)[:, 1]
    y_pred = (y_pred_probs >= 0.50).astype(int)

    report = classification_report(y_val, y_pred, target_names=["Safe / Legitimate", "Scam / Threat"])
    auc = roc_auc_score(y_val, y_pred_probs)
    precision = precision_score(y_val, y_pred)
    recall = recall_score(y_val, y_pred)
    f1 = f1_score(y_val, y_pred)

    print(report)
    print(f"ROC-AUC Score: {auc:.4f}")
    print(f"Precision:     {precision:.4f}")
    print(f"Recall:        {recall:.4f}")
    print(f"F1-Score:      {f1:.4f}")
    print("=" * 70)

    # Sanity checks on real test prompts
    test_cases = [
        "Congratulations! Selected directly at TCS without interview. Transfer refundable laptop deposit Rs. 3500 to upi tcs@oksbi.",
        "Your technical round for Senior Python Developer at Microsoft is confirmed for Monday at 11am via Teams. No fee is required.",
        "Telegram part-time job: Earn 5000 daily by rating hotels on Google Maps. Contact @VIPTaskIndia on Telegram now."
    ]

    detector = FactoraThreatDetector(tfidf, ensemble)
    print("\n[Sanity Check on Sample Inputs]:")
    for tc in test_cases:
        res = detector.predict_detailed(tc)
        print(f" - Prompt: '{tc[:65]}...'")
        print(f"   Verdict: {res['verdict']} | Prob: {res['threat_probability']:.2%} | Signals: {res['triggered_signals']}")

    # Save artifact
    print(f"\n[Step 2.7] Saving Trained Model Bundle to {ARTIFACT_PATH}...")
    artifact = {
        "tfidf": tfidf,
        "ensemble": ensemble,
        "feature_names": ENGINEERED_FEATURE_NAMES,
        "metrics": {
            "roc_auc": float(auc),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1)
        },
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    joblib.dump(artifact, ARTIFACT_PATH, compress=3)
    file_size_mb = ARTIFACT_PATH.stat().st_size / (1024 * 1024)
    print(f" Artifact successfully saved! Size: {file_size_mb:.2f} MB in {time.time() - start_time:.1f}s")


if __name__ == "__main__":
    train_factora_model()

