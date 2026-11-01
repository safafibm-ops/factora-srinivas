"""
Factora Agent 1: OSINT Forensics, Screenshot OCR & Indian Student Registry Verifier
Provides real-world security checks:
1. URL & Domain Forensics (Redirect unrolling, WHOIS age < 90 days, Wayback CDX footprint, Free form abuse).
2. Screenshot OCR & Multimodal Vision Entity Extractor (pytesseract + API fallback).
3. Indian Student Registry Verifier (Official UGC Fake Universities DB, AICTE claims, scholarships.gov.in validation).
"""

import os
import re
import json
import base64
import io
import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
import tldextract

try:
    import whois
except ImportError:
    whois = None

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    import pytesseract
except ImportError:
    pytesseract = None


BASE_DIR = Path(__file__).resolve().parent
UGC_REGISTRY_PATH = BASE_DIR / "ugc_fake_universities.json"

# Load UGC Registry once into memory
UGC_FAKE_UNIVERSITIES = []
if UGC_REGISTRY_PATH.exists():
    try:
        with open(UGC_REGISTRY_PATH, "r", encoding="utf-8") as f:
            UGC_FAKE_UNIVERSITIES = json.load(f)
    except Exception as e:
        print(f"[Warning] Failed to load UGC registry: {e}")


# =====================================================================
# 1. URL & Domain OSINT Forensics
# =====================================================================

FREE_FORM_HOSTS = {
    "forms.gle", "docs.google.com", "tally.so", "typeform.com",
    "forms.office.com", "linktr.ee", "notion.site", "carrd.co",
    "canva.site", "sites.google.com"
}

GENUINE_BRAND_DOMAINS = {
    "tata consultancy services": ["tcs.com"],
    "tcs": ["tcs.com"],
    "infosys": ["infosys.com", "infy.com"],
    "wipro": ["wipro.com"],
    "google": ["google.com", "google.co.in", "withgoogle.com"],
    "microsoft": ["microsoft.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.jobs"],
    "accenture": ["accenture.com"],
    "ibm": ["ibm.com"],
    "cognizant": ["cognizant.com"],
    "hcl": ["hcltech.com", "hcl.com"],
    "tech mahindra": ["techmahindra.com"],
    "deloitte": ["deloitte.com"],
    "capgemini": ["capgemini.com"]
}


def strip_tracking_params(url: str) -> str:
    """Removes common marketing/tracking parameters (utm_*, ref, fbclid) from a URL."""
    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        filtered_query = {
            k: v for k, v in query.items()
            if not k.startswith("utm_") and k not in ["fbclid", "gclid", "ref", "source", "wa_bulk"]
        }
        new_query = urlencode(filtered_query, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    except Exception:
        return url


def unroll_redirect_chain(start_url: str, max_hops: int = 7) -> Dict[str, Any]:
    """
    Follows HTTP redirect chains for shorteners (bit.ly, tinyurl, t.co, etc.)
    and returns all intermediate hops and the final destination URL.
    """
    if not start_url.startswith(("http://", "https://")):
        start_url = "https://" + start_url

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    })

    hops = []
    current_url = start_url
    final_url = start_url
    error = None

    try:
        response = session.get(start_url, allow_redirects=True, timeout=8, stream=True)
        for r in response.history:
            hops.append({
                "url": r.url,
                "status_code": r.status_code,
                "location": r.headers.get("Location")
            })
        final_url = response.url
    except requests.exceptions.RequestException as e:
        error = str(e)

    extracted = tldextract.extract(final_url)
    registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

    return {
        "original_url": start_url,
        "final_url": final_url,
        "clean_final_url": strip_tracking_params(final_url),
        "registered_domain": registered_domain,
        "hop_count": len(hops),
        "redirect_history": hops,
        "is_shortened": len(hops) > 0 or any(s in start_url for s in ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly"]),
        "error": error
    }


def get_domain_whois_age(domain: str) -> Dict[str, Any]:
    """
    Queries live WHOIS data to determine the domain registration age in days.
    Domains younger than 90 days are flagged as critical high-risk phishing indicators.
    """
    extracted = tldextract.extract(domain)
    root_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else domain

    if not whois:
        return {"domain": root_domain, "age_days": None, "is_new_domain": False, "note": "whois package unavailable"}

    try:
        w = whois.whois(root_domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {"domain": root_domain, "age_days": None, "is_new_domain": False, "note": "creation_date absent"}

        if isinstance(creation_date, str):
            for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y"):
                try:
                    creation_date = datetime.datetime.strptime(creation_date, fmt)
                    break
                except ValueError:
                    pass

        if hasattr(creation_date, "tzinfo") and creation_date.tzinfo:
            creation_date = creation_date.replace(tzinfo=None)

        now = datetime.datetime.utcnow()
        age_days = (now - creation_date).days if isinstance(creation_date, datetime.datetime) else None
        is_new = (age_days is not None and age_days < 90)

        return {
            "domain": root_domain,
            "creation_date": str(creation_date),
            "age_days": age_days,
            "is_new_domain": is_new,
            "high_risk_flag": is_new,
            "registrar": str(getattr(w, "registrar", "Unknown"))
        }
    except Exception as e:
        return {
            "domain": root_domain,
            "age_days": None,
            "is_new_domain": False,
            "error": str(e)
        }


def check_wayback_history(domain: str) -> Dict[str, Any]:
    """
    Queries the Wayback Machine CDX API to inspect historical internet presence.
    A complete lack of web history for a supposed established corporation is a major red flag.
    """
    try:
        cdx_url = f"https://archive.org/wayback/available?url={domain}"
        resp = requests.get(cdx_url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            archived = data.get("archived_snapshots", {})
            has_snapshot = "closest" in archived
            snapshot_details = archived.get("closest", {})
            return {
                "domain": domain,
                "has_historical_snapshots": has_snapshot,
                "first_seen_snapshot": snapshot_details.get("timestamp"),
                "snapshot_url": snapshot_details.get("url")
            }
    except Exception as e:
        return {"domain": domain, "has_historical_snapshots": False, "error": str(e)}

    return {"domain": domain, "has_historical_snapshots": False}


def detect_free_form_or_host(url: str) -> Dict[str, Any]:
    """Detects if an official recruitment or application intake is abusing free form builders."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()

    is_free_form = any(f_host in host for f_host in FREE_FORM_HOSTS)
    form_type = None

    if "forms.gle" in host or "docs.google.com/forms" in (host + path):
        form_type = "Google Forms"
    elif "tally.so" in host:
        form_type = "Tally Form"
    elif "typeform.com" in host:
        form_type = "Typeform"
    elif "forms.office.com" in host:
        form_type = "Microsoft Forms"
    elif "linktr.ee" in host:
        form_type = "Linktree"

    return {
        "url": url,
        "is_free_form_or_host": is_free_form,
        "form_provider": form_type,
        "risk_explanation": (
            f"Legitimate multinational corporations do not collect resumes or offer letters on free public forms ({form_type})."
            if is_free_form else None
        )
    }


def detect_brand_domain_mismatch(claimed_organization: str, sender_domain_or_email: str) -> Dict[str, Any]:
    """
    Detects when an email or domain claims to represent a recognized organization
    (e.g., TCS, Infosys, Google) but operates from lookalikes or free webmail.
    """
    org_clean = claimed_organization.lower().strip()
    sender_clean = sender_domain_or_email.lower().strip()

    # Extract domain from email if email provided
    domain = sender_clean.split("@")[-1] if "@" in sender_clean else sender_clean
    extracted = tldextract.extract(domain)
    registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

    matched_brand = None
    for brand, legit_domains in GENUINE_BRAND_DOMAINS.items():
        if brand in org_clean:
            matched_brand = brand
            is_official = registered_domain in legit_domains
            is_free_webmail = registered_domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]

            return {
                "claimed_organization": claimed_organization,
                "matched_brand": brand,
                "sender_domain": registered_domain,
                "official_domains": legit_domains,
                "is_genuine_domain": is_official,
                "is_domain_mismatch": not is_official,
                "is_free_webmail": is_free_webmail,
                "alert": (
                    f"CRITICAL MISMATCH: Senders claiming to represent {brand.upper()} must use official domains ({', '.join(legit_domains)}). "
                    f"'{registered_domain}' is an unauthorized third-party or spoofed domain."
                    if not is_official else "Verified official domain."
                )
            }

    return {
        "claimed_organization": claimed_organization,
        "sender_domain": registered_domain,
        "is_domain_mismatch": False,
        "matched_brand": None
    }


# =====================================================================
# 2. Screenshot OCR & Vision Analyzer
# =====================================================================

def extract_text_from_screenshot(image_input: Any) -> Dict[str, Any]:
    """
    Extracts text and critical entity indicators from an offer letter, WhatsApp, or Telegram screenshot.
    Supports file path, raw bytes, PIL Image, or Base64 string.
    """
    extracted_text = ""
    ocr_engine = "none"
    error = None

    image_obj = None
    try:
        if isinstance(image_input, str):
            if image_input.startswith("data:image"):
                # Base64 data URI
                b64_data = image_input.split(",", 1)[-1]
                image_bytes = base64.b64decode(b64_data)
                image_obj = Image.open(io.BytesIO(image_bytes)) if Image else None
            elif Path(image_input).exists():
                image_obj = Image.open(image_input) if Image else None
            else:
                # Raw base64 string
                image_bytes = base64.b64decode(image_input)
                image_obj = Image.open(io.BytesIO(image_bytes)) if Image else None
        elif isinstance(image_input, bytes):
            image_obj = Image.open(io.BytesIO(image_input)) if Image else None
        elif hasattr(image_input, "convert"):
            image_obj = image_input
    except Exception as e:
        error = f"Image decode failed: {e}"

    # Tier 1: Local pytesseract if available and configured
    if image_obj and pytesseract:
        try:
            # Check standard Windows tesseract paths if default fails
            possible_tesseract_bins = [
                r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
                r"C:\Users\Mohammed safaf\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"
            ]
            for p in possible_tesseract_bins:
                if Path(p).exists():
                    pytesseract.pytesseract.tesseract_cmd = p
                    break

            extracted_text = pytesseract.image_to_string(image_obj)
            ocr_engine = "pytesseract"
        except Exception as e:
            error = f"pytesseract error: {e}"

    # Tier 2: Gemini Vision API Fallback if API key present in env
    if not extracted_text.strip() and image_obj and os.getenv("GEMINI_API_KEY"):
        try:
            import google.generativeai as genai
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            vision_model = genai.GenerativeModel("gemini-1.5-flash")
            response = vision_model.generate_content([
                "Extract all visible text from this offer letter or chat screenshot verbatim. Do not summarize.",
                image_obj
            ])
            if response and response.text:
                extracted_text = response.text
                ocr_engine = "gemini_vision"
        except Exception as e:
            error = f"Gemini vision error: {e}"

    # Extract forensic entities from extracted text
    text_clean = extracted_text or ""
    phones = re.findall(r"(?:\+91[\-\s]?)?[6789]\d{9}\b", text_clean)
    upis = re.findall(r"[\w\.\-]+@(okhdfcbank|oksbi|okaxis|ybl|paytm|upi|ibl|axl)", text_clean, re.IGNORECASE)
    # Get full UPI handles
    full_upis = re.findall(r"[\w\.\-]+@(?:okhdfcbank|oksbi|okaxis|ybl|paytm|upi|ibl|axl)", text_clean, re.IGNORECASE)
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text_clean)
    urls = re.findall(r"https?://[^\s<>\"']+", text_clean)
    amounts = re.findall(r"(?:₹|rs\.?|inr)\s*(\d+(?:,\d+)*(?:\.\d+)?)", text_clean, re.IGNORECASE)

    return {
        "extracted_text": extracted_text,
        "ocr_engine": ocr_engine,
        "char_count": len(extracted_text),
        "detected_entities": {
            "phones": list(set(phones)),
            "upi_handles": list(set(full_upis)),
            "emails": list(set(emails)),
            "urls": list(set(urls)),
            "monetary_amounts": list(set(amounts))
        },
        "error": error
    }


# =====================================================================
# 3. Indian Student Registry Verifier (UGC, AICTE, Scholarships)
# =====================================================================

def verify_indian_institution(text_or_name: str) -> Dict[str, Any]:
    """
    Cross-checks university or college names against the official University Grants Commission
    (UGC) Fake Universities Registry.
    """
    t_lower = text_or_name.lower()
    matches = []

    for entry in UGC_FAKE_UNIVERSITIES:
        # Check canonical name
        if entry["name"].lower() in t_lower:
            matches.append(entry)
            continue
        # Check aliases
        for alias in entry.get("aliases", []):
            if alias.lower() in t_lower:
                matches.append(entry)
                break

    if matches:
        first = matches[0]
        return {
            "is_fake_university": True,
            "severity": "CRITICAL",
            "matched_institution": first["name"],
            "state": first["state"],
            "ugc_status": first["ugc_status"],
            "warning": first["warning"],
            "official_citation": "UGC Public Notice on Fake Universities (ugc.gov.in)",
            "all_matches": matches
        }

    return {
        "is_fake_university": False,
        "severity": "CLEAR",
        "note": "No match found in UGC Fake Universities registry."
    }


def verify_aicte_legitimacy(claim_text: str) -> Dict[str, Any]:
    """
    Inspects texts claiming AICTE (All India Council for Technical Education) approval.
    Flags common unapproved commercial patterns and suspicious internship certificates.
    """
    t_lower = claim_text.lower()
    claims_aicte = "aicte" in t_lower
    unapproved_terms = ["autonomous certification", "no exam required", "guaranteed certificate without internship", "pay for aicte credits"]

    is_suspicious = claims_aicte and any(term in t_lower for term in unapproved_terms)

    return {
        "claims_aicte_approval": claims_aicte,
        "is_suspicious_claim": is_suspicious,
        "warning": (
            "WARNING: Entity falsely promises AICTE academic credits for paid certificates without legitimate institutional internship."
            if is_suspicious else None
        )
    }


def verify_government_scholarship_url(url: str) -> Dict[str, Any]:
    """
    Validates national/state government scholarship URLs.
    Official Indian scholarships operate strictly on '.gov.in' / 'scholarships.gov.in'.
    """
    parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    host = parsed.netloc.lower()

    claims_scholarship = any(w in (host + parsed.path.lower()) for w in ["scholarship", "nsp", "pragati", "saksham", "postmatric"])
    is_official_gov = host.endswith(".gov.in") or host.endswith(".nic.in")

    is_phishing = claims_scholarship and not is_official_gov

    return {
        "url": url,
        "claims_government_scholarship": claims_scholarship,
        "is_official_gov_domain": is_official_gov,
        "is_scholarship_phishing": is_phishing,
        "legitimate_portal": "https://scholarships.gov.in (National Scholarship Portal)",
        "warning": (
            f"CRITICAL FRAUD ALERT: Senders claiming to disburse Indian Government scholarships on non-governmental domain '{host}' are fraudulent phishing operations. All legitimate scholarships require filing via scholarships.gov.in."
            if is_phishing else None
        )
    }

