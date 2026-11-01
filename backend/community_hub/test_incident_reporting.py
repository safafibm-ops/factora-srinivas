"""
Verification suite for the Report an Incident feature in Factora Community Module.
Tests validation, evidence upload, pseudonymous attribution, initial SUBMITTED status,
retrieval of user submissions, and PII masking.
"""

import sys
import io
from pathlib import Path
from fastapi import UploadFile, HTTPException

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from shared.schemas import VictimReportSubmission, IncidentSubmissionResponse
from backend.community_hub.storage import (
    init_db,
    add_victim_report,
    get_user_submitted_reports,
    get_incident_by_ref,
    get_recent_activity,
    mask_contact,
)
from backend.community_hub.evidence_storage import (
    sanitize_and_store_file,
    get_evidence_file_path,
)
from backend.community_hub.router import (
    submit_victim_report,
    get_my_submissions,
    upload_incident_evidence,
    get_evidence_file,
    serve_community_dashboard,
)


def run_tests():
    init_db()
    print("================================================================")
    print("STARTING TEST SUITE: REPORT AN INCIDENT FEATURE (MEMBER 3)")
    print("================================================================")

    # -------------------------------------------------------------
    # Test 1: Mandatory field validation
    # -------------------------------------------------------------
    print("\n[Test 1] Validating mandatory fields...")
    # Title too short
    try:
        submit_victim_report(VictimReportSubmission(
            incident_title="Hey",
            scam_type="recruitment_fraud",
            description="A detailed description of what happened in the scam incident."
        ))
        assert False, "Should have failed due to short title"
    except HTTPException as e:
        assert e.status_code == 422
        print(f" -> Short title correctly rejected with HTTP 422: {e.detail}")

    # Description too short
    try:
        submit_victim_report(VictimReportSubmission(
            incident_title="Legitimate length title here",
            scam_type="recruitment_fraud",
            description="Too short"
        ))
        assert False, "Should have failed due to short description"
    except HTTPException as e:
        assert e.status_code == 422
        print(f" -> Short description correctly rejected with HTTP 422: {e.detail}")

    # -------------------------------------------------------------
    # Test 2: Permitted Evidence File Uploads & Security
    # -------------------------------------------------------------
    print("\n[Test 2] Testing Permitted Evidence File Uploads...")
    valid_file = UploadFile(
        filename="offer_letter_fake.png",
        file=io.BytesIO(b"\x89PNG\r\n\x1a\nfake-png-bytes-here"),
        headers={"content-type": "image/png"}
    )
    meta = sanitize_and_store_file(valid_file)
    assert meta["stored_filename"].startswith("evid_")
    assert meta["stored_filename"].endswith(".png")
    assert meta["file_size_bytes"] > 0
    print(f" -> Valid PNG safely stored as: {meta['stored_filename']} ({meta['file_size_bytes']} bytes)")

    # Verify retrieval
    stored_path = get_evidence_file_path(meta["stored_filename"])
    assert stored_path is not None and stored_path.exists()
    print(f" -> File verified on disk at: {stored_path.name}")

    # Test path traversal prevention
    traversal_path = get_evidence_file_path("../../router.py")
    assert traversal_path is None
    print(" -> Directory traversal attack ('../../router.py') successfully blocked (returned None)")

    # Test disallowed executable upload
    bad_file = UploadFile(
        filename="malware.exe",
        file=io.BytesIO(b"MZ\x90\x00executable-bytes"),
        headers={"content-type": "application/x-dosexec"}
    )
    try:
        sanitize_and_store_file(bad_file)
        assert False, "Executable should have been rejected"
    except HTTPException as e:
        assert e.status_code == 400
        print(f" -> Executable (.exe) correctly rejected with HTTP 400: {e.detail}")

    # -------------------------------------------------------------
    # Test 3: Submitting an Incident with All 11 Fields
    # -------------------------------------------------------------
    print("\n[Test 3] Submitting Full Incident with 11 Fields...")
    test_pseudonym = "student-sentinel-test-889"
    submission_payload = VictimReportSubmission(
        incident_title="Accenture On-Campus Direct Joining Bond Trap",
        scam_type="recruitment_fraud",
        description="Received an unprompted WhatsApp offer letter alleging to be Accenture Campus Recruitment. Asked to transfer Rs. 4,500 security deposit for laptop dispatch.",
        claimed_organization="Accenture India (alleged impersonation)",
        suspicious_url_or_domain="accenture-careers-portal.site",
        github_repo_link="https://github.com/accenture-assessment/coding-task-2026",
        financial_loss_occurred=True,
        amount_demanded_or_lost_inr=4500.0,
        official_complaint_filed=True,
        complaint_ack_ref="2026/CYBER/994102",
        evidence_filenames=[meta["stored_filename"]],
        user_pseudonym=test_pseudonym,
        scammer_contacts=["+919876543299", "accenture.verify@oksbi"],
        scammer_links=["https://accenture-careers-portal.site"]
    )

    resp: IncidentSubmissionResponse = submit_victim_report(
        report=submission_payload,
        x_user_pseudonym=test_pseudonym
    )

    assert resp.status == "success"
    assert resp.incident_id.startswith("COMM-2026-")
    assert resp.verification_status == "SUBMITTED"
    assert resp.user_pseudonym == test_pseudonym
    assert resp.complaint_draft_fir is not None
    assert len(resp.emergency_freeze_checklist) > 0

    print(f" -> Incident successfully created!")
    print(f"    * Assigned Incident ID : {resp.incident_id}")
    print(f"    * Verification Status  : {resp.verification_status} (Expected: SUBMITTED)")
    print(f"    * Pseudonym Handle     : {resp.user_pseudonym}")
    print(f"    * Database Row ID      : {resp.database_id}")
    print(f"    * FIR Complaint Draft  : {len(resp.complaint_draft_fir)} chars generated")

    # -------------------------------------------------------------
    # Test 4: View User's Submitted Reports (My Reports)
    # -------------------------------------------------------------
    print("\n[Test 4] Retrieving User's Personal Submitted Reports...")
    my_reports_resp = get_my_submissions(pseudonym=test_pseudonym)
    assert my_reports_resp["status"] == "success"
    assert my_reports_resp["submissions_count"] >= 1
    user_incidents = my_reports_resp["submissions"]
    found = any(i["incident_ref"] == resp.incident_id for i in user_incidents)
    assert found, "Newly submitted incident should be present in user submissions"
    target_inc = next(i for i in user_incidents if i["incident_ref"] == resp.incident_id)
    assert target_inc["verification_status"] == "SUBMITTED"
    assert target_inc["financial_loss_occurred"] == 1
    assert target_inc["official_complaint_filed"] == 1
    assert target_inc["complaint_ack_ref"] == "2026/CYBER/994102"
    print(f" -> User submissions list verified: {len(user_incidents)} reports found for '{test_pseudonym}'")
    print(f"    * Incident Ref: {target_inc['incident_ref']} | Status: {target_inc['verification_status']} | Amount: Rs. {target_inc['amount_demanded_or_lost_inr']}")

    # -------------------------------------------------------------
    # Test 5: PII Masking & Privacy Safeguard
    # -------------------------------------------------------------
    print("\n[Test 5] Verifying PII Masking in Public Endpoints...")
    phone_masked = mask_contact("+919876543210")
    email_masked = mask_contact("hr-recruit@accenture.com")
    upi_masked = mask_contact("recruiter@oksbi")

    print(f" -> Phone masking : '+919876543210' -> '{phone_masked}'")
    print(f" -> Email masking : 'hr-recruit@accenture.com' -> '{email_masked}'")
    print(f" -> UPI masking   : 'recruiter@oksbi' -> '{upi_masked}'")

    assert "*****" in phone_masked
    assert "***" in email_masked
    assert "***" in upi_masked

    # Verify public activity feed returns masked contacts
    recent = get_recent_activity(limit=5)
    for r in recent:
        for c in r.get("scammer_contacts", []):
            digits = "".join(d for d in c if d.isdigit())
            if len(digits) >= 10:
                assert "*****" in c, f"Phone should be masked: {c}"
    print(" -> All public recent activity feed contacts verified as masked!")

    # -------------------------------------------------------------
    # Test 6: Dashboard HTML UI contains 11-field form & My Reports
    # -------------------------------------------------------------
    print("\n[Test 6] Verifying Dashboard UI Elements...")
    ui_resp = serve_community_dashboard()
    assert ui_resp.status_code == 200
    html_content = ui_resp.body.decode("utf-8")
    assert "formTitle" in html_content
    assert "formCategory" in html_content
    assert "formDescription" in html_content
    assert "formOrg" in html_content
    assert "formSuspiciousLink" in html_content
    assert "formGithubRepo" in html_content
    assert "lossOccurred" in html_content
    assert "formAmount" in html_content
    assert "complaintFiled" in html_content
    assert "formAckRef" in html_content
    assert "formEvidenceFiles" in html_content
    assert "successModal" in html_content
    assert "myReportsModal" in html_content
    print(" -> All 11 form fields, confirmation modal, and My Reports modal verified in UI HTML!")

    print("\n================================================================")
    print("ALL 6 REPORT AN INCIDENT FEATURE TESTS PASSED 100%!")
    print("================================================================")


if __name__ == "__main__":
    run_tests()
