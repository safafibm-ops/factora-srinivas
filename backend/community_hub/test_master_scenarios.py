"""
End-to-End Test Suite for FACTORA — From Victim to Defender (Prompts 5–9 Master Verification).
Direct in-memory execution covering all 11 scenarios specified in Requirement 5.

Scenarios Tested:
1. User submits a new incident.
2. Incident saved successfully in database with unique incident ID.
3. Potential relationship with historical incidents is identified using DB records.
4. Potential threat alert is generated when sufficient evidence exists.
5. User searches for an existing domain, URL, repo, or indicator.
6. No matching incident found (empty state gracefully handled).
7. Duplicate incidents submitted and flagged by moderator.
8. Moderator reviews and updates an incident (with valid X-Moderator-Key).
9. Unauthorized user attempts moderation action (HTTP 401 rejected).
10. Sensitive information submitted as evidence (PII masked across public feeds).
11. Incomplete or invalid incident data submitted (HTTP 422 rejected).
"""

import sys
import unittest
from pathlib import Path
from fastapi import HTTPException

root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from shared.schemas import VictimReportSubmission
from backend.community_hub.storage import (
    init_db,
    add_victim_report,
    get_incident_by_ref,
    query_community_incident_feed,
    search_threat_indicators,
    mask_contact
)
from backend.community_hub.threat_alerts import (
    generate_dynamic_community_alerts,
    get_community_alert_by_id
)
from backend.community_hub.education import (
    get_all_education_topics,
    get_education_topic_by_id
)
from backend.community_hub.graph_engine import (
    build_community_threat_graph
)
from backend.community_hub.moderation import (
    get_moderation_queue,
    apply_moderator_action,
    get_incident_audit_trail,
    verify_moderator_access,
    MODERATOR_SECRET_KEY
)
from backend.community_hub.router import (
    submit_victim_report,
    search_threat_network,
    get_community_victim_feed,
    apply_moderation_review_endpoint,
    ModerationReviewPayload
)


class TestMasterCommunityScenarios(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.test_ref = None

    def test_scenario_01_and_02_submit_and_save_incident(self):
        """Scenarios 1 & 2: User submits a new incident, saved successfully with unique ID."""
        submission = VictimReportSubmission(
            incident_title="TCS Smart Hiring Security Deposit Telegram Trap",
            claimed_organization="Tata Consultancy Services",
            scam_type="recruitment_fraud",
            amount_demanded_or_lost_inr=3500.0,
            description="Student received offer letter claiming to be TCS Campus Hiring, demanding Rs. 3,500 laptop deposit via UPI.",
            scammer_contacts=["+919876543299", "tcscareers.security@oksbi"],
            scammer_links=["https://tcs-careers-portal.in/register", "tcs-careers-portal.in"],
            user_pseudonym="student-test-defender-01",
            financial_loss_occurred=True,
            suspicious_url_or_domain="tcs-careers-portal.in"
        )
        res = submit_victim_report(submission, x_user_pseudonym="student-test-defender-01")
        self.assertEqual(res.status, "success")
        self.assertTrue(res.incident_id.startswith("COMM-2026-"))
        self.assertEqual(res.verification_status, "SUBMITTED")
        TestMasterCommunityScenarios.test_ref = res.incident_id

        # Verify saved in SQLite DB
        db_record = get_incident_by_ref(res.incident_id)
        self.assertIsNotNone(db_record)
        self.assertEqual(db_record["incident_title"], "TCS Smart Hiring Security Deposit Telegram Trap")
        self.assertEqual(db_record["amount_demanded_or_lost_inr"], 3500.0)

    def test_scenario_03_identify_relationship_with_historical_incidents(self):
        """Scenario 3: Potential relationship with historical incidents identified using DB records."""
        # Query graph for the incident submitted in scenario 1
        graph_data = build_community_threat_graph(self.test_ref)
        self.assertEqual(graph_data["status"], "success")
        self.assertTrue(graph_data["has_relationships"])
        self.assertGreater(graph_data["summary"]["connected_incidents_count"], 0)
        
        # Verify edge relationships exist (e.g. shares_domain)
        relationships = [e["relationship"] for e in graph_data["edges"]]
        self.assertTrue("uses_domain" in relationships or "shares_domain" in relationships)

    def test_scenario_04_potential_threat_alert_generated(self):
        """Scenario 4: Potential threat alert generated when sufficient evidence exists."""
        alerts = generate_dynamic_community_alerts()
        self.assertGreater(len(alerts), 0)
        
        # Check alert contract fields
        first_alert = alerts[0]
        self.assertIn("alert_id", first_alert)
        self.assertIn("title", first_alert)
        self.assertIn("threat_category", first_alert)
        self.assertGreaterEqual(first_alert["number_of_related_incidents"], 2)
        self.assertIn("shared_indicators", first_alert)
        self.assertIn("relationship_confidence", first_alert)
        self.assertIn("date", first_alert)
        self.assertIn("status", first_alert)
        self.assertIn("cautious_disclaimer", first_alert)
        self.assertIn("Potentially Related Incidents", first_alert["cautious_disclaimer"])

    def test_scenario_05_search_existing_indicator(self):
        """Scenario 5: User searches for an existing domain, URL, or indicator."""
        search_res = search_threat_network(q="tcs-careers-portal.in")
        self.assertEqual(search_res["status"], "success")
        self.assertGreater(search_res["exact_matches_count"], 0)
        
        # Verify exact match explanation
        first_exact = [r for r in search_res["results"] if r["match_type"] == "exact"][0]
        self.assertEqual(first_exact["relationship_confidence"], 1.0)
        self.assertIn("Exact indicator match", first_exact["match_explanation"])

    def test_scenario_06_no_matching_incident_found_empty_state(self):
        """Scenario 6: No matching incident found (empty state gracefully handled)."""
        search_res = search_threat_network(q="completely-nonexistent-domain-xyz-2026.net")
        self.assertEqual(search_res["status"], "success")
        self.assertEqual(search_res["exact_matches_count"], 0)
        self.assertEqual(search_res["total_results"], 0)
        self.assertEqual(len(search_res["results"]), 0)

    def test_scenario_07_duplicate_incidents_submitted(self):
        """Scenario 7: Duplicate incident submitted, identified and linked."""
        dup_submission = VictimReportSubmission(
            incident_title="TCS Smart Hiring Security Deposit Telegram Trap (Duplicate Submission)",
            claimed_organization="Tata Consultancy Services",
            scam_type="recruitment_fraud",
            amount_demanded_or_lost_inr=3500.0,
            description="Duplicate report of identical TCS security deposit WhatsApp offer.",
            scammer_contacts=["+919876543299"],
            scammer_links=["https://tcs-careers-portal.in/register"],
            user_pseudonym="student-test-defender-02",
            suspicious_url_or_domain="tcs-careers-portal.in"
        )
        res_dup = submit_victim_report(dup_submission, x_user_pseudonym="student-test-defender-02")
        dup_ref = res_dup.incident_id

        # Moderator flags as duplicate of original test_ref
        ok, msg, data = apply_moderator_action(
            incident_ref=dup_ref,
            action="FLAG_DUPLICATE",
            moderator_id="mod-test-scenario",
            new_status="CLOSED",
            moderator_notes="Duplicate submission of earlier verified incident.",
            moderation_flag="duplicate",
            duplicate_of_ref=self.test_ref
        )
        self.assertTrue(ok)
        self.assertEqual(data["moderation_flag"], "duplicate")
        self.assertEqual(data["duplicate_of_ref"], self.test_ref)

    def test_scenario_08_moderator_reviews_and_updates_incident(self):
        """Scenario 8: Moderator reviews and updates incident with valid authorization."""
        payload = ModerationReviewPayload(
            new_status="CORROBORATED",
            moderator_id="mod-compliance-officer-07",
            moderator_notes="Corroborated: Suspect bank VPA confirmed linked to active cyber police bulletin.",
            is_public_approved=True
        )
        res = apply_moderation_review_endpoint(
            incident_ref=self.test_ref,
            payload=payload,
            x_moderator_key=MODERATOR_SECRET_KEY
        )
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["moderation_record"]["new_status"], "CORROBORATED")

        # Verify audit trail updated
        trail = get_incident_audit_trail(self.test_ref)
        self.assertGreater(len(trail), 0)
        self.assertEqual(trail[0]["moderator_id"], "mod-compliance-officer-07")

    def test_scenario_09_unauthorized_moderator_action_rejected(self):
        """Scenario 9: Unauthorized user attempts moderation action (HTTP 401 rejected)."""
        payload = ModerationReviewPayload(
            new_status="CLOSED",
            moderator_id="attacker-impersonator"
        )
        with self.assertRaises(HTTPException) as cm:
            apply_moderation_review_endpoint(
                incident_ref=self.test_ref,
                payload=payload,
                x_moderator_key="invalid-unauthorized-key"
            )
        self.assertEqual(cm.exception.status_code, 401)
        self.assertIn("Unauthorized", cm.exception.detail)

    def test_scenario_10_sensitive_information_submitted_pii_masked(self):
        """Scenario 10: Sensitive information submitted as evidence (PII masked in public feeds)."""
        phone = "+919876543299"
        masked = mask_contact(phone)
        self.assertNotIn("9876543299", masked)
        self.assertTrue(masked.startswith("+9198765"))
        self.assertTrue(masked.endswith("*****"))

        # Verify public feed masks all contact handles
        feed = get_community_victim_feed(page=1, page_size=5)
        for item in feed["feed"]:
            for c in item.get("scammer_contacts", []):
                self.assertNotIn("+919876543210", c)
                self.assertNotIn("+919876543299", c)

    def test_scenario_11_incomplete_or_invalid_incident_data_rejected(self):
        """Scenario 11: Incomplete or invalid incident data submitted (HTTP 422 rejected)."""
        invalid_short_title = VictimReportSubmission(
            incident_title="Scam",  # Less than 5 chars
            description="Detailed description of what happened to the student."
        )
        with self.assertRaises(HTTPException) as cm:
            submit_victim_report(invalid_short_title)
        self.assertEqual(cm.exception.status_code, 422)

        invalid_short_desc = VictimReportSubmission(
            incident_title="Legitimate Length Incident Title",
            description="Too short"  # Less than 10 chars
        )
        with self.assertRaises(HTTPException) as cm2:
            submit_victim_report(invalid_short_desc)
        self.assertEqual(cm2.exception.status_code, 422)

    def test_extra_cyber_awareness_and_education_centre(self):
        """Verify Education Centre module data and live database connection."""
        topics = get_all_education_topics()
        self.assertEqual(len(topics), 6)
        
        # Check topic 1
        t1 = topics[0]
        self.assertIn("title", t1)
        self.assertIn("common_warning_signs", t1)
        self.assertIn("sanitized_examples", t1)
        self.assertIn("potential_consequences", t1)
        self.assertIn("prevention_tips", t1)
        self.assertIn("recommended_actions", t1)
        self.assertIn("live_community_stats", t1)
        self.assertGreater(t1["live_community_stats"]["community_reports_count"], 0)


if __name__ == "__main__":
    unittest.main()
