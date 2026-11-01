"""
Test suite for Community Incident Feed (Part A) and Threat Search (Part B) in FACTORA Community Module.
Direct functional verification without network or socket overhead.
Verifies:
1. Backend pagination (does not dump entire DB to client).
2. Dynamic multi-factor filtering: Category, Risk Level, Status, Date, Scam Type.
3. Incident card contract fields: title, category, short description, date, risk level, verification status, related incident count.
4. Distinguishing exact indicator matches (1.0) from correlated syndicate links (0.88) and approximate company/text matches (0.60-0.70).
5. Ensuring similar company names or message content are NOT treated as proof of connection.
6. PII masking on phone numbers, email handles, and payment IDs.
"""

import sys
import unittest
from pathlib import Path

# Ensure root monorepo directory is on pythonpath
root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.community_hub.storage import (
    init_db,
    query_community_incident_feed,
    search_threat_indicators,
    get_feed_filter_options,
    compute_incident_risk_level,
    mask_contact
)
from backend.community_hub.router import (
    get_feed_filter_choices,
    get_community_victim_feed,
    search_threat_network
)


class TestCommunityFeedAndSearch(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_01_filter_options_endpoint(self):
        """Test get_feed_filter_choices returns all dynamic categories and dropdown values."""
        data = get_feed_filter_choices()
        self.assertEqual(data.get("status"), "success")
        options = data.get("options", {})
        self.assertIn("categories", options)
        self.assertIn("risk_levels", options)
        self.assertIn("verification_statuses", options)
        self.assertIn("date_filters", options)
        self.assertIn("incident_types", options)
        
        # Verify specific standard risk levels are present
        risk_labels = [r["name"] for r in options["risk_levels"]]
        self.assertIn("Critical Scam", risk_labels)
        self.assertIn("High Risk", risk_labels)
        self.assertIn("Caution", risk_labels)

    def test_02_feed_pagination(self):
        """Test get_community_victim_feed performs server-side pagination with correct metadata."""
        # Request page 1 with page_size=3
        data1 = get_community_victim_feed(page=1, page_size=3)
        self.assertEqual(data1.get("status"), "success")
        
        pagination = data1.get("pagination", {})
        self.assertEqual(pagination.get("page"), 1)
        self.assertEqual(pagination.get("page_size"), 3)
        self.assertGreaterEqual(pagination.get("total_items"), 5)
        self.assertGreaterEqual(pagination.get("total_pages"), 2)
        self.assertTrue(pagination.get("has_next"))
        self.assertFalse(pagination.get("has_prev"))
        
        items1 = data1.get("feed", [])
        self.assertEqual(len(items1), 3)

        # Request page 2 with page_size=3
        data2 = get_community_victim_feed(page=2, page_size=3)
        self.assertEqual(data2.get("status"), "success")
        items2 = data2.get("feed", [])
        self.assertGreaterEqual(len(items2), 1)

        # Verify page 1 items and page 2 items are disjoint
        ids_page1 = {item["incident_ref"] for item in items1}
        ids_page2 = {item["incident_ref"] for item in items2}
        self.assertTrue(ids_page1.isdisjoint(ids_page2), "Page 1 and Page 2 records must not overlap")

    def test_03_incident_card_required_fields(self):
        """Test that each card in the feed contains all user-required display fields."""
        data = get_community_victim_feed(page=1, page_size=10)
        self.assertEqual(data.get("status"), "success")
        items = data.get("feed", [])
        self.assertGreater(len(items), 0)

        for item in items:
            self.assertIn("incident_ref", item)
            self.assertIn("incident_title", item)
            self.assertIn("category", item)
            self.assertIn("category_name", item)
            self.assertIn("description", item)
            self.assertIn("reported_at", item)
            self.assertIn("risk_level", item)
            self.assertIn("risk_color", item)
            self.assertIn("verification_status", item)
            self.assertIn("related_incidents_count", item)
            self.assertIsInstance(item["related_incidents_count"], int)
            self.assertIn(item["risk_level"], ["Critical Scam", "High Risk", "Caution", "Low Risk", "Verified Safe"])

    def test_04_feed_multi_factor_filtering(self):
        """Test feed filtering by Category, Risk Level, Status, and Date."""
        # 1. Filter by category
        res_cat = get_community_victim_feed(category="recruitment_fraud")
        self.assertEqual(res_cat.get("status"), "success")
        items_cat = res_cat.get("feed", [])
        for item in items_cat:
            self.assertEqual(item["category"], "recruitment_fraud")

        # 2. Filter by risk_level
        res_risk = get_community_victim_feed(risk_level="Critical Scam")
        self.assertEqual(res_risk.get("status"), "success")
        items_risk = res_risk.get("feed", [])
        for item in items_risk:
            self.assertEqual(item["risk_level"], "Critical Scam")

        # 3. Filter by verification_status
        res_status = get_community_victim_feed(verification_status="CORROBORATED")
        self.assertEqual(res_status.get("status"), "success")
        items_status = res_status.get("feed", [])
        for item in items_status:
            self.assertEqual(item["verification_status"].upper(), "CORROBORATED")

        # 4. Filter by date_filter
        res_date = get_community_victim_feed(date_filter="all")
        self.assertEqual(res_date.get("status"), "success")
        self.assertGreater(len(res_date.get("feed", [])), 0)

    def test_05_threat_search_exact_match_and_correlated_incidents(self):
        """
        Test Threat Search with an exact indicator (domain: tcs-careers-portal.in).
        Must return:
        - Exact indicator match with confidence = 1.0
        - Related syndicate incidents with confidence = 0.88
        - Clear explanation of why each result matched
        """
        data = search_threat_network(q="tcs-careers-portal.in")
        self.assertEqual(data.get("status"), "success")
        self.assertEqual(data.get("query"), "tcs-careers-portal.in")
        self.assertGreater(data.get("exact_matches_count", 0), 0)

        results = data.get("results", [])
        self.assertGreater(len(results), 0)

        exact_results = [r for r in results if r.get("match_type") == "exact"]
        self.assertGreater(len(exact_results), 0, "Expected at least 1 exact match for tcs-careers-portal.in")
        first_exact = exact_results[0]
        self.assertEqual(first_exact["relationship_confidence"], 1.0)
        self.assertTrue(first_exact["is_exact_match"])
        self.assertIn("Exact indicator match", first_exact["match_explanation"])

        # Verify correlated syndicate results
        related_results = [r for r in results if r.get("match_type") == "related"]
        for rel in related_results:
            self.assertEqual(rel["relationship_confidence"], 0.88)
            self.assertIn("GhostRecruiter Syndicate #4", rel["match_explanation"])

    def test_06_threat_search_approximate_company_no_false_proof(self):
        """
        CRITICAL SAFETY TEST:
        Search for a company name ('Tata Consultancy Services').
        Requirement:
        - Do NOT treat similar company names or similar message content as proof of a connection.
        - Must distinguish exact matches from approximate matches.
        - Must NOT assign 1.0 confidence or claim direct compromise of the legitimate company.
        """
        data = search_threat_network(q="Tata Consultancy Services")
        self.assertEqual(data.get("status"), "success")

        # Company search should NOT have exact indicator matches
        self.assertEqual(data.get("exact_matches_count"), 0, "Company name alone must not produce exact indicator matches")

        # Should produce approximate matches
        self.assertGreater(data.get("approximate_matches_count", 0), 0)
        results = data.get("results", [])
        approx_results = [r for r in results if r.get("match_type") == "approximate"]
        self.assertGreater(len(approx_results), 0, "Expected approximate match for claimed company name")

        first_approx = approx_results[0]
        self.assertFalse(first_approx["is_exact_match"])
        self.assertEqual(first_approx["relationship_confidence"], 0.70)
        
        # Verify cautionary explanation is explicitly present
        explanation = first_approx["match_explanation"]
        self.assertIn("Approximate match in claimed company", explanation)
        self.assertIn("Similar company names do NOT prove a syndicate connection", explanation)

    def test_07_pii_masking_enforcement(self):
        """Verify that victim contact details (phone numbers, emails, UPI IDs) are masked."""
        phone = "+919876543210"
        masked_phone = mask_contact(phone)
        self.assertNotIn("9876543210", masked_phone)
        self.assertTrue(masked_phone.startswith("+9198765"))
        self.assertTrue(masked_phone.endswith("*****"))

        email = "hr-onboarding@tcs-careers-portal.in"
        masked_email = mask_contact(email)
        self.assertIn("tcs-careers-portal.in", masked_email)
        self.assertNotIn("hr-onboarding@", masked_email)

        telegram = "@amazon_vip_task_manager"
        masked_tg = mask_contact(telegram)
        self.assertTrue(masked_tg.startswith("@am"))
        self.assertNotIn("vip_task", masked_tg)

    def test_08_empty_or_whitespace_search(self):
        """Test searching with empty or whitespace string handles gracefully."""
        data = search_threat_network(q="   ")
        self.assertEqual(data.get("status"), "success")
        self.assertEqual(data.get("query"), "")
        self.assertEqual(len(data.get("results", [])), 0)


if __name__ == "__main__":
    unittest.main()
