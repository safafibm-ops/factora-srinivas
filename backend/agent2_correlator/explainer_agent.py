"""
Factora - Agent 2: LLM Threat Reasoning & Explainability Agent
Problem 1: Safety Tech — FAKE OR REAL (Hackathon 2026)

Responsibilities:
1. Explains in plain English WHY the ML model correlated threat incidents.
2. Integrates Member 3's Community Victim DB (reported victim count & total INR lost).
3. Synthesizes campus-wide early warnings and links to official reporting portals (CyberCrime.gov.in, CERT-In).
4. Dual-Mode Architecture:
   - Live LLM Reasoning (Google Gemini API / Groq API) when API key is provided.
   - Robust, high-fidelity offline heuristic reasoning engine fallback when offline or no key is set.
"""

import os
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import requests

from shared.schemas import (
    ThreatIndicators,
    ThreatRelationshipRecord,
    RelatedIncidentMatch,
    GraphNode,
    GraphEdge,
    CommunityThreatLookupResponse,
    get_mock_data,
)


class LLMExplainerAgent:
    """
    Cognitive explanation agent that translates machine learning correlation metrics
    into actionable threat intelligence narratives for students and placement coordinators.
    """

    def __init__(
        self,
        gemini_api_key: Optional[str] = None,
        groq_api_key: Optional[str] = None,
        model_name: str = "gemini-2.5-flash"
    ):
        self.gemini_api_key = gemini_api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.groq_api_key = groq_api_key or os.getenv("GROQ_API_KEY")
        self.model_name = model_name

    def explain_and_enrich(
        self,
        base_record: ThreatRelationshipRecord,
        indicators: ThreatIndicators,
        community_data: Optional[CommunityThreatLookupResponse] = None
    ) -> ThreatRelationshipRecord:
        """
        Takes raw ML correlation outputs, enriches match explanations,
        and generates student-first community warnings.
        """
        # 1. Attempt LLM Generation if API key is active
        if self.gemini_api_key:
            try:
                llm_result = self._call_gemini_api(base_record, indicators, community_data)
                if llm_result:
                    return llm_result
            except Exception as e:
                print(f"[LLM Agent] Gemini API call exception ({e}), engaging offline template fallback.")

        if self.groq_api_key:
            try:
                llm_result = self._call_groq_api(base_record, indicators, community_data)
                if llm_result:
                    return llm_result
            except Exception as e:
                print(f"[LLM Agent] Groq API call exception ({e}), engaging offline template fallback.")

        # 2. Seamless Offline Rule & Template Reasoning Engine Fallback
        return self._offline_template_reasoning(base_record, indicators, community_data)

    def _call_gemini_api(
        self,
        base_record: ThreatRelationshipRecord,
        indicators: ThreatIndicators,
        community_data: Optional[CommunityThreatLookupResponse]
    ) -> Optional[ThreatRelationshipRecord]:
        """Calls Google Gemini API via REST endpoint to synthesize threat narrative."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.gemini_api_key}"
        
        prompt = self._build_llm_prompt(base_record, indicators, community_data)
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
        }

        resp = requests.post(url, json=payload, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(raw_text)
            return self._apply_llm_updates(base_record, parsed)
        else:
            print(f"[LLM Agent] Gemini API returned status {resp.status_code}: {resp.text[:120]}")
            return None

    def _call_groq_api(
        self,
        base_record: ThreatRelationshipRecord,
        indicators: ThreatIndicators,
        community_data: Optional[CommunityThreatLookupResponse]
    ) -> Optional[ThreatRelationshipRecord]:
        """Calls Groq Cloud API via OpenAI-compatible endpoint."""
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type": "application/json"
        }
        prompt = self._build_llm_prompt(base_record, indicators, community_data)
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {"role": "system", "content": "You are a cyber threat intelligence analyst specialized in student recruitment fraud. Output JSON only."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            raw_text = data["choices"][0]["message"]["content"]
            parsed = json.loads(raw_text)
            return self._apply_llm_updates(base_record, parsed)
        return None

    def _build_llm_prompt(
        self,
        base_record: ThreatRelationshipRecord,
        indicators: ThreatIndicators,
        community_data: Optional[CommunityThreatLookupResponse]
    ) -> str:
        """Constructs an analytical prompt for the LLM."""
        return f"""
Analyze this cyber threat correlation and explain in simple, protective language why these incidents are linked:
- Source Incident: {base_record.source_incident_id}
- Detected Syndicate/Campaign: {base_record.detected_campaign_name}
- Recurring Threat?: {base_record.is_recurring_campaign}
- Indicators: Domains={indicators.domains}, UPI/Phones={indicators.phones_or_upi}, Repos={indicators.github_repos}, Packages={indicators.suspicious_packages}
- Matched Past Incidents: {json.dumps([m.model_dump() for m in base_record.related_incidents[:4]])}
- Member 3 Community DB Stats: {community_data.internal_victim_reports_count if community_data else 0} victims reported, Total INR Lost: Rs {community_data.total_reported_money_lost_inr if community_data else 0}

Output a strictly valid JSON object with:
{{
  "enriched_explanations": {{
     "<matched_incident_id>": "Plain-English 1-2 sentence explanation of the specific connection"
  }},
  "recommended_community_warnings": [
     "3-4 urgent, actionable warning bullet points for students, placement cells, and law enforcement"
  ]
}}
"""

    def _apply_llm_updates(
        self,
        base_record: ThreatRelationshipRecord,
        llm_json: Dict[str, Any]
    ) -> ThreatRelationshipRecord:
        """Merges LLM reasoning into the ThreatRelationshipRecord."""
        enriched_map = llm_json.get("enriched_explanations", {})
        warnings = llm_json.get("recommended_community_warnings", base_record.recommended_community_warnings)

        updated_matches = []
        for match in base_record.related_incidents:
            if match.matched_incident_id in enriched_map:
                match_dict = match.model_dump()
                match_dict["connection_explanation"] = enriched_map[match.matched_incident_id]
                updated_matches.append(RelatedIncidentMatch(**match_dict))
            else:
                updated_matches.append(match)

        return ThreatRelationshipRecord(
            source_incident_id=base_record.source_incident_id,
            detected_campaign_name=base_record.detected_campaign_name,
            is_recurring_campaign=base_record.is_recurring_campaign,
            related_incidents=updated_matches,
            graph_nodes=base_record.graph_nodes,
            graph_edges=base_record.graph_edges,
            recommended_community_warnings=warnings
        )

    def _offline_template_reasoning(
        self,
        base_record: ThreatRelationshipRecord,
        indicators: ThreatIndicators,
        community_data: Optional[CommunityThreatLookupResponse]
    ) -> ThreatRelationshipRecord:
        """
        High-fidelity heuristic reasoning engine that delivers crisp, human-readable explanations
        even when running 100% offline without API keys or internet access.
        """
        syndicate = base_record.detected_campaign_name or "Unknown Syndicate"
        updated_matches = []

        for match in base_record.related_incidents:
            explanation = match.connection_explanation
            shared = match.shared_indicators

            # Synthesize clean narrative based on shared indicator types
            reasons = []
            matching_upis = [s for s in shared if "@" in s or s.startswith("+91")]
            matching_repos = [s for s in shared if s.startswith("repo:")]
            matching_pkgs = [s for s in shared if s.startswith("pkg:")]
            matching_doms = [s for s in shared if s.startswith("domain:")]

            if matching_upis:
                clean_upi = matching_upis[0].replace("upi:", "").replace("phone:", "")
                reasons.append(f"The exact contact or payment handle '{clean_upi}' also appears in a historical report")
            if matching_repos:
                repo = matching_repos[0].replace("repo:", "")
                reasons.append(f"The exact repository '{repo}' also appears in a historical report; this match does not establish that its contents are malicious")
            if matching_pkgs:
                pkgs_str = ", ".join(p.replace("pkg:", "") for p in matching_pkgs)
                reasons.append(f"The package name(s) {pkgs_str} also appear in a historical report; inspect package contents before drawing a malware conclusion")
            if matching_doms:
                dom_str = matching_doms[0].replace("domain:", "")
                reasons.append(f"The domain '{dom_str}' also appears in a historical report")

            if reasons:
                explanation = f"{'; '.join(reasons)}. This overlap is a lead to verify; it does not by itself prove the same operator or campaign."
            else:
                # A match should always carry a concrete shared indicator. If a
                # future caller violates that invariant, avoid inventing one.
                explanation = "The correlation model found a candidate link, but no exact shared indicator is available to explain it. Treat this as unconfirmed."

            match_dict = match.model_dump()
            match_dict["connection_explanation"] = explanation
            updated_matches.append(RelatedIncidentMatch(**match_dict))

        # Build synthesized community warnings
        warnings = []
        if base_record.is_recurring_campaign:
            warnings.append(
                f"[Potential association] Multiple records share indicators associated with '{syndicate}'. Review each shared indicator before treating them as the same campaign."
            )

        if community_data and community_data.internal_victim_reports_count > 0:
            warnings.append(
                f"[Community context] The community database contains {community_data.internal_victim_reports_count} reports and Rs {community_data.total_reported_money_lost_inr:,.0f} in reported losses overall; these totals do not establish a link to this incident."
            )

        if indicators.phones_or_upi:
            upis = ", ".join(indicators.phones_or_upi)
            warnings.append(
                f"[Shared contact indicator] This incident includes {upis}. Verify the contact with official sources; its presence alone does not confirm who controls it."
            )

        if indicators.github_repos or indicators.suspicious_packages:
            warnings.append(
                "[Code security advisory] A GitHub repository or package was referenced. Review its source and build hooks before opening it or running npm/pip install; this correlation result does not confirm malware."
            )

        # External portal escalation links
        warnings.append(
            "[Official Law Enforcement Route] Report this incident to National Cyber Crime Reporting Portal at https://cybercrime.gov.in (Helpline: 1930)."
        )

        return ThreatRelationshipRecord(
            source_incident_id=base_record.source_incident_id,
            detected_campaign_name=base_record.detected_campaign_name,
            is_recurring_campaign=base_record.is_recurring_campaign,
            related_incidents=updated_matches,
            graph_nodes=base_record.graph_nodes,
            graph_edges=base_record.graph_edges,
            recommended_community_warnings=warnings
        )


# Standalone runner for testing the LLM Explainer Agent
if __name__ == "__main__":
    from backend.agent2_correlator.ai_correlator import ThreatCorrelationEngine

    print("=" * 60)
    print(" FACTORA AGENT 2: TESTING LLM EXPLAINER AGENT")
    print("=" * 60)

    mock = get_mock_data()
    engine = ThreatCorrelationEngine()
    explainer = LLMExplainerAgent()

    print("1. Running AI Correlation Engine...")
    base_record = engine.correlate(
        source_incident_id="INC-2026-TCS-9021",
        indicators=mock["indicators"],
        query_text="Fake TCS campus recruitment email demanding Rs 3500 laptop deposit via UPI"
    )

    print("2. Passing ML findings through LLM Reasoning Agent...")
    enriched_record = explainer.explain_and_enrich(
        base_record=base_record,
        indicators=mock["indicators"],
        community_data=mock["community_hub"]
    )

    print("\n[OK] LLM Enriched Incident Explanations:")
    for match in enriched_record.related_incidents[:3]:
        print(f"  • {match.matched_incident_id} [{match.relationship_confidence * 100:.1f}% Confidence]:")
        print(f"    {match.connection_explanation}")

    print("\n[OK] Synthesized Community & External Portal Warnings:")
    for w in enriched_record.recommended_community_warnings:
        print(f"  {w}")
