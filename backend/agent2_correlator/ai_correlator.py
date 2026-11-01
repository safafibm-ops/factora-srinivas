"""
Factora - Agent 2: AI Inference & Threat Correlation Engine
Problem 1: Safety Tech — FAKE OR REAL (Hackathon 2026)

Loads:
- Trained Random Forest Classifier & TF-IDF Vectorizer from models/correlator_rf_model.joblib
- Historical Threat Incidents Database from data/historical_incidents.json
- Community Hub victim intelligence from Member 3

Features:
1. Performs AI-driven pairwise similarity prediction against historical scam databases.
2. Uses NetworkX graph analytics to cluster incidents into syndicated campaigns.
3. Produces RelatedIncidentMatch, GraphNode, and GraphEdge structures adhering to shared/schemas.py.
"""

import json
import difflib
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Ensure repository root is on sys.path for robust cross-module imports
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import joblib
import numpy as np
import networkx as nx
from sklearn.metrics.pairwise import cosine_similarity

from shared.schemas import (
    ThreatIndicators,
    ThreatRelationshipRecord,
    RelatedIncidentMatch,
    GraphNode,
    GraphEdge,
    get_mock_data,
)


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "correlator_rf_model.joblib"
INCIDENTS_PATH = DATA_DIR / "historical_incidents.json"
if not INCIDENTS_PATH.exists():
    INCIDENTS_PATH = BASE_DIR / "historical_incidents.json"


class ThreatCorrelationEngine:
    """
    Production Machine Learning correlation engine that maps threat indicators
    to known syndicates, builds graph relationships, and predicts connection confidence.
    """

    def __init__(self, model_path: Path = MODEL_PATH, incidents_path: Path = INCIDENTS_PATH):
        self.model_path = model_path
        self.incidents_path = incidents_path
        self.bundle: Optional[Dict[str, Any]] = None
        self.model = None
        self.vectorizer = None
        self.feature_names = []
        self.historical_incidents: List[Dict[str, Any]] = []

        self._load_resources()

    def _load_resources(self):
        """Loads serialized model bundle and historical incident catalog."""
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Trained AI model not found at {self.model_path}. Run train_model.py first!"
            )
        
        self.bundle = joblib.load(self.model_path)
        self.model = self.bundle["model"]
        if hasattr(self.model, "n_jobs"):
            self.model.n_jobs = 1
        self.vectorizer = self.bundle["vectorizer"]
        self.feature_names = self.bundle["feature_names"]

        if self.incidents_path.exists():
            with open(self.incidents_path, "r", encoding="utf-8") as f:
                self.historical_incidents = json.load(f)
        else:
            print(f"[Warning] Historical database not found at {self.incidents_path}.")
            self.historical_incidents = []

    def _extract_pair_features(
        self,
        query_text: str,
        query_indicators: ThreatIndicators,
        hist_inc: Dict[str, Any]
    ) -> Tuple[np.ndarray, List[str], str]:
        """
        Calculates feature vector and human-readable explanation for a query vs historical incident.
        """
        # 1. Semantic Cosine Similarity
        hist_text = f"{hist_inc.get('incident_title', '')} {hist_inc.get('description', '')} {hist_inc.get('claimed_organization', '')}"
        vec_q = self.vectorizer.transform([query_text])
        vec_h = self.vectorizer.transform([hist_text])
        semantic_sim = float(cosine_similarity(vec_q, vec_h)[0][0])

        # 2. Fuzzy Domain Similarity
        hist_domains = hist_inc.get("domains", [])
        query_domains = query_indicators.domains
        domain_sim = 0.0
        for qd in query_domains:
            for hd in hist_domains:
                sim = difflib.SequenceMatcher(None, qd.lower(), hd.lower()).ratio()
                if sim > domain_sim:
                    domain_sim = sim

        # 3. Exact matching counts and shared labels
        shared_indicators = []
        shared_reasons = []

        # Domains
        common_domains = set(query_domains) & set(hist_domains)
        common_domains = {d for d in common_domains if d not in {"bit.ly", "t.me", "telegram.org"}}
        if common_domains:
            shared_indicators.extend([f"domain:{d}" for d in common_domains])
            shared_reasons.append(f"Matching domain(s): {', '.join(common_domains)}")

        # Contacts (emails + phone/upi)
        q_contacts = set(query_indicators.emails + query_indicators.phones_or_upi)
        h_contacts = set(hist_inc.get("emails", []) + hist_inc.get("phones_or_upi", []))
        common_contacts = q_contacts & h_contacts
        if common_contacts:
            shared_indicators.extend(list(common_contacts))
            shared_reasons.append(f"Shared contact/UPI ID(s): {', '.join(common_contacts)}")

        # GitHub Repos
        common_repos = set(query_indicators.github_repos) & set(hist_inc.get("github_repos", []))
        if common_repos:
            shared_indicators.extend([f"repo:{r}" for r in common_repos])
            shared_reasons.append(f"Identical GitHub repository: {', '.join(common_repos)}")

        # Suspicious Packages
        common_pkgs = set(query_indicators.suspicious_packages) & set(hist_inc.get("suspicious_packages", []))
        if common_pkgs:
            shared_indicators.extend([f"pkg:{p}" for p in common_pkgs])
            shared_reasons.append(f"Identical suspicious package(s): {', '.join(common_pkgs)}")

        # Scam flags overlap
        q_flags = query_indicators.student_scam_flags.model_dump()
        h_flags = hist_inc.get("student_scam_flags", {})
        shared_flags_count = sum(1 for k in q_flags if q_flags[k] and h_flags.get(k, False))
        if shared_flags_count >= 2:
            shared_reasons.append(f"Matched {shared_flags_count} student scam tactics (fees/zero-interview)")

        feature_vector = np.array([
            semantic_sim,
            float(domain_sim),
            float(len(common_domains)),
            float(len(common_contacts)),
            float(len(common_repos)),
            float(len(common_pkgs)),
            float(shared_flags_count)
        ], dtype=np.float32).reshape(1, -1)

        if not shared_reasons:
            if semantic_sim > 0.45 or domain_sim > 0.65:
                explanation = f"High behavioral/text similarity ({semantic_sim:.2f}) and domain resemblance ({domain_sim:.2f}) with {hist_inc['campaign_name']} pattern."
            else:
                explanation = "Correlated based on common threat vectors and targeting profile."
        else:
            explanation = "; ".join(shared_reasons) + f" (attributed to {hist_inc['campaign_name']})."

        return feature_vector, shared_indicators, explanation

    def correlate(
        self,
        source_incident_id: str,
        indicators: ThreatIndicators,
        query_text: Optional[str] = None,
        confidence_threshold: float = 0.45
    ) -> ThreatRelationshipRecord:
        """
        Executes AI correlation pipeline:
        1. Predicts connection probabilities across all historical incidents.
        2. Constructs NetworkX graph to detect syndicate clusters.
        3. Formulates graph nodes/edges and community alerts.
        """
        if query_text is None:
            # Build representative text from indicators
            query_text = " ".join([
                indicators.claimed_organization or "",
                *indicators.urls,
                *indicators.domains,
                *indicators.emails,
                *indicators.phones_or_upi,
                *indicators.github_repos,
                *indicators.suspicious_packages,
            ])

        matches: List[RelatedIncidentMatch] = []
        graph = nx.Graph()

        # Add central query incident node
        query_node_id = source_incident_id
        graph.add_node(
            query_node_id,
            label=f"Current Incident ({source_incident_id})",
            node_type="incident"
        )

        campaign_counter: Dict[str, float] = {}

        # 1. Run AI ML Pairwise Inference
        for hist in self.historical_incidents:
            feats, shared_indics, explanation = self._extract_pair_features(query_text, indicators, hist)
            
            # Predict correlation probability using trained Random Forest
            prob = float(self.model.predict_proba(feats)[0][1])

            # A model score based only on broad text resemblance is not enough
            # to say two incidents are connected. Require a concrete shared
            # contact, repository, package, or a strong model result.
            strong_exact_match = any(
                indicator.startswith(("repo:", "pkg:"))
                or ("@" in indicator)
                or indicator.startswith("+")
                for indicator in shared_indics
            )
            if strong_exact_match or (prob >= confidence_threshold and shared_indics):
                relationship_confidence = max(prob, 0.75) if strong_exact_match else prob
                match = RelatedIncidentMatch(
                    matched_incident_id=hist["incident_id"],
                    shared_indicators=shared_indics,
                    connection_explanation=explanation,
                    relationship_confidence=round(relationship_confidence, 3)
                )
                matches.append(match)

                # Weight campaigns by predicted confidence
                camp = hist.get("campaign_name", "Unknown Syndicate")
                if camp != "Isolated Incident":
                    campaign_counter[camp] = campaign_counter.get(camp, 0.0) + relationship_confidence

                # Graph node for matched past incident
                graph.add_node(
                    hist["incident_id"],
                    label=f"Past Incident: {hist.get('incident_title', hist['incident_id'])[:30]}",
                    node_type="incident"
                )
                graph.add_edge(
                    query_node_id,
                    hist["incident_id"],
                    relationship="correlated_with",
                    confidence=round(relationship_confidence, 3)
                )

        # Sort matches by relationship confidence descending
        matches.sort(key=lambda m: m.relationship_confidence, reverse=True)

        # 2. Determine Primary Campaign & Recurring Status
        detected_campaign = None
        is_recurring = False
        recurring_campaigns = {
            campaign: total for campaign, total in campaign_counter.items()
            if sum(1 for match in matches if any(
                incident.get("incident_id") == match.matched_incident_id
                and incident.get("campaign_name", "Isolated Incident") == campaign
                for incident in self.historical_incidents
            )) >= 2
        }
        if recurring_campaigns:
            detected_campaign = max(recurring_campaigns.items(), key=lambda x: x[1])[0]
            is_recurring = True
            
            # Add campaign cluster node
            camp_node_id = f"camp:{detected_campaign.replace(' ', '_')}"
            graph.add_node(camp_node_id, label=f"Syndicate: {detected_campaign}", node_type="campaign")
            graph.add_edge(query_node_id, camp_node_id, relationship="attributed_to", confidence=0.92)

        # 3. Add Indicator Nodes to Graph (Domains, UPI, GitHub Repos)
        for domain in indicators.domains:
            if domain not in {"bit.ly", "t.me"}:
                d_id = f"dom:{domain}"
                graph.add_node(d_id, label=domain, node_type="domain")
                graph.add_edge(query_node_id, d_id, relationship="uses_domain", confidence=1.0)

        for contact in indicators.phones_or_upi:
            c_id = f"upi:{contact}" if "@" in contact else f"phone:{contact}"
            graph.add_node(c_id, label=contact, node_type="phone_upi")
            graph.add_edge(query_node_id, c_id, relationship="demands_payment_to", confidence=1.0)

        for repo in indicators.github_repos:
            repo_name = repo.split("/")[-1] if "/" in repo else repo
            r_id = f"repo:{repo_name}"
            graph.add_node(r_id, label=f"GitHub: {repo_name}", node_type="github_repo")
            graph.add_edge(query_node_id, r_id, relationship="distributes_malware_via", confidence=0.95)

        # 4. Serialize NetworkX Graph into Pydantic GraphNode & GraphEdge Contracts
        graph_nodes: List[GraphNode] = []
        for n, attrs in graph.nodes(data=True):
            graph_nodes.append(GraphNode(
                id=n,
                label=attrs.get("label", n),
                node_type=attrs.get("node_type", "incident")
            ))

        graph_edges: List[GraphEdge] = []
        for u, v, attrs in graph.edges(data=True):
            graph_edges.append(GraphEdge(
                source=u,
                target=v,
                relationship=attrs.get("relationship", "connected_to"),
                confidence=attrs.get("confidence", 1.0)
            ))

        # 5. Formulate Recommended Community Warnings
        warnings = []
        if is_recurring and detected_campaign:
            warnings.append(
                f"[High Priority Alert] Incident is linked to active syndicated campaign '{detected_campaign}' with {len(matches)} historical matches."
            )
        if indicators.phones_or_upi:
            warnings.append(
                f"Flag receiver contacts {', '.join(indicators.phones_or_upi)} with campus placement cells and CyberCrime portal."
            )
        if indicators.github_repos or indicators.suspicious_packages:
            warnings.append(
                "Immediate developer warning: Avoid running 'npm install' or cloning associated repositories; inspect workspace trust settings."
            )
        if not warnings:
            warnings.append("No active syndicate cluster detected. Exercise standard zero-trust caution.")

        return ThreatRelationshipRecord(
            source_incident_id=source_incident_id,
            detected_campaign_name=detected_campaign,
            is_recurring_campaign=is_recurring,
            related_incidents=matches,
            graph_nodes=graph_nodes,
            graph_edges=graph_edges,
            recommended_community_warnings=warnings
        )


# Standalone verification runner
if __name__ == "__main__":
    print("=" * 60)
    print(" FACTORA AGENT 2: TESTING AI CORRELATION & CLUSTERING ENGINE")
    print("=" * 60)
    
    mock_data = get_mock_data()
    mock_indicators: ThreatIndicators = mock_data["indicators"]
    engine = ThreatCorrelationEngine()

    print(f"Loaded {len(engine.historical_incidents)} incidents into correlation engine.")
    print("\nRunning AI correlation against test incident 'INC-2026-TEST-001'...")
    
    result = engine.correlate(
        source_incident_id="INC-2026-TEST-001",
        indicators=mock_indicators,
        query_text="Tata Consultancy Services NextStep campus internship offer asking 3500 INR laptop bond"
    )

    print(f"\n[OK] Correlation Complete:")
    print(f"  * Detected Campaign:     {result.detected_campaign_name}")
    print(f"  * Is Recurring:          {result.is_recurring_campaign}")
    print(f"  * Matched Past Incidents: {len(result.related_incidents)}")
    print(f"  * Graph Entities:        {len(result.graph_nodes)} nodes, {len(result.graph_edges)} edges")

    print("\nTop Correlated Past Incidents:")
    for match in result.related_incidents[:3]:
        print(f"  • Matched: {match.matched_incident_id} (Confidence: {match.relationship_confidence * 100:.1f}%)")
        print(f"    Explanation: {match.connection_explanation}")

    print("\nRecommended Community Warnings:")
    for warn in result.recommended_community_warnings:
        print(f"  - {warn}")
