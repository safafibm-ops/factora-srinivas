"""
Factora Threat Relationship Graph Engine
Module: backend.community_hub.graph_engine
Constructs mathematically grounded entity relationship graphs from actual SQLite
community incident indicators and shared attributes.

Safety Guarantees:
1. Distinguishes direct exact indicator matches (confidence = 1.0) from syndicate campaign links (0.88)
   and weaker alleged impersonation similarities (0.70).
2. Never creates decorative or fictitious edges.
3. Does NOT treat a shared company name or keyword as proof of a common attacker.
4. Returns an explicit empty state with has_relationships = False when an incident has no corroborated links.
"""

from typing import List, Dict, Any, Optional, Set
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

from shared.schemas import GraphNode, GraphEdge, ThreatIndicators
from backend.community_hub.storage import (
    get_db_connection,
    extract_row_indicators,
    mask_contact,
    compute_incident_risk_level
)

def build_community_threat_graph(
    incident_ref: Optional[str] = None,
    max_nodes: int = 60
) -> Dict[str, Any]:
    """
    Constructs a node-link entity relationship graph from the community database.
    If `incident_ref` is provided, builds the targeted neighborhood graph for that incident.
    If `incident_ref` is None or 'all', builds the multi-incident correlation network.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # Target incident retrieval if specified
        target_incident = None
        if incident_ref and incident_ref.lower() != 'all':
            cursor.execute("SELECT * FROM victim_reports WHERE incident_ref = ?", (incident_ref.strip(),))
            target_incident = cursor.fetchone()
            if not target_incident:
                return {
                    "status": "not_found",
                    "incident_ref": incident_ref,
                    "has_relationships": False,
                    "nodes": [],
                    "edges": [],
                    "summary": {"total_nodes": 0, "total_edges": 0, "message": f"Incident '{incident_ref}' not found in database."}
                }

        # Fetch all public/corroborated records for correlation
        cursor.execute("SELECT * FROM victim_reports ORDER BY id DESC")
        all_rows = cursor.fetchall()

        # Build indicator -> list of incident_refs index
        indicator_to_incidents: Dict[str, Set[str]] = {}
        incident_indicators: Dict[str, Dict[str, List[str]]] = {}
        row_by_ref: Dict[str, sqlite3.Row] = {}

        for row in all_rows:
            ref = row["incident_ref"]
            row_by_ref[ref] = row
            inds = extract_row_indicators(row)
            incident_indicators[ref] = inds

            # Index atomic indicators
            for dom in inds.get("domains", []):
                key = f"dom:{dom.lower()}"
                indicator_to_incidents.setdefault(key, set()).add(ref)

            for phone_upi in inds.get("phones_or_upi", []):
                key = f"upi:{phone_upi.lower()}"
                indicator_to_incidents.setdefault(key, set()).add(ref)

            for repo in inds.get("github_repos", []):
                key = f"repo:{repo.lower()}"
                indicator_to_incidents.setdefault(key, set()).add(ref)

            for pkg in inds.get("suspicious_packages", []):
                key = f"pkg:{pkg.lower()}"
                indicator_to_incidents.setdefault(key, set()).add(ref)

            # Campaign correlation (if confirmed)
            camp = row["campaign_name"]
            if camp and camp != "Under Automated Correlation":
                key = f"camp:{camp}"
                indicator_to_incidents.setdefault(key, set()).add(ref)

        nodes_map: Dict[str, GraphNode] = {}
        edges_list: List[GraphEdge] = []
        edge_keys: Set[str] = set()

        def add_edge(src: str, tgt: str, rel: str, conf: float):
            pair_key = f"{src}->{tgt}:{rel}"
            if pair_key not in edge_keys:
                edge_keys.add(pair_key)
                edges_list.append(GraphEdge(source=src, target=tgt, relationship=rel, confidence=conf))

        if target_incident:
            # -------------------------------------------------------------
            # Target Neighborhood Subgraph
            # -------------------------------------------------------------
            t_ref = target_incident["incident_ref"]
            t_risk, t_color = compute_incident_risk_level(target_incident, 0)

            # Add target root incident node
            nodes_map[t_ref] = GraphNode(
                id=t_ref,
                label=f"{target_incident['incident_title'][:28]}... ({t_ref})",
                node_type="incident"
            )

            # Collect target's indicators
            t_inds = incident_indicators.get(t_ref, {})
            has_shared_connections = False

            # Add indicator nodes and check for shared cross-incident links
            for dom in t_inds.get("domains", []):
                dom_key = f"dom:{dom.lower()}"
                dom_label = dom
                nodes_map[dom_key] = GraphNode(id=dom_key, label=dom_label, node_type="domain")
                add_edge(t_ref, dom_key, "uses_domain", 1.0)

                # Find other incidents using this EXACT domain
                sharers = indicator_to_incidents.get(dom_key, set()) - {t_ref}
                if sharers:
                    has_shared_connections = True
                    for other_ref in list(sharers)[:5]:
                        other_row = row_by_ref.get(other_ref)
                        if other_row:
                            if other_ref not in nodes_map:
                                nodes_map[other_ref] = GraphNode(
                                    id=other_ref,
                                    label=f"{other_row['incident_title'][:24]}... ({other_ref})",
                                    node_type="incident"
                                )
                            add_edge(other_ref, dom_key, "shares_domain", 1.0)

            for upi_contact in t_inds.get("phones_or_upi", []):
                upi_key = f"upi:{upi_contact.lower()}"
                upi_label = mask_contact(upi_contact)
                nodes_map[upi_key] = GraphNode(id=upi_key, label=upi_label, node_type="phone_upi")
                add_edge(t_ref, upi_key, "demands_payment_to", 1.0)

                sharers = indicator_to_incidents.get(upi_key, set()) - {t_ref}
                if sharers:
                    has_shared_connections = True
                    for other_ref in list(sharers)[:5]:
                        other_row = row_by_ref.get(other_ref)
                        if other_row:
                            if other_ref not in nodes_map:
                                nodes_map[other_ref] = GraphNode(
                                    id=other_ref,
                                    label=f"{other_row['incident_title'][:24]}... ({other_ref})",
                                    node_type="incident"
                                )
                            add_edge(other_ref, upi_key, "shared_payout_receiver", 1.0)

            for repo in t_inds.get("github_repos", []):
                repo_name = repo.split("/")[-1] if "/" in repo else repo
                repo_key = f"repo:{repo.lower()}"
                nodes_map[repo_key] = GraphNode(id=repo_key, label=f"GitHub: {repo_name}", node_type="github_repo")
                add_edge(t_ref, repo_key, "distributes_repo", 1.0)

                sharers = indicator_to_incidents.get(repo_key, set()) - {t_ref}
                if sharers:
                    has_shared_connections = True
                    for other_ref in list(sharers)[:5]:
                        other_row = row_by_ref.get(other_ref)
                        if other_row:
                            if other_ref not in nodes_map:
                                nodes_map[other_ref] = GraphNode(
                                    id=other_ref,
                                    label=f"{other_row['incident_title'][:24]}... ({other_ref})",
                                    node_type="incident"
                                )
                            add_edge(other_ref, repo_key, "shares_malicious_repo", 1.0)

            # Campaign correlation
            t_camp = target_incident["campaign_name"]
            if t_camp and t_camp != "Under Automated Correlation":
                camp_key = f"camp:{t_camp}"
                nodes_map[camp_key] = GraphNode(id=camp_key, label=t_camp, node_type="campaign")
                add_edge(t_ref, camp_key, "attributed_to_campaign", 0.88)

                sharers = indicator_to_incidents.get(camp_key, set()) - {t_ref}
                if sharers:
                    has_shared_connections = True
                    for other_ref in list(sharers)[:5]:
                        other_row = row_by_ref.get(other_ref)
                        if other_row:
                            if other_ref not in nodes_map:
                                nodes_map[other_ref] = GraphNode(
                                    id=other_ref,
                                    label=f"{other_row['incident_title'][:24]}... ({other_ref})",
                                    node_type="incident"
                                )
                            add_edge(other_ref, camp_key, "attributed_to_campaign", 0.88)

            # Alleged company impersonation (Strict safety: confidence = 0.70, relationship = 'alleged_impersonation')
            claimed_org = target_incident["claimed_organization"]
            if claimed_org and claimed_org != "Unspecified Entity":
                org_key = f"org:{claimed_org.lower().replace(' ', '_')}"
                nodes_map[org_key] = GraphNode(id=org_key, label=f"Alleged Org: {claimed_org}", node_type="organization")
                add_edge(t_ref, org_key, "alleged_impersonation", 0.70)

            return {
                "status": "success",
                "inspected_ref": t_ref,
                "has_relationships": has_shared_connections,
                "nodes": [n.model_dump() for n in nodes_map.values()],
                "edges": [e.model_dump() for e in edges_list],
                "summary": {
                    "total_nodes": len(nodes_map),
                    "total_edges": len(edges_list),
                    "connected_incidents_count": len([n for n in nodes_map.values() if n.node_type == "incident"]) - 1,
                    "has_corroborated_syndicate": bool(t_camp and t_camp != "Under Automated Correlation"),
                    "cautionary_note": "Direct indicator edges (1.0) represent identical cryptographic artifacts or network indicators. Impersonation edges (0.70) reflect alleged target brands and do NOT represent legitimate organization compromise."
                }
            }

        else:
            # -------------------------------------------------------------
            # Global Multi-Incident Correlation Graph (Filtered to Connected Clusters)
            # -------------------------------------------------------------
            # Find indicators shared by >= 2 incidents
            shared_indicator_keys = {k: v for k, v in indicator_to_incidents.items() if len(v) >= 2}

            if not shared_indicator_keys:
                return {
                    "status": "success",
                    "inspected_ref": "all",
                    "has_relationships": False,
                    "nodes": [],
                    "edges": [],
                    "summary": {
                        "total_nodes": 0,
                        "total_edges": 0,
                        "message": "No corroborated multi-incident indicator links currently detected in the database. No synthetic connections generated."
                    }
                }

            # Build graph for shared clusters
            for ind_key, ref_set in shared_indicator_keys.items():
                if len(nodes_map) >= max_nodes:
                    break

                ind_type, ind_val = ind_key.split(":", 1)
                node_type = "domain" if ind_type == "dom" else ("phone_upi" if ind_type == "upi" else ("github_repo" if ind_type == "repo" else ("campaign" if ind_type == "camp" else "indicator")))
                label = mask_contact(ind_val) if ind_type == "upi" else ind_val

                if ind_key not in nodes_map:
                    nodes_map[ind_key] = GraphNode(id=ind_key, label=label, node_type=node_type)

                for r_ref in list(ref_set)[:6]:
                    r_row = row_by_ref.get(r_ref)
                    if r_row:
                        if r_ref not in nodes_map:
                            nodes_map[r_ref] = GraphNode(
                                id=r_ref,
                                label=f"{r_row['incident_title'][:24]}... ({r_ref})",
                                node_type="incident"
                            )
                        rel_name = "shares_domain" if ind_type == "dom" else ("shares_upi" if ind_type == "upi" else ("shares_repo" if ind_type == "repo" else "part_of_campaign"))
                        conf = 0.88 if ind_type == "camp" else 1.0
                        add_edge(r_ref, ind_key, rel_name, conf)

            return {
                "status": "success",
                "inspected_ref": "all",
                "has_relationships": len(edges_list) > 0,
                "nodes": [n.model_dump() for n in nodes_map.values()],
                "edges": [e.model_dump() for e in edges_list],
                "summary": {
                    "total_nodes": len(nodes_map),
                    "total_edges": len(edges_list),
                    "shared_indicators_count": len([n for n in nodes_map.values() if n.node_type != "incident"]),
                    "connected_incidents_count": len([n for n in nodes_map.values() if n.node_type == "incident"]),
                    "cautionary_note": "Relationships are strictly generated from corroborated shared indicators (100% confidence) and confirmed syndicates (88% confidence). Similar company names alone do NOT establish a threat connection."
                }
            }
    finally:
        conn.close()


def build_recent_model_correlation_graph(days: int = 30, max_nodes: int = 80) -> Dict[str, Any]:
    """Compare recent live community reports with Agent 2 and return explainable graph links."""
    from backend.agent2_correlator.router import get_engine
    from backend.community_hub.external_threat_feed import get_openphish_graph_data

    days = max(1, min(int(days), 30))
    max_nodes = max(5, min(int(max_nodes), 120))
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    report_limit = max(2, min(60, max_nodes // 2))
    conn = get_db_connection()
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM victim_reports WHERE data_source = 'community' AND reported_at >= ? ORDER BY reported_at DESC, id DESC LIMIT ?",
            (cutoff, report_limit + 1),
        ).fetchall()
    finally:
        conn.close()

    try:
        engine = get_engine()
        if engine.model is None:
            raise RuntimeError("Agent 2 correlation model is not loaded.")
    except Exception as exc:
        community_nodes = []
        community_details = {}
        for row in rows:
            ref = row["incident_ref"]
            amount = float(row["amount_demanded_or_lost_inr"] or 0)
            lost = bool(row["financial_loss_occurred"])
            community_nodes.append({"id": ref, "label": (row["incident_title"] or ref)[:48], "node_type": "incident"})
            community_details[ref] = {
                "entity_name": row["incident_title"] or ref,
                "details": f"Community-submitted report · {row['scam_type'] or 'Unspecified category'} · {row['reported_at'] or 'date unavailable'}" + (f" · reported loss ₹{amount:,.0f}" if lost else " · no financial loss reported"),
                "source_name": "Factora Community Reports",
                "source_url": f"/api/community/dashboard/incident/{ref}",
                "source_type": "community_report",
            }
        external = get_openphish_graph_data(max_nodes=max_nodes - len(community_nodes))
        return {
            "status": "degraded", "source": "community_reports_plus_openphish", "window_days": days,
            "generated_at": generated_at, "model": {"status": "unavailable", "name": "Agent 2 Correlator", "error": str(exc)},
            "nodes": community_nodes + external["nodes"], "edges": external["edges"], "correlations": [],
            "node_details": {**community_details, **external["node_details"]},
            "external_feed": external["feed"],
            "summary": {"reports_in_window": len(rows), "connected_pairs": 0, "shared_indicator_pairs": 0,
                        "similarity_candidates": 0, "external_feed_entries": external["feed"]["count"],
                        "message": "Agent 2 is unavailable, so no community relationships were inferred. OpenPhish feed entries are shown separately."},
        }

    truncated_reports = len(rows) > report_limit
    rows = rows[:report_limit]
    reports = []
    for row in rows:
        data = dict(row)
        indicators = extract_row_indicators(data)
        contact_indicators = sorted(set(indicators["emails"]) | set(indicators["phones"]) | set(indicators["upis"]))
        model_indicators = ThreatIndicators(
            urls=sorted(indicators["urls"]), domains=sorted(indicators["domains"]),
            emails=sorted(indicators["emails"]), phones_or_upi=contact_indicators,
            claimed_organization=data.get("claimed_organization"),
            github_repos=sorted(indicators["repos"]), suspicious_packages=sorted(indicators["packages"]),
        )
        query_text = " ".join((data.get("incident_title") or "", data.get("description") or "", data.get("claimed_organization") or "", data.get("scam_type") or ""))
        reports.append({"row": data, "indicators": indicators, "model_indicators": model_indicators, "query_text": query_text})

    nodes: Dict[str, Dict[str, str]] = {}
    edges: List[Dict[str, Any]] = []
    correlations: List[Dict[str, Any]] = []
    seen_edges: Set[str] = set()
    for report in reports:
        row = report["row"]
        incident_ref = row["incident_ref"]
        nodes[incident_ref] = {
            "id": incident_ref,
            "label": (row.get("incident_title") or incident_ref)[:48],
            "node_type": "incident",
        }

    node_details: Dict[str, Dict[str, Any]] = {}
    for report in reports:
        row = report["row"]
        ref = row["incident_ref"]
        amount = float(row.get("amount_demanded_or_lost_inr") or 0)
        lost = bool(row.get("financial_loss_occurred"))
        node_details[ref] = {
            "entity_name": row.get("incident_title") or ref,
            "details": f"Community-submitted report · {row.get('scam_type') or 'Unspecified category'} · {row.get('reported_at') or 'date unavailable'}" + (f" · reported loss ₹{amount:,.0f}" if lost else " · no financial loss reported"),
            "source_name": "Factora Community Reports",
            "source_url": f"/api/community/dashboard/incident/{ref}",
            "source_type": "community_report",
        }

    external = get_openphish_graph_data(max_nodes=max_nodes // 3)
    community_node_limit = max(0, max_nodes - len(external["nodes"]))

    generic_domains = {"bit.ly", "t.me", "telegram.org", "github.com", "forms.gle", "google.com"}
    for index, left in enumerate(reports):
        if len(nodes) >= community_node_limit:
            break
        for right in reports[index + 1:]:
            if len(nodes) >= community_node_limit or len(edges) >= 160:
                break
            a = left["row"]
            b = right["row"]
            try:
                features, _, _ = engine._extract_pair_features(left["query_text"], left["model_indicators"], {
                    "incident_id": b["incident_ref"], "incident_title": b.get("incident_title", ""),
                    "description": b.get("description", ""), "claimed_organization": b.get("claimed_organization", ""),
                    "domains": sorted(right["indicators"]["domains"]),
                    "emails": sorted(right["indicators"]["emails"]),
                    "phones_or_upi": sorted(set(right["indicators"]["phones"]) | set(right["indicators"]["upis"])),
                    "github_repos": sorted(right["indicators"]["repos"]),
                    "suspicious_packages": sorted(right["indicators"]["packages"]),
                    "student_scam_flags": {}, "campaign_name": b.get("campaign_name") or "Isolated Incident",
                })
                probability = float(engine.model.predict_proba(features)[0][1])
            except Exception:
                continue

            shared_domains = (left["indicators"]["domains"] & right["indicators"]["domains"]) - generic_domains
            shared_contacts = (left["indicators"]["emails"] | left["indicators"]["phones"] | left["indicators"]["upis"]) & (right["indicators"]["emails"] | right["indicators"]["phones"] | right["indicators"]["upis"])
            shared_repos = left["indicators"]["repos"] & right["indicators"]["repos"]
            shared_packages = left["indicators"]["packages"] & right["indicators"]["packages"]
            exact_values = sorted(shared_domains | shared_contacts | shared_repos | shared_packages)
            semantic_similarity = float(features[0][0])
            domain_similarity = float(features[0][1])

            if exact_values:
                match_type = "shared_indicator"
            elif probability >= 0.78 and (semantic_similarity >= 0.45 or domain_similarity >= 0.72):
                match_type = "model_similarity_candidate"
            else:
                continue

            masked_values = [mask_contact(value) if value in shared_contacts else value for value in exact_values]
            relationship_confidence = max(probability, 0.75) if match_type == "shared_indicator" else probability
            correlations.append({
                "source_incident_id": a["incident_ref"], "matched_incident_id": b["incident_ref"],
                "relationship_confidence": round(relationship_confidence, 3),
                "model_probability": round(probability, 3), "match_type": match_type,
                "shared_indicators": masked_values,
                "connection_explanation": (
                    "The reports contain the same indicator(s): " + ", ".join(masked_values)
                    if match_type == "shared_indicator" else
                    f"Agent 2 found behavioral similarity (text {semantic_similarity:.0%}; domain resemblance {domain_similarity:.0%}). Treat this as a review lead, not confirmation of the same attacker."
                ),
            })

            if match_type == "shared_indicator":
                for value in exact_values:
                    digest = hashlib.sha256(value.lower().encode("utf-8")).hexdigest()[:18]
                    entity_id = f"indicator:{digest}"
                    if entity_id not in nodes and len(nodes) < community_node_limit:
                        if value in shared_domains:
                            node_type = "domain"
                        elif value in shared_repos:
                            node_type = "github_repo"
                        else:
                            node_type = "phone_upi"
                        nodes[entity_id] = {"id": entity_id, "label": mask_contact(value) if value in shared_contacts else value, "node_type": node_type}
                        node_details[entity_id] = {
                            "entity_name": mask_contact(value) if value in shared_contacts else value,
                            "details": f"Exact indicator reported in multiple community incidents ({a['incident_ref']} and {b['incident_ref']}). A shared indicator is evidence to review; it does not by itself prove common ownership.",
                            "source_name": "Factora Community Reports",
                            "source_url": f"/api/community/dashboard/incident/{a['incident_ref']}",
                            "source_type": "community_report",
                        }
                    for incident in (a["incident_ref"], b["incident_ref"]):
                        key = f"{incident}:{entity_id}"
                        if entity_id in nodes and key not in seen_edges:
                            seen_edges.add(key)
                            edges.append({"source": incident, "target": entity_id, "relationship": "shares_indicator", "confidence": round(relationship_confidence, 3)})
            else:
                key = f"{a['incident_ref']}:{b['incident_ref']}"
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({"source": a["incident_ref"], "target": b["incident_ref"], "relationship": match_type, "confidence": round(relationship_confidence, 3)})

    # Connect only exact host matches. Similar or sibling domains are not joined.
    external_domain_ids = {node["label"].lower(): node["id"] for node in external["nodes"] if node["node_type"] == "external_phishing_domain"}
    for report in reports:
        ref = report["row"]["incident_ref"]
        for domain in report["indicators"]["domains"]:
            external_id = external_domain_ids.get(domain.lower().rstrip("."))
            if external_id:
                key = f"{ref}:{external_id}:exact_external_domain_match"
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append({"source": ref, "target": external_id, "relationship": "exact_external_domain_match", "confidence": 1.0})
                    node_details[ref]["details"] += " An exact reported domain also appears in the OpenPhish feed."
    nodes.update({node["id"]: node for node in external["nodes"]})
    node_details.update(external["node_details"])
    return {
        "status": "success", "source": "community_reports_plus_openphish", "window_days": days,
        "generated_at": generated_at,
        "model": {"status": "loaded", "name": "Agent 2 trained correlation model"},
        "nodes": list(nodes.values()), "edges": external["edges"] + edges, "correlations": correlations,
        "node_details": node_details, "external_feed": external["feed"],
        "summary": {
            "reports_in_window": len(reports), "connected_pairs": len(correlations),
            "shared_indicator_pairs": sum(1 for match in correlations if match["match_type"] == "shared_indicator"),
            "similarity_candidates": sum(1 for match in correlations if match["match_type"] == "model_similarity_candidate"),
            "external_feed_entries": external["feed"]["count"],
            "truncated": truncated_reports or len(nodes) >= max_nodes,
            "message": "Model similarity links are leads for review; they do not prove common ownership or fraud." if correlations else "No sufficiently strong links were found among live reports in this date window.",
        },
    }
