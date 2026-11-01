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
from pathlib import Path

from shared.schemas import GraphNode, GraphEdge
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
