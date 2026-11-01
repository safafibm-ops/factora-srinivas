"""
Factora Member 3: Independent Agent Integration Client
Integrates with Agent 1 (Threat Analyzer) and Agent 2 (Correlator) through
configurable HTTP endpoints ONLY.

Strict Operating Rules:
1. Never starts or executes Agent 1 or Agent 2 processes.
2. If either agent is unreachable, returns explicit 'service-unavailable' or
   'pending-analysis' status.
3. NEVER generates fake AI analysis or fake threat correlation graphs.
"""

import os
import httpx
from typing import Dict, Any, Optional

# Configurable endpoints (via environment variables)
AGENT1_API_URL = os.getenv("AGENT1_API_URL", "http://localhost:8000/api/analyzer")
AGENT2_API_URL = os.getenv("AGENT2_API_URL", "http://localhost:8000/api/correlator")
AGENT_TIMEOUT_SECONDS = float(os.getenv("AGENT_TIMEOUT_SECONDS", "0.5"))


def get_agents_config() -> Dict[str, str]:
    """Returns current configured external endpoints for Agent 1 and Agent 2."""
    return {
        "agent1_analyzer_url": AGENT1_API_URL,
        "agent2_correlator_url": AGENT2_API_URL,
        "timeout_seconds": str(AGENT_TIMEOUT_SECONDS)
    }


def probe_agent1_status() -> Dict[str, Any]:
    """
    Probes Agent 1 health via HTTP.
    Returns status: 'online' or 'service-unavailable'.
    Does NOT start or launch Agent 1.
    """
    url = f"{AGENT1_API_URL.rstrip('/')}/health"
    try:
        with httpx.Client(timeout=AGENT_TIMEOUT_SECONDS) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                return {
                    "service": "Agent 1 (Cyber Threat Detection Agent)",
                    "configured_url": AGENT1_API_URL,
                    "status": "online",
                    "details": resp.json()
                }
            else:
                return {
                    "service": "Agent 1 (Cyber Threat Detection Agent)",
                    "configured_url": AGENT1_API_URL,
                    "status": "service-unavailable",
                    "analysis_status": "pending-analysis",
                    "message": f"Agent 1 returned unexpected status code: {resp.status_code}"
                }
    except Exception as e:
        return {
            "service": "Agent 1 (Cyber Threat Detection Agent)",
            "configured_url": AGENT1_API_URL,
            "status": "service-unavailable",
            "analysis_status": "pending-analysis",
            "message": "Agent 1 is offline or unreachable at configured endpoint."
        }


def probe_agent2_status() -> Dict[str, Any]:
    """
    Probes Agent 2 health via HTTP.
    Returns status: 'online' or 'service-unavailable'.
    Does NOT start or launch Agent 2.
    """
    url = f"{AGENT2_API_URL.rstrip('/')}/health"
    try:
        with httpx.Client(timeout=AGENT_TIMEOUT_SECONDS) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                return {
                    "service": "Agent 2 (Threat Intelligence Correlator)",
                    "configured_url": AGENT2_API_URL,
                    "status": "online",
                    "details": resp.json()
                }
            else:
                return {
                    "service": "Agent 2 (Threat Intelligence Correlator)",
                    "configured_url": AGENT2_API_URL,
                    "status": "service-unavailable",
                    "correlation_status": "pending-analysis",
                    "message": f"Agent 2 returned unexpected status code: {resp.status_code}"
                }
    except Exception as e:
        return {
            "service": "Agent 2 (Threat Intelligence Correlator)",
            "configured_url": AGENT2_API_URL,
            "status": "service-unavailable",
            "correlation_status": "pending-analysis",
            "message": "Agent 2 is offline or unreachable at configured endpoint."
        }


def request_agent1_analysis(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calls Agent 1's /analyze endpoint over HTTP if available.
    If Agent 1 is unreachable, returns an explicit 'pending-analysis' status.
    DOES NOT generate fake AI responses.
    """
    url = f"{AGENT1_API_URL.rstrip('/')}/analyze"
    try:
        with httpx.Client(timeout=AGENT_TIMEOUT_SECONDS) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                return {
                    "status": "success",
                    "analysis_status": "completed",
                    "data": resp.json()
                }
            else:
                return {
                    "status": "service-unavailable",
                    "analysis_status": "pending-analysis",
                    "error": f"Agent 1 error response: HTTP {resp.status_code}",
                    "data": None
                }
    except Exception:
        return {
            "status": "service-unavailable",
            "analysis_status": "pending-analysis",
            "error": "Agent 1 (Threat Detection Agent) is currently offline or unreachable at configured endpoint.",
            "data": None
        }


def request_agent2_correlation(incident_id: str, indicators: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Calls Agent 2's /correlate endpoint over HTTP if available.
    If Agent 2 is unreachable, returns an explicit 'pending-analysis' status.
    DOES NOT generate fake threat correlations or fake graph data.
    """
    url = f"{AGENT2_API_URL.rstrip('/')}/correlate"
    payload = {
        "incident_id": incident_id,
        "extracted_indicators": indicators
    }
    try:
        with httpx.Client(timeout=AGENT_TIMEOUT_SECONDS) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                return {
                    "status": "success",
                    "correlation_status": "completed",
                    "data": resp.json()
                }
            else:
                return {
                    "status": "service-unavailable",
                    "correlation_status": "pending-analysis",
                    "error": f"Agent 2 error response: HTTP {resp.status_code}",
                    "graph_nodes": [],
                    "graph_edges": []
                }
    except Exception:
        return {
            "status": "service-unavailable",
            "correlation_status": "pending-analysis",
            "error": "Agent 2 (Threat Correlation Agent) is currently offline or unreachable at configured endpoint.",
            "graph_nodes": [],
            "graph_edges": []
        }
