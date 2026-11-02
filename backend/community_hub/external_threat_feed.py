"""Small, cached adapter for the OpenPhish community URL feed.

Feed entries remain external intelligence. They are never written to the victim
database and never contribute to community loss/report/campaign totals.
"""

from __future__ import annotations

import threading
import time
import hashlib
from typing import Any, Dict, List, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

FEED_URL = "https://openphish.com/feed.txt"
SOURCE_NAME = "OpenPhish Community Feed"
REFRESH_SECONDS = 12 * 60 * 60
MAX_FEED_URLS = 250
_lock = threading.Lock()
_cached_at = 0.0
_last_attempt_at = 0.0
_cached_urls: List[str] = []
_last_error: str | None = None


def _valid_feed_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname) and not parsed.username and not parsed.password
    except ValueError:
        return False


def _read_feed() -> Tuple[List[str], str | None]:
    request = Request(FEED_URL, headers={"User-Agent": "Factora-Threat-Intel/1.0"})
    with urlopen(request, timeout=8) as response:
        if response.status != 200:
            raise URLError(f"OpenPhish returned HTTP {response.status}")
        body = response.read(2_000_000).decode("utf-8", errors="replace")
    urls: List[str] = []
    seen = set()
    for line in body.splitlines():
        url = line.strip()
        if not url or url.startswith("#") or not _valid_feed_url(url):
            continue
        key = url.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        urls.append(url)
        if len(urls) >= MAX_FEED_URLS:
            break
    return urls, None


def get_openphish_graph_data(max_nodes: int = 60) -> Dict[str, Any]:
    """Return actual feed-backed graph nodes/edges with a stale-cache fallback."""
    global _cached_at, _last_attempt_at, _cached_urls, _last_error
    with _lock:
        refreshed = False
        now = time.time()
        retry_after = REFRESH_SECONDS if _cached_at else 5 * 60
        if not _last_attempt_at or now - _last_attempt_at >= retry_after:
            _last_attempt_at = now
            try:
                _cached_urls, _last_error = _read_feed()
                _cached_at = time.time()
                refreshed = True
            except Exception as exc:  # Network/feed errors should not break community graph.
                _last_error = str(exc)[:240]

        urls = list(_cached_urls)
        cached_at = _cached_at
        error = _last_error

    nodes: List[Dict[str, str]] = []
    edges: List[Dict[str, Any]] = []
    details: Dict[str, Dict[str, Any]] = {}
    domain_ids: Dict[str, str] = {}
    domain_counts: Dict[str, int] = {}
    url_records: List[Tuple[str, str]] = []
    seen_urls = set()
    max_nodes = max(0, min(int(max_nodes), 120))
    for url in urls:
        normalized_url = url.rstrip("/").lower()
        if normalized_url in seen_urls:
            continue
        seen_urls.add(normalized_url)
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        if not host:
            continue
        domain_id = "openphish:domain:" + host
        url_id = "openphish:url:" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
        if len(url_records) + len(domain_ids) + (0 if domain_id in domain_ids else 1) + 1 > max_nodes:
            continue
        domain_counts[host] = domain_counts.get(host, 0) + 1
        url_records.append((url_id, url))
        domain_ids.setdefault(host, domain_id)

    for host, node_id in domain_ids.items():
        nodes.append({"id": node_id, "label": host, "node_type": "external_phishing_domain"})
        details[node_id] = {
            "entity_name": host,
            "details": f"Host of {domain_counts[host]} URL(s) listed in the OpenPhish phishing feed. This is external threat-feed data, not a Factora community report.",
            "source_name": SOURCE_NAME,
            "source_url": FEED_URL,
            "source_type": "external_threat_feed",
        }

    for url_id, url in url_records:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        domain_id = domain_ids[host]
        nodes.append({"id": url_id, "label": url[:64], "node_type": "external_phishing_url"})
        edges.append({"source": url_id, "target": domain_id, "relationship": "hosted_on", "confidence": 1.0})
        details[url_id] = {
            "entity_name": url,
            "details": "This exact URL appears in the OpenPhish community phishing feed. The feed identifies phishing URLs; it does not establish student losses or a connection to any Factora report.",
            "source_name": SOURCE_NAME,
            "source_url": FEED_URL,
            "source_type": "external_threat_feed",
        }

    return {
        "nodes": nodes,
        "edges": edges,
        "node_details": details,
        "feed": {
            "name": SOURCE_NAME,
            "source_url": FEED_URL,
            "license_url": "https://openphish.com/terms.html",
            "count": len(url_records),
            "available_count": len(urls),
            "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(cached_at)) if cached_at else None,
            "refreshed": refreshed,
            "stale": bool(error and urls),
            "error": error,
        },
    }
