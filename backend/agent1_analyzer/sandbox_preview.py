"""Remote, disposable-browser screenshots for suspicious links.

Target pages are rendered by a remote Browserless browser, never in the user's
browser or Factora's backend. The app only receives a bounded PNG screenshot.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict
from urllib.parse import urlsplit

import requests

MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024
PREVIEW_TIMEOUT_SECONDS = 35
RATE_LIMIT_COUNT = 3
RATE_LIMIT_WINDOW_SECONDS = 300
_rate_lock = threading.Lock()
_requests_by_client: Dict[str, Deque[float]] = defaultdict(deque)


class PreviewError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def validate_public_web_url(value: str) -> str:
    """Accept only ordinary public HTTP(S) URLs; refuse local/private targets."""
    if not value or len(value) > 2048:
        raise PreviewError("The link is empty or too long.")
    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise PreviewError("Only complete http:// or https:// links can be previewed.")
        if parsed.username or parsed.password:
            raise PreviewError("Links containing embedded usernames or passwords cannot be previewed.")
        host = parsed.hostname.rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal")):
            raise PreviewError("Local or internal network addresses cannot be previewed.")
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                raise PreviewError("Private or reserved network addresses cannot be previewed.")
        except ValueError:
            if not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host or ".." in host:
                raise PreviewError("That host name is not a valid public domain.")
        return value.strip()
    except ValueError as exc:
        if isinstance(exc, PreviewError):
            raise
        raise PreviewError("That link could not be parsed.") from exc


def enforce_rate_limit(client_key: str) -> None:
    now = time.monotonic()
    with _rate_lock:
        hits = _requests_by_client[client_key]
        while hits and now - hits[0] > RATE_LIMIT_WINDOW_SECONDS:
            hits.popleft()
        if len(hits) >= RATE_LIMIT_COUNT:
            raise PreviewError("Preview limit reached. Wait a few minutes before trying again.", 429)
        hits.append(now)


def capture_isolated_preview(url: str) -> dict:
    """Ask Browserless to render the URL remotely and return a small PNG."""
    token = os.getenv("BROWSERLESS_TOKEN", "").strip()
    if not token:
        raise PreviewError("Isolated preview is not configured yet. Add BROWSERLESS_TOKEN to the server environment.", 503)

    endpoint = os.getenv("BROWSERLESS_SCREENSHOT_ENDPOINT", "https://production-sfo.browserless.io/screenshot").strip()
    if not endpoint.startswith("https://"):
        raise PreviewError("The isolated browser service endpoint must use HTTPS.", 503)

    try:
        response = requests.post(
            endpoint,
            params={"token": token},
            json={
                "url": url,
                "bestAttempt": True,
                "gotoOptions": {"waitUntil": "domcontentloaded", "timeout": 20000},
                "options": {"type": "png", "fullPage": False},
            },
            headers={"Cache-Control": "no-cache"},
            timeout=(5, PREVIEW_TIMEOUT_SECONDS),
            stream=True,
        )
    except requests.RequestException as exc:
        raise PreviewError(f"The remote isolated browser could not be reached: {str(exc)[:180]}", 502) from exc

    with response:
        if not response.ok:
            raise PreviewError(f"The remote isolated browser returned HTTP {response.status_code}.", 502)
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
        if content_type != "image/png":
            raise PreviewError("The isolated browser did not return a PNG screenshot.", 502)
        length = response.headers.get("Content-Length")
        try:
            if length and int(length) > MAX_SCREENSHOT_BYTES:
                raise PreviewError("The preview image exceeded the size limit.", 502)
        except ValueError as exc:
            raise PreviewError("The remote browser returned an invalid image size.", 502) from exc
        chunks = []
        size = 0
        for chunk in response.iter_content(64 * 1024):
            if not chunk:
                continue
            size += len(chunk)
            if size > MAX_SCREENSHOT_BYTES:
                raise PreviewError("The preview image exceeded the size limit.", 502)
            chunks.append(chunk)
        image = b"".join(chunks)
        if not image.startswith(b"\x89PNG\r\n\x1a\n"):
            raise PreviewError("The isolated browser returned an invalid image.", 502)

        return {
            "status": "captured",
            "requested_url": url,
            "final_url": response.headers.get("X-Response-URL") or url,
            "page_status": response.headers.get("X-Response-Code"),
            "image_data_url": "data:image/png;base64," + base64.b64encode(image).decode("ascii"),
            "isolation": "remote_disposable_browser",
            "notice": "This is a visual preview from a remote disposable browser. The page may still be deceptive; the screenshot does not certify the site as safe.",
        }
