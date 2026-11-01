"""Telegram webhook integration for text, image, and text-based PDF scans."""

import base64
import hmac
import logging
import os
import re
from collections import OrderedDict
from io import BytesIO
from typing import Any, Dict, Optional, Tuple

import httpx
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request
from pypdf import PdfReader
from starlette.concurrency import run_in_threadpool

from backend.agent1_analyzer.router import scorer as analyzer_scorer
from backend.agent2_correlator.router import get_engine as get_correlator_engine
from shared.schemas import IncidentAnalyzeRequest, ThreatIntelligenceRecord, ThreatRelationshipRecord


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/telegram", tags=["Telegram Safety Bot"])

TELEGRAM_API = "https://api.telegram.org"
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024
MAX_WEBHOOK_BODY_BYTES = 1024 * 1024
MAX_TEXT_CHARS = 12_000
MAX_PDF_PAGES = 12
MAX_PDF_TEXT_CHARS = 40_000
_seen_updates: "OrderedDict[int, None]" = OrderedDict()


def _bot_token() -> Optional[str]:
    return os.getenv("TELEGRAM_BOT_TOKEN")


def _webhook_secret() -> Optional[str]:
    return os.getenv("TELEGRAM_WEBHOOK_SECRET")


def _hello_text() -> str:
    return (
        "Hi, I’m Factora. Send a suspicious recruitment message, screenshot, or text-based PDF "
        "and I’ll check it for warning signs.\n\n"
        "Please avoid sharing passwords, OTPs, or unnecessary personal details. A low-risk result "
        "does not prove that a sender or offer is genuine. Use /help for supported files."
    )


async def _telegram_call(method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    token = _bot_token()
    if not token:
        raise RuntimeError("Telegram bot is not configured.")
    async with httpx.AsyncClient(timeout=25.0) as client:
        response = await client.post(f"{TELEGRAM_API}/bot{token}/{method}", json=payload)
    response.raise_for_status()
    result = response.json()
    if not result.get("ok"):
        raise RuntimeError(result.get("description", "Telegram API request failed."))
    return result.get("result", {})


async def _reply(chat_id: int, text: str, reply_to_message_id: Optional[int] = None) -> None:
    payload: Dict[str, Any] = {"chat_id": chat_id, "text": text[:3900]}
    if reply_to_message_id is not None:
        payload["reply_parameters"] = {"message_id": reply_to_message_id}
    await _telegram_call("sendMessage", payload)


async def _download_telegram_file(file_id: str) -> Tuple[bytes, str, str]:
    token = _bot_token()
    if not token:
        raise RuntimeError("Telegram bot is not configured.")
    file_info = await _telegram_call("getFile", {"file_id": file_id})
    if int(file_info.get("file_size") or 0) > MAX_DOWNLOAD_BYTES:
        raise ValueError("That file is too large. Please send a file smaller than 20 MB.")
    file_path = file_info.get("file_path")
    if not file_path or file_path.startswith("/") or ".." in file_path.split("/"):
        raise ValueError("Telegram returned an invalid file reference.")

    url = f"{TELEGRAM_API}/file/bot{token}/{file_path}"
    chunks = bytearray()
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        async with client.stream("GET", url) as response:
            response.raise_for_status()
            content_length = int(response.headers.get("content-length", "0") or 0)
            if content_length > MAX_DOWNLOAD_BYTES:
                raise ValueError("That file is too large. Please send a file smaller than 20 MB.")
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > MAX_DOWNLOAD_BYTES:
                    raise ValueError("That file is too large. Please send a file smaller than 20 MB.")
            content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
    return bytes(chunks), content_type, file_path.rsplit("/", 1)[-1]


def _pdf_to_text(data: bytes) -> str:
    if not data.startswith(b"%PDF-"):
        raise ValueError("The attachment does not appear to be a valid PDF.")
    try:
        reader = PdfReader(BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise ValueError("Password-protected PDFs are not supported. Please send an unlocked copy.")
        if len(reader.pages) > MAX_PDF_PAGES:
            raise ValueError(f"Please send a PDF with {MAX_PDF_PAGES} pages or fewer.")
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("I couldn’t read that PDF. Please send a clear screenshot or paste its text.") from exc
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        raise ValueError("This PDF has no selectable text. Please send screenshots of its pages or paste the message text.")
    return text[:MAX_PDF_TEXT_CHARS]


def _analyze(payload: IncidentAnalyzeRequest) -> Tuple[ThreatIntelligenceRecord, Optional[ThreatRelationshipRecord]]:
    record = analyzer_scorer.analyze_payload(payload)
    correlation: Optional[ThreatRelationshipRecord] = None
    try:
        engine = get_correlator_engine()
        correlation = engine.correlate(
            source_incident_id=record.incident_id,
            indicators=record.extracted_indicators,
        )
    except Exception:
        logger.exception("Telegram scan completed without historical correlation.")
    return record, correlation


def _format_result(record: ThreatIntelligenceRecord, correlation: Optional[ThreatRelationshipRecord]) -> str:
    score = float(record.fuzzy_risk_score)
    lines = [f"Factora result: {record.risk_tier} — {score:.0f}/100"]
    findings = record.why_it_is_risky_summary[:3]
    if findings:
        lines.extend(f"• {finding}" for finding in findings)
    else:
        lines.append("No specific warning signs were identified in the supplied content.")

    if correlation and correlation.related_incidents:
        match = correlation.related_incidents[0]
        lines.append(f"Historical indicator link ({match.relationship_confidence:.0%}): {match.connection_explanation}")

    checklist = record.verify_before_proceeding_checklist[:2]
    if checklist:
        lines.append("Before acting:")
        lines.extend(f"• {step.step_title}" for step in checklist)
    lines.append("A low score is not proof of authenticity. Verify the sender through the organization’s official site.")
    lines.append(f"Incident: {record.incident_id}")
    return "\n".join(lines)[:3900]


async def _process_update(update: Dict[str, Any]) -> None:
    message = update.get("message") or update.get("edited_message")
    if not message:
        return
    chat = message.get("chat") or {}
    if chat.get("type") != "private" or message.get("from", {}).get("is_bot"):
        return
    chat_id = chat.get("id")
    message_id = message.get("message_id")
    if not isinstance(chat_id, int):
        return

    text = (message.get("text") or "").strip()
    if text.startswith("/start") or text.startswith("/help"):
        await _reply(chat_id, _hello_text(), message_id)
        return

    caption = (message.get("caption") or "").strip()
    input_text = text or caption
    file_id = None
    file_kind = None
    file_name = ""
    if message.get("photo"):
        file_id = message["photo"][-1].get("file_id")
        file_kind = "image"
    elif message.get("document"):
        document = message["document"]
        file_id = document.get("file_id")
        file_name = (document.get("file_name") or "").lower()
        mime = (document.get("mime_type") or "").lower()
        if mime == "application/pdf" or file_name.endswith(".pdf"):
            file_kind = "pdf"
        elif mime.startswith("image/") or file_name.endswith((".png", ".jpg", ".jpeg", ".webp")):
            file_kind = "image"
        else:
            await _reply(chat_id, "I can scan text messages, images, and PDFs. Please send one of those formats.", message_id)
            return

    if not file_id and not input_text:
        await _reply(chat_id, "Send a message, screenshot, or text-based PDF to scan. Use /help for details.", message_id)
        return

    try:
        screenshot_base64 = None
        if file_id:
            data, content_type, _ = await _download_telegram_file(file_id)
            if file_kind == "pdf":
                input_text = "\n".join(part for part in (input_text, _pdf_to_text(data)) if part)
            else:
                if data.startswith(b"\x89PNG\r\n\x1a\n"):
                    content_type = "image/png"
                elif data.startswith(b"\xff\xd8\xff"):
                    content_type = "image/jpeg"
                elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
                    content_type = "image/webp"
                if content_type not in {"image/png", "image/jpeg", "image/webp"}:
                    raise ValueError("I can only scan PNG, JPEG, or WebP images. Please send a supported image.")
                screenshot_base64 = f"data:{content_type};base64,{base64.b64encode(data).decode('ascii')}"
                from backend.agent1_analyzer.osint_scanners import extract_text_from_screenshot
                ocr = await run_in_threadpool(extract_text_from_screenshot, screenshot_base64)
                extracted = (ocr or {}).get("extracted_text", "").strip()
                if not extracted:
                    await _reply(chat_id, "I couldn’t read text from that image, so I haven’t assigned a risk score. Send a clearer image or paste the message text.", message_id)
                    return
                input_text = "\n".join(part for part in (input_text, extracted) if part)

        if len(input_text) > MAX_TEXT_CHARS:
            input_text = input_text[:MAX_TEXT_CHARS]
        if not input_text.strip():
            await _reply(chat_id, "I couldn’t find readable text to scan. Please paste the message or send a clearer file.", message_id)
            return

        payload = IncidentAnalyzeRequest(input_text=input_text)
        record, correlation = await run_in_threadpool(_analyze, payload)
        await _reply(chat_id, _format_result(record, correlation), message_id)
    except ValueError as exc:
        await _reply(chat_id, str(exc), message_id)
    except Exception:
        logger.exception("Telegram scan failed for an update.")
        await _reply(chat_id, "I couldn’t complete that scan right now. Please try again or use the Factora website.", message_id)


def _remember_update(update_id: int) -> bool:
    if update_id in _seen_updates:
        return False
    _seen_updates[update_id] = None
    if len(_seen_updates) > 2048:
        _seen_updates.popitem(last=False)
    return True


@router.get("/info", summary="Public Telegram bot link")
async def telegram_info() -> Dict[str, Any]:
    username = (os.getenv("TELEGRAM_BOT_USERNAME") or "").strip().lstrip("@").strip()
    return {
        "configured": bool(username),
        "username": username or None,
        "chat_url": f"https://t.me/{username}" if username else None,
    }


@router.get("/health", summary="Telegram bot configuration status")
async def telegram_health() -> Dict[str, Any]:
    return {
        "configured": bool(_bot_token() and _webhook_secret() and os.getenv("TELEGRAM_WEBHOOK_URL")),
        "username_set": bool(os.getenv("TELEGRAM_BOT_USERNAME")),
    }


@router.post("/webhook", summary="Receive Telegram updates")
async def telegram_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    telegram_secret: Optional[str] = Header(default=None, alias="X-Telegram-Bot-Api-Secret-Token"),
) -> Dict[str, bool]:
    expected_secret = _webhook_secret()
    if not _bot_token() or not expected_secret:
        raise HTTPException(status_code=503, detail="Telegram bot is not configured.")
    if not telegram_secret or not hmac.compare_digest(telegram_secret, expected_secret):
        raise HTTPException(status_code=403, detail="Invalid Telegram webhook secret.")
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_WEBHOOK_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Telegram update is too large.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid content length.") from exc

    try:
        update = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid Telegram update.") from exc
    if not isinstance(update, dict):
        raise HTTPException(status_code=400, detail="Invalid Telegram update.")
    update_id = update.get("update_id")
    if not isinstance(update_id, int) or not _remember_update(update_id):
        return {"ok": True}
    background_tasks.add_task(_process_update, update)
    return {"ok": True}


async def register_webhook_if_configured() -> None:
    token = _bot_token()
    secret = _webhook_secret()
    webhook_url = (os.getenv("TELEGRAM_WEBHOOK_URL") or "").strip()
    if not token or not secret or not webhook_url:
        logger.info("Telegram bot webhook not registered; set its Render environment variables to enable it.")
        return
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", secret):
        logger.error("Telegram webhook secret must contain only letters, numbers, underscores, or hyphens.")
        return
    if not webhook_url.startswith("https://"):
        logger.error("Telegram webhook URL must use HTTPS.")
        return
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{TELEGRAM_API}/bot{token}/setWebhook",
                json={"url": webhook_url, "secret_token": secret, "allowed_updates": ["message"]},
            )
        response.raise_for_status()
        result = response.json()
        if not result.get("ok"):
            logger.error("Telegram rejected webhook registration: %s", result.get("description", "unknown error"))
            return
        logger.info("Telegram webhook registered.")
    except Exception:
        logger.exception("Could not register the Telegram webhook.")
