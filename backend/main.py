"""
Factora Main Backend Application
Problem 1: Safety Tech — FAKE OR REAL
Wires Agent 1 (Analyzer), Agent 2 (Correlator), and Member 3 (Community Hub).
"""

import sys
import json
import re
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit
from zipfile import ZIP_DEFLATED, ZipFile

# Ensure root monorepo directory is on pythonpath for seamless imports
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from backend.agent1_analyzer.router import router as analyzer_router, scorer as analyzer_scorer
from backend.agent2_correlator.router import router as correlator_router, get_engine as get_correlator_engine
from backend.community_hub.router import router as community_router
from backend.telegram_bot.router import router as telegram_router, register_webhook_if_configured

app = FastAPI(
    title="Factora — Safety Tech Cyber Defense API",
    description="Multi-agent threat analysis, campaign correlation, and community scam intelligence defense platform.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable permissive CORS for frontend team development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Wire all 3 agent routers
app.include_router(analyzer_router)
app.include_router(correlator_router)
app.include_router(community_router)
app.include_router(telegram_router)


@app.on_event("startup")
async def configure_telegram_webhook():
    await register_webhook_if_configured()

FRONTEND_DIR = ROOT_DIR / "frontend"
EXTENSION_DIR = ROOT_DIR / "extension"


@app.get("/", summary="Root UI Dashboard")
async def root():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "platform": "Factora — Fake or Real Safety Tech",
        "status": "operational",
        "docs": "/docs",
        "endpoints": {
            "agent1_analyzer": "/api/analyzer",
            "agent2_correlator": "/api/correlator",
            "member3_community": "/api/community",
            "community_dashboard": "/api/community/ui"
        }
    }


@app.get("/ui", summary="Factora Web Dashboard")
async def ui_dashboard():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"error": "frontend/index.html not found"}


@app.get("/extension/download", summary="Download the Factora Chrome Extension")
async def download_extension(request: Request):
    """Build a downloadable extension ZIP configured for this deployed API host."""
    parsed_origin = urlsplit(str(request.base_url))
    scheme = parsed_origin.scheme if parsed_origin.scheme in {"http", "https"} else "https"
    hostname = parsed_origin.hostname or ""
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", hostname):
        raise HTTPException(status_code=400, detail="Could not determine the Factora server hostname.")
    try:
        port = parsed_origin.port
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid Factora server port.") from exc

    formatted_host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    backend_origin = f"{scheme}://{formatted_host}" + (f":{port}" if port and not default_port else "")
    extension_files = ("manifest.json", "background.js", "content.js", "popup.html", "popup.js")
    archive_buffer = BytesIO()

    with ZipFile(archive_buffer, "w", compression=ZIP_DEFLATED) as archive:
        for filename in extension_files:
            source_path = EXTENSION_DIR / filename
            contents = source_path.read_text(encoding="utf-8")

            if filename == "manifest.json":
                manifest = json.loads(contents)
                host_permissions = manifest.setdefault("host_permissions", [])
                backend_permission = f"{backend_origin}/*"
                if backend_permission not in host_permissions:
                    host_permissions.append(backend_permission)
                contents = json.dumps(manifest, indent=2, ensure_ascii=False)
            elif filename == "background.js":
                contents = contents.replace(
                    'const BACKEND_URL = "http://localhost:8000";',
                    f'const BACKEND_URL = "{backend_origin}";'
                )
            elif filename == "popup.js":
                contents = contents.replace('"http://localhost:8000', f'"{backend_origin}')

            archive.writestr(f"factora-extension/{filename}", contents)

    archive_buffer.seek(0)
    return StreamingResponse(
        iter([archive_buffer.getvalue()]),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="factora-chrome-extension.zip"'}
    )


@app.get("/community", summary="Redirect to Community Dashboard UI")
async def redirect_community_dashboard():
    return RedirectResponse(url="/api/community/ui")


@app.get("/api/health", summary="Overall Health Check")
async def health_check():
    analyzer_loaded = analyzer_scorer.ml_detector is not None
    try:
        correlator_loaded = get_correlator_engine().model is not None
        correlator_error = None if correlator_loaded else "The correlation model did not load."
    except Exception as exc:
        correlator_loaded = False
        correlator_error = str(exc)

    models_ready = analyzer_loaded and correlator_loaded
    return {
        "status": "healthy" if models_ready else "degraded",
        "services": {
            "analyzer": {
                "status": "up" if analyzer_loaded else "degraded",
                "ml_model_loaded": analyzer_loaded,
                "ml_model_error": analyzer_scorer.ml_model_error
            },
            "correlator": {
                "status": "up" if correlator_loaded else "degraded",
                "ml_model_loaded": correlator_loaded,
                "ml_model_error": correlator_error
            },
            "community_hub": "up"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
