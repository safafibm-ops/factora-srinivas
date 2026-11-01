"""
Factora Main Backend Application
Problem 1: Safety Tech — FAKE OR REAL
Wires Agent 1 (Analyzer), Agent 2 (Correlator), and Member 3 (Community Hub).
"""

import sys
from pathlib import Path

# Ensure root monorepo directory is on pythonpath for seamless imports
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.agent1_analyzer.router import router as analyzer_router
from backend.agent2_correlator.router import router as correlator_router
from backend.community_hub.router import router as community_router

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


@app.get("/", summary="Root Index")
async def root():
    return {
        "platform": "Factora — Fake or Real Safety Tech",
        "status": "operational",
        "docs": "/docs",
        "endpoints": {
            "agent1_analyzer": "/api/analyzer",
            "agent2_correlator": "/api/correlator",
            "member3_community": "/api/community"
        }
    }


@app.get("/api/health", summary="Overall Health Check")
async def health_check():
    return {
        "status": "healthy",
        "services": {
            "analyzer": "up",
            "correlator": "up",
            "community_hub": "up"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)

