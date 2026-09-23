"""FastAPI V1 REST API Endpoints for PhishGuard.

Endpoints:
    - POST /api/v1/analyze: Submit URL for adaptive multimodal phishing detection
    - GET  /api/v1/health: System health and active model metadata
    - GET  /api/v1/history: Query historical analysis logs from database
    - GET  /api/v1/experiments: Retrieve research experiment metrics (Experiments 1-7)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, HttpUrl

from backend.app.adaptive.decision_engine import AdaptiveDecisionEngine
from backend.app.core.config import PROJECT_ROOT, get_settings
from backend.app.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Analysis"])

# Singleton engine instance
engine = AdaptiveDecisionEngine()


# Request / Response Schemas
class AnalyzeRequest(BaseModel):
    url: str = Field(..., example="https://example.com", description="Target website URL to analyze")
    force_full_analysis: bool = Field(default=False, description="If True, bypasses early stopping and runs all 6 modalities")


class AnalyzeResponse(BaseModel):
    request_id: str
    url: str
    prediction: str
    confidence: float
    risk_level: str
    stage_reached: str
    modalities_used: int
    early_stopped: bool
    total_latency_ms: float
    stage_latencies_ms: dict[str, float]
    explanation: dict[str, Any]
    created_at: str
    errors: list[str]


class HealthResponse(BaseModel):
    status: str
    app_name: str
    version: str
    environment: str
    loaded_models: dict[str, str]
    timestamp: str


# In-memory history cache for API history queries
_ANALYSIS_HISTORY: list[dict[str, Any]] = []


@router.post("/analyze", response_model=AnalyzeResponse, status_code=status.HTTP_200_OK)
async def analyze_url_endpoint(req: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze a URL using the adaptive multimodal phishing detection framework."""
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")

    req_id = f"req_{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        res = await engine.analyze_url(
            req.url,
            sample_id=req_id,
            force_full_analysis=req.force_full_analysis,
        )

        response_data = {
            "request_id": req_id,
            "url": res.url,
            "prediction": res.prediction,
            "confidence": res.confidence,
            "risk_level": res.risk_level,
            "stage_reached": res.stage_reached,
            "modalities_used": res.modalities_used,
            "early_stopped": res.early_stopped,
            "total_latency_ms": res.total_latency_ms,
            "stage_latencies_ms": res.stage_latencies_ms,
            "explanation": res.explanation,
            "created_at": now_iso,
            "errors": res.errors,
        }

        # Cache in history log (keep last 100)
        _ANALYSIS_HISTORY.insert(0, response_data)
        if len(_ANALYSIS_HISTORY) > 100:
            _ANALYSIS_HISTORY.pop()

        return AnalyzeResponse(**response_data)

    except Exception as e:
        logger.error(f"API analysis error for {req.url}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal analysis error: {str(e)}")


@router.get("/health", response_model=HealthResponse)
async def get_health_endpoint() -> HealthResponse:
    """Get system health, active config, and model versions."""
    settings = get_settings()
    now_iso = datetime.now(timezone.utc).isoformat()

    return HealthResponse(
        status="healthy",
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        loaded_models={
            "url_analyzer": "v1.0 (22 features)",
            "html_analyzer": "v1.0 (28 features)",
            "ssl_analyzer": "v1.0 (10 features)",
            "domain_analyzer": "v1.0 (6 features)",
            "ocr_analyzer": "v1.0 EasyOCR (13 features)",
            "visual_analyzer": "v1.0 CLIP ViT-B/32 + FAISS",
            "fusion_model": "PyTorch MultimodalFusionModel (192d)",
        },
        timestamp=now_iso,
    )


@router.get("/history")
async def get_history_endpoint(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    prediction: str | None = Query(default=None, description="Filter by 'benign' or 'phishing'"),
) -> dict[str, Any]:
    """Retrieve historical analysis logs."""
    filtered = _ANALYSIS_HISTORY
    if prediction:
        filtered = [item for item in filtered if item.get("prediction") == prediction.lower()]

    paginated = filtered[offset : offset + limit]
    return {
        "total": len(filtered),
        "limit": limit,
        "offset": offset,
        "items": paginated,
    }


@router.get("/experiments")
async def get_experiments_endpoint() -> dict[str, Any]:
    """Retrieve saved research experiment metrics (Experiments 1-7)."""
    saved_dir = PROJECT_ROOT / "ml" / "models" / "saved"

    base_metrics = {}
    base_file = saved_dir / "baseline_metrics.json"
    if base_file.exists():
        with open(base_file, "r", encoding="utf-8") as f:
            base_metrics = json.load(f)

    fusion_metrics = {}
    fusion_file = saved_dir / "fusion_metrics.json"
    if fusion_file.exists():
        with open(fusion_file, "r", encoding="utf-8") as f:
            fusion_metrics = json.load(f)

    adaptive_metrics = {}
    adaptive_file = saved_dir / "experiment7_adaptive_metrics.json"
    if adaptive_file.exists():
        with open(adaptive_file, "r", encoding="utf-8") as f:
            adaptive_metrics = json.load(f)

    return {
        "experiments_1_to_5_baselines": base_metrics,
        "experiment_6_full_multimodal_fusion": fusion_metrics,
        "experiment_7_adaptive_system": adaptive_metrics,
    }
