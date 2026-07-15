"""Alert management API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from utils.logger import setup_logger

logger = setup_logger("netsentinel.api.routes.alerts")

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _state(request: Request) -> Any:
    return request.app.state.netsentinel


@router.get("/stats")
async def alert_stats(request: Request) -> dict[str, Any]:
    """Return aggregate alert statistics (counts by severity, etc.)."""
    state = _state(request)
    try:
        return state.alert_engine.get_alert_stats()
    except Exception as exc:
        logger.exception("Failed to fetch alert stats")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/acknowledge/{alert_id}")
async def acknowledge_alert(alert_id: str, request: Request) -> dict[str, str]:
    """Acknowledge an alert by ID.

    .. note::
        Full acknowledge logic is not yet implemented.  Always returns
        HTTP 200.
    """
    logger.info("Alert %s acknowledged (stub)", alert_id)
    return {"status": "ok", "alert_id": alert_id}


@router.get("")
async def list_alerts(
    request: Request,
    limit: int = Query(100, ge=1, le=5000, description="Max records"),
    severity: str | None = Query(
        None,
        description="Filter by severity: critical, high, medium, low, info",
    ),
) -> list[dict[str, Any]]:
    """Return recent alerts with optional severity filtering."""
    state = _state(request)
    try:
        return state.alert_engine.get_recent_alerts(
            limit=limit, severity=severity
        )
    except Exception as exc:
        logger.exception("Failed to fetch alerts")
        raise HTTPException(status_code=500, detail=str(exc))
