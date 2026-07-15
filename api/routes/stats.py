"""General statistics and overview API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from utils.logger import setup_logger

logger = setup_logger("netsentinel.api.routes.stats")

router = APIRouter(prefix="/api/stats", tags=["stats"])


def _state(request: Request) -> Any:
    return request.app.state.netsentinel


@router.get("/overview")
async def overview(request: Request) -> dict[str, Any]:
    """Return a combined overview of every tracked metric.

    Aggregates data from devices, traffic, flows, DNS, TLS, alerts,
    bandwidth, and capture status into a single payload.
    """
    state = _state(request)
    result: dict[str, Any] = {}

    try:
        devices = state.device_discovery.get_devices()
        result["devices"] = {
            "total": len(devices),
            "active": sum(1 for d in devices if d.get("is_active")),
        }
    except Exception:
        result["devices"] = {"total": 0, "active": 0}

    try:
        ts = state.traffic_stats
        result["traffic"] = {
            "packets_per_sec": ts.get_packets_per_second(),
            "bytes_per_sec": ts.get_bytes_per_second(),
            "total_packets": ts.get_total_packets(),
            "total_bytes": ts.get_total_bytes(),
        }
    except Exception:
        result["traffic"] = {}

    try:
        result["flows"] = state.flow_monitor.get_flow_stats()
    except Exception:
        result["flows"] = {}

    try:
        result["dns"] = state.dns_analytics.get_query_stats()
    except Exception:
        result["dns"] = {}

    try:
        result["tls"] = state.certificate_inspector.get_certificate_stats()
    except Exception:
        result["tls"] = {}

    try:
        result["alerts"] = state.alert_engine.get_alert_stats()
    except Exception:
        result["alerts"] = {}

    try:
        result["bandwidth"] = state.bandwidth_monitor.get_current_bandwidth()
    except Exception:
        result["bandwidth"] = {}

    if state.capture_engine is not None:
        try:
            cap = state.capture_engine.get_stats()
            cap["running"] = state.capture_engine.is_running()
            result["capture"] = cap
        except Exception:
            result["capture"] = {}

    return result


@router.get("/bandwidth")
async def bandwidth_history(
    request: Request,
    seconds: int = Query(
        60, ge=1, le=3600, description="History window in seconds"
    ),
) -> list[dict[str, Any]]:
    """Return bandwidth usage history for the requested time window."""
    state = _state(request)
    try:
        return state.bandwidth_monitor.get_history(seconds=seconds)
    except Exception as exc:
        logger.exception("Failed to fetch bandwidth history")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/protocols")
async def protocol_distribution(request: Request) -> dict[str, int]:
    """Return the protocol distribution across observed traffic."""
    state = _state(request)
    try:
        return state.traffic_stats.get_protocol_distribution()
    except Exception as exc:
        logger.exception("Failed to fetch protocol distribution")
        raise HTTPException(status_code=500, detail=str(exc))
