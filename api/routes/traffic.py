"""Traffic analysis and flow API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from utils.logger import setup_logger

logger = setup_logger("netsentinel.api.routes.traffic")

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


def _state(request: Request) -> Any:
    return request.app.state.netsentinel


@router.get("/overview")
async def traffic_overview(request: Request) -> dict[str, Any]:
    """Return protocol distribution, packets/sec, and bytes/sec."""
    state = _state(request)
    ts = state.traffic_stats
    try:
        return {
            "protocol_distribution": ts.get_protocol_distribution(),
            "packets_per_sec": ts.get_packets_per_second(),
            "bytes_per_sec": ts.get_bytes_per_second(),
            "total_packets": ts.get_total_packets(),
            "total_bytes": ts.get_total_bytes(),
        }
    except Exception as exc:
        logger.exception("Failed to build traffic overview")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/top-talkers")
async def top_talkers(request: Request) -> list[dict[str, Any]]:
    """Return the top source IPs by total bytes transferred."""
    state = _state(request)
    try:
        talkers = state.traffic_stats.get_top_talkers(limit=25)
        return [{"ip": ip, "total_bytes": b} for ip, b in talkers]
    except Exception as exc:
        logger.exception("Failed to fetch top talkers")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/top-destinations")
async def top_destinations(request: Request) -> list[dict[str, Any]]:
    """Return the top destination IPs by total bytes transferred."""
    state = _state(request)
    try:
        dests = state.traffic_stats.get_top_destinations(limit=25)
        return [{"ip": ip, "total_bytes": b} for ip, b in dests]
    except Exception as exc:
        logger.exception("Failed to fetch top destinations")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/flows/{flow_id}")
async def get_flow(flow_id: str, request: Request) -> dict[str, Any]:
    """Retrieve a specific flow by its identifier."""
    state = _state(request)
    flow = state.flow_monitor.get_flow_by_id(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
    return flow


@router.get("/flows")
async def list_flows(request: Request) -> dict[str, Any]:
    """Return active network flows and aggregate flow statistics."""
    state = _state(request)
    try:
        return {
            "flows": state.flow_monitor.get_active_flows(),
            "stats": state.flow_monitor.get_flow_stats(),
        }
    except Exception as exc:
        logger.exception("Failed to fetch flows")
        raise HTTPException(status_code=500, detail=str(exc))
