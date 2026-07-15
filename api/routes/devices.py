"""Device discovery and inventory API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, Query

from utils.logger import setup_logger

logger = setup_logger("netsentinel.api.routes.devices")

router = APIRouter(prefix="/api/devices", tags=["devices"])


def _state(request: Request) -> Any:
    return request.app.state.netsentinel


@router.get("/stats")
async def device_statistics(request: Request) -> dict[str, Any]:
    """Return aggregate device statistics.

    Provides counts of active, inactive and total known devices plus
    vendor distribution information.
    """
    state = _state(request)
    try:
        devices = state.device_discovery.get_devices()
    except Exception as exc:
        logger.exception("Failed to fetch device stats")
        raise HTTPException(status_code=500, detail=str(exc))

    active = [d for d in devices if d.get("is_active")]
    vendors: dict[str, int] = {}
    for d in devices:
        v = d.get("vendor", "") or "Unknown"
        vendors[v] = vendors.get(v, 0) + 1

    return {
        "total": len(devices),
        "active": len(active),
        "inactive": len(devices) - len(active),
        "vendors": vendors,
    }


@router.get("/{mac}")
async def get_device(mac: str, request: Request) -> dict[str, Any]:
    """Retrieve a single device by its MAC address."""
    state = _state(request)
    device = state.device_discovery.get_device(mac)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device {mac} not found")
    return device


@router.get("")
async def list_devices(
    request: Request,
    active_only: bool = Query(False, description="Only return active devices"),
) -> list[dict[str, Any]]:
    """List all discovered devices."""
    state = _state(request)
    try:
        devices = state.device_discovery.get_devices()
    except Exception as exc:
        logger.exception("Failed to list devices")
        raise HTTPException(status_code=500, detail=str(exc))

    if active_only:
        devices = [d for d in devices if d.get("is_active")]

    return devices
