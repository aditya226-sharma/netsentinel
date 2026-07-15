"""Data export API routes (JSON, CSV, PCAP placeholders)."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from utils.logger import setup_logger

logger = setup_logger("netsentinel.api.routes.export")

router = APIRouter(prefix="/api/export", tags=["export"])


def _state(request: Request) -> Any:
    return request.app.state.netsentinel


@router.get("/json")
async def export_json(request: Request) -> dict[str, Any]:
    """Export all collected data as a single JSON structure."""
    state = _state(request)
    data: dict[str, Any] = {}

    try:
        data["devices"] = state.device_discovery.get_devices()
    except Exception:
        data["devices"] = []

    try:
        data["traffic"] = {
            "protocol_distribution": state.traffic_stats.get_protocol_distribution(),
            "top_talkers": [
                {"ip": ip, "total_bytes": b}
                for ip, b in state.traffic_stats.get_top_talkers(limit=50)
            ],
            "top_destinations": [
                {"ip": ip, "total_bytes": b}
                for ip, b in state.traffic_stats.get_top_destinations(limit=50)
            ],
        }
    except Exception:
        data["traffic"] = {}

    try:
        data["flows"] = state.flow_monitor.get_active_flows()
    except Exception:
        data["flows"] = []

    try:
        data["dns_queries"] = state.db_manager.get_dns_logs(limit=5000)
    except Exception:
        data["dns_queries"] = []

    try:
        data["tls_sessions"] = state.certificate_inspector.get_tls_sessions()
    except Exception:
        data["tls_sessions"] = []

    try:
        data["alerts"] = state.db_manager.get_alerts(limit=5000)
    except Exception:
        data["alerts"] = []

    return data


@router.get("/csv")
async def export_csv(request: Request) -> StreamingResponse:
    """Export the device inventory as a CSV download."""
    state = _state(request)
    try:
        devices = state.device_discovery.get_devices()
    except Exception as exc:
        logger.exception("Failed to export devices as CSV")
        raise HTTPException(status_code=500, detail=str(exc))

    if not devices:
        devices = []

    headers = list(devices[0].keys()) if devices else [
        "id", "mac", "ip", "hostname", "vendor", "os_fingerprint",
        "first_seen", "last_seen", "is_active",
    ]

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    for d in devices:
        writer.writerow(d)

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=netsentinel_devices.csv"
        },
    )


@router.get("/pcap")
async def export_pcap() -> dict[str, str]:
    """Placeholder for PCAP export.

    Full PCAP export requires an active packet capture session and is
    not yet implemented.
    """
    return {
        "status": "not_implemented",
        "message": (
            "PCAP export requires an active capture session. "
            "Start a capture first, then request this endpoint."
        ),
    }
