"""Packet capture control API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from capture.engine import PacketCaptureEngine
from modules.interface_detector import InterfaceDetector
from utils.logger import setup_logger

logger = setup_logger("netsentinel.api.routes.capture")

router = APIRouter(prefix="/api/capture", tags=["capture"])


def _state(request: Request) -> Any:
    return request.app.state.netsentinel


@router.get("/interfaces")
async def list_interfaces(request: Request) -> list[dict[str, Any]]:
    """List all detected network interfaces."""
    state = _state(request)
    try:
        return state.interface_detector.get_interfaces()
    except Exception as exc:
        logger.exception("Failed to enumerate interfaces")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/status")
async def capture_status(request: Request) -> dict[str, Any]:
    """Return current capture engine status and statistics."""
    state = _state(request)
    if state.capture_engine is None:
        return {
            "running": False,
            "interface": "",
            "bpf_filter": "",
            "stats": {},
        }

    try:
        running = state.capture_engine.is_running()
        stats = state.capture_engine.get_stats()
        return {
            "running": running,
            "interface": state.current_interface,
            "bpf_filter": state.current_bpf,
            "stats": stats,
        }
    except Exception as exc:
        logger.exception("Failed to query capture status")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/stop")
async def stop_capture(request: Request) -> dict[str, str]:
    """Stop the running packet capture engine."""
    state = _state(request)
    if state.capture_engine is None or not state.capture_engine.is_running():
        raise HTTPException(
            status_code=409, detail="Capture is not running"
        )
    try:
        state.capture_engine.stop()
        logger.info("Capture stopped via API")
        return {"status": "stopped"}
    except Exception as exc:
        logger.exception("Failed to stop capture")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/start")
async def start_capture(
    request: Request,
    interface: str | None = Query(
        None, description="Network interface to capture on"
    ),
    bpf_filter: str | None = Query(
        None, description="BPF filter expression"
    ),
) -> dict[str, str]:
    """Start packet capture on the specified interface.

    If *interface* is omitted the system default is used.  An optional
    BPF filter can narrow the capture scope.
    """
    state = _state(request)
    if (
        state.capture_engine is not None
        and state.capture_engine.is_running()
    ):
        raise HTTPException(
            status_code=409, detail="Capture is already running"
        )

    iface = interface or state.interface_detector.get_default_interface()
    state.current_interface = iface
    state.current_bpf = bpf_filter or ""

    # Build packet pipeline callback
    def _on_packet(packet: Any) -> None:
        try:
            state.traffic_stats.process_packet(packet)
        except Exception:
            pass
        try:
            state.bandwidth_monitor.process_packet(packet)
        except Exception:
            pass
        try:
            state.device_discovery.process_packet(packet)
        except Exception:
            pass
        try:
            state.flow_monitor.process_packet(packet)
        except Exception:
            pass
        try:
            state.dns_analytics.process_packet(packet)
        except Exception:
            pass
        try:
            state.certificate_inspector.process_packet(packet)
        except Exception:
            pass

    try:
        state.capture_engine = PacketCaptureEngine(
            interface=iface,
            bpf_filter=bpf_filter or None,
            packet_callback=_on_packet,
            db_manager=state.db_manager,
        )
        state.capture_engine.start()
        logger.info(
            "Capture started via API (iface=%s, bpf=%r)",
            iface,
            bpf_filter,
        )
        return {"status": "started", "interface": iface}
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail="Packet capture requires root/admin privileges",
        )
    except Exception as exc:
        logger.exception("Failed to start capture")
        raise HTTPException(status_code=500, detail=str(exc))
