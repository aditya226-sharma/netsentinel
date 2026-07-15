"""TLS/SSL inspection API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from utils.logger import setup_logger

logger = setup_logger("netsentinel.api.routes.tls")

router = APIRouter(prefix="/api/tls", tags=["tls"])


def _state(request: Request) -> Any:
    return request.app.state.netsentinel


@router.get("/sessions")
async def tls_sessions(request: Request) -> list[dict[str, Any]]:
    """Return all observed TLS sessions."""
    state = _state(request)
    try:
        return state.certificate_inspector.get_tls_sessions()
    except Exception as exc:
        logger.exception("Failed to fetch TLS sessions")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats")
async def tls_stats(request: Request) -> dict[str, Any]:
    """Return aggregate TLS statistics."""
    state = _state(request)
    try:
        return state.certificate_inspector.get_certificate_stats()
    except Exception as exc:
        logger.exception("Failed to fetch TLS stats")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/expired")
async def expired_certificates(request: Request) -> list[dict[str, Any]]:
    """Return TLS sessions with expired or soon-to-expire certificates."""
    state = _state(request)
    try:
        return state.certificate_inspector.get_expired_certificates()
    except Exception as exc:
        logger.exception("Failed to fetch expired certificates")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{sni}")
async def tls_session_by_sni(sni: str, request: Request) -> dict[str, Any]:
    """Retrieve a TLS session by its Server Name Indication."""
    state = _state(request)
    session = state.certificate_inspector.get_certificate_by_sni(sni)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail=f"No TLS session found for SNI '{sni}'",
        )
    return session
