"""DNS analytics API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from utils.logger import setup_logger

logger = setup_logger("netsentinel.api.routes.dns")

router = APIRouter(prefix="/api/dns", tags=["dns"])


def _state(request: Request) -> Any:
    return request.app.state.netsentinel


@router.get("/queries")
async def dns_queries(
    request: Request,
    limit: int = Query(100, ge=1, le=5000, description="Max records to return"),
    filter: str | None = Query(None, description="Substring match on query name"),
) -> list[dict[str, Any]]:
    """Return recent DNS queries, optionally filtered."""
    state = _state(request)
    try:
        db = state.db_manager
        return db.get_dns_logs(limit=limit, query_filter=filter)
    except Exception as exc:
        logger.exception("Failed to fetch DNS queries")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats")
async def dns_stats(request: Request) -> dict[str, Any]:
    """Return aggregate DNS query statistics."""
    state = _state(request)
    try:
        return state.dns_analytics.get_query_stats()
    except Exception as exc:
        logger.exception("Failed to fetch DNS stats")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/top-domains")
async def top_domains(
    request: Request,
    limit: int = Query(20, ge=1, le=500, description="Number of top domains"),
) -> list[dict[str, Any]]:
    """Return the most queried domain names."""
    state = _state(request)
    try:
        domains = state.dns_analytics.get_top_domains(limit=limit)
        return [{"domain": d, "count": c} for d, c in domains]
    except Exception as exc:
        logger.exception("Failed to fetch top domains")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/errors")
async def dns_errors(request: Request) -> list[dict[str, Any]]:
    """Return recent DNS error responses."""
    state = _state(request)
    try:
        return state.dns_analytics.get_dns_errors()
    except Exception as exc:
        logger.exception("Failed to fetch DNS errors")
        raise HTTPException(status_code=500, detail=str(exc))
