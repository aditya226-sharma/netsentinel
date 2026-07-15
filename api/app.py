"""FastAPI application factory for NetSentinel.

Creates and configures the FastAPI app, mounts static assets for the
React dashboard, wires up all route routers, and manages the global
application state shared across every endpoint.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from config.settings import get_config
from database.db_manager import DatabaseManager
from modules.interface_detector import InterfaceDetector
from modules.device_discovery import DeviceDiscovery
from modules.bandwidth_monitor import BandwidthMonitor
from modules.dns_analytics import DNSAnalytics
from modules.certificate_inspector import CertificateInspector
from modules.traffic_stats import TrafficStats
from modules.flow_monitor import FlowMonitor
from modules.alert_engine import AlertEngine
from plugins.loader import PluginLoader
from capture.engine import PacketCaptureEngine
from utils.logger import setup_logger

logger = setup_logger("netsentinel.api.app")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIST = PROJECT_ROOT / "dashboard" / "frontend" / "dist"


# ------------------------------------------------------------------
# Application state
# ------------------------------------------------------------------

@dataclass
class AppState:
    """Global mutable state shared across all API routes and tasks."""

    db_manager: DatabaseManager
    capture_engine: Optional[PacketCaptureEngine] = None
    interface_detector: InterfaceDetector = field(
        default_factory=InterfaceDetector
    )
    device_discovery: Optional[DeviceDiscovery] = None
    bandwidth_monitor: Optional[BandwidthMonitor] = None
    dns_analytics: Optional[DNSAnalytics] = None
    certificate_inspector: Optional[CertificateInspector] = None
    traffic_stats: Optional[TrafficStats] = None
    flow_monitor: Optional[FlowMonitor] = None
    alert_engine: Optional[AlertEngine] = None
    plugin_loader: Optional[PluginLoader] = None
    ws_manager: Any = field(default=None)

    # Capture helpers
    current_interface: str = ""
    current_bpf: str = ""


# ------------------------------------------------------------------
# SPA fallback helper
# ------------------------------------------------------------------

def _create_spa_fallback(app: FastAPI) -> None:
    """Mount static assets and add middleware to serve the React build.

    If the ``dashboard/frontend/dist`` directory does not exist the
    mount is silently skipped so the API remains functional during
    development.
    """
    if not DASHBOARD_DIST.is_dir():
        logger.warning(
            "Dashboard dist directory not found at %s – "
            "SPA fallback disabled",
            DASHBOARD_DIST,
        )
        return

    index_path = DASHBOARD_DIST / "index.html"

    # Serve every asset under dist/ at /assets/...
    assets_dir = DASHBOARD_DIST / "assets"
    if assets_dir.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=str(assets_dir)),
            name="static-assets",
        )

    class SPAMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            response = await call_next(request)
            # Only intercept 404s for non-API routes
            if response.status_code == 404:
                path = request.url.path
                if not path.startswith("/api/") and path != "/ws":
                    return HTMLResponse(
                        content=index_path.read_text(encoding="utf-8"),
                        status_code=200,
                    )
            return response

    app.add_middleware(SPAMiddleware)


# ------------------------------------------------------------------
# Application factory
# ------------------------------------------------------------------

def create_app(state: AppState) -> FastAPI:
    """Build and configure the FastAPI application.

    Args:
        state: Pre-initialised :class:`AppState` with live module
            references.

    Returns:
        Fully wired :class:`FastAPI` instance ready to run.
    """
    config = get_config()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("NetSentinel API starting up")
        state.db_manager.initialize()
        if state.ws_manager is not None:
            state.ws_manager.start_broadcasting(state)
        if state.plugin_loader is not None:
            state.plugin_loader.load_all_plugins()
        logger.info("NetSentinel API ready")
        yield
        logger.info("NetSentinel API shutting down")
        if state.ws_manager is not None:
            state.ws_manager.stop_broadcasting()
        if state.capture_engine is not None and state.capture_engine.is_running():
            state.capture_engine.stop()
        if state.plugin_loader is not None:
            state.plugin_loader.unload_all()
        state.db_manager.close()
        logger.info("NetSentinel API stopped")

    app = FastAPI(
        title="NetSentinel",
        description="Network Traffic Analysis Framework API",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # Store state so route dependencies can access it
    app.state.netsentinel = state

    # ------------------------------------------------------------------
    # Middleware
    # ------------------------------------------------------------------

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    @app.get("/api/health", tags=["system"])
    async def health_check() -> dict[str, str]:
        """Simple health-check endpoint."""
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/api/info", tags=["system"])
    async def server_info() -> dict[str, Any]:
        """Return basic server configuration metadata."""
        return {
            "version": "0.1.0",
            "auth_enabled": config.auth.enabled,
            "dashboard_theme": config.dashboard.theme,
            "capture_interface": state.current_interface or "(auto)",
        }

    # ------------------------------------------------------------------
    # Route routers
    # ------------------------------------------------------------------

    from api.routes.devices import router as devices_router
    from api.routes.traffic import router as traffic_router
    from api.routes.dns import router as dns_router
    from api.routes.tls import router as tls_router
    from api.routes.alerts import router as alerts_router
    from api.routes.stats import router as stats_router
    from api.routes.capture import router as capture_router
    from api.routes.export import router as export_router

    app.include_router(devices_router)
    app.include_router(traffic_router)
    app.include_router(dns_router)
    app.include_router(tls_router)
    app.include_router(alerts_router)
    app.include_router(stats_router)
    app.include_router(capture_router)
    app.include_router(export_router)

    # ------------------------------------------------------------------
    # WebSocket endpoint
    # ------------------------------------------------------------------

    from fastapi import WebSocket as _WS

    @app.websocket("/ws")
    async def websocket_endpoint(ws: _WS) -> None:
        """Endpoint for real-time stats streaming via WebSocket."""
        mgr = state.ws_manager
        if mgr is None:
            await ws.close(code=1011, reason="WebSocket manager not initialised")
            return
        await mgr.connect(ws)
        try:
            while True:
                # Keep the connection alive; ignore incoming messages
                await ws.receive_text()
        except WebSocketDisconnect:
            await mgr.disconnect(ws)
        except Exception:
            await mgr.disconnect(ws)

    # ------------------------------------------------------------------
    # SPA fallback (registered last so API routes take priority)
    # ------------------------------------------------------------------

    _create_spa_fallback(app)

    return app
