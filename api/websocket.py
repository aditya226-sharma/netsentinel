"""WebSocket connection manager and periodic broadcast.

Maintains a set of connected WebSocket clients and periodically pushes
aggregated stats collected from all active modules.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from config.settings import get_config
from utils.logger import setup_logger
from utils.helpers import get_timestamp

logger = setup_logger("netsentinel.api.websocket")


class ConnectionManager:
    """Manages WebSocket connections and periodic stats broadcasting.

    Usage::

        manager = ConnectionManager()
        manager.start_broadcasting(state)

        # In a route:
        await manager.connect(websocket)
    """

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = threading.Lock()
        self._broadcast_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket client."""
        await websocket.accept()
        with self._lock:
            self._connections.append(websocket)
        logger.info(
            "WebSocket client connected (total: %d)",
            len(self._connections),
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket client from the active set."""
        with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)
        logger.info(
            "WebSocket client disconnected (total: %d)",
            len(self._connections),
        )

    @property
    def active_connections(self) -> int:
        """Return the number of currently connected clients."""
        with self._lock:
            return len(self._connections)

    # ------------------------------------------------------------------
    # Message sending
    # ------------------------------------------------------------------

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Send a JSON message to all connected clients.

        Failed connections are silently removed.

        Args:
            message: Dictionary payload that will be JSON-serialised.
        """
        payload = json.dumps(message, default=str)
        dead: list[WebSocket] = []

        with self._lock:
            clients = list(self._connections)

        for ws in clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        if dead:
            with self._lock:
                for ws in dead:
                    if ws in self._connections:
                        self._connections.remove(ws)
            logger.debug("Pruned %d dead WebSocket connection(s)", len(dead))

    async def broadcast_stats(self, stats: dict[str, Any]) -> None:
        """Broadcast a formatted stats update envelope.

        Wraps *stats* in a standard message envelope with type and
        timestamp metadata.

        Args:
            stats: Aggregated statistics dictionary.
        """
        message = {
            "type": "stats_update",
            "timestamp": get_timestamp(),
            "data": stats,
        }
        await self.broadcast(message)

    # ------------------------------------------------------------------
    # Background broadcasting
    # ------------------------------------------------------------------

    def start_broadcasting(self, state: Any) -> None:
        """Start the background thread that periodically broadcasts stats.

        Args:
            state: The application state object that holds module
                references needed to collect stats.
        """
        if (
            self._broadcast_thread is not None
            and self._broadcast_thread.is_alive()
        ):
            logger.debug("Broadcast thread already running")
            return

        self._stop_event.clear()
        self._broadcast_thread = threading.Thread(
            target=self._broadcast_loop,
            args=(state,),
            name="netsentinel-ws-broadcast",
            daemon=True,
        )
        self._broadcast_thread.start()
        logger.info("WebSocket broadcast thread started")

    def stop_broadcasting(self) -> None:
        """Signal the broadcast thread to stop and wait for it."""
        self._stop_event.set()
        if self._broadcast_thread is not None:
            self._broadcast_thread.join(timeout=5.0)
            self._broadcast_thread = None
        logger.info("WebSocket broadcast thread stopped")

    def _broadcast_loop(self, state: Any) -> None:
        """Blocking loop executed in the background thread.

        Collects stats from all modules and pushes them to connected
        clients at the configured refresh interval.
        """
        import asyncio

        config = get_config()
        interval = config.dashboard.refresh_interval
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        logger.info(
            "Broadcast loop started (interval=%ds)", interval
        )

        while not self._stop_event.is_set():
            try:
                stats = self._collect_stats(state)
                if self.active_connections > 0:
                    loop.run_until_complete(
                        self.broadcast_stats(stats)
                    )
            except Exception:
                logger.exception("Error during stats broadcast")

            self._stop_event.wait(timeout=interval)

        loop.close()
        logger.debug("Broadcast loop exited")

    @staticmethod
    def _collect_stats(state: Any) -> dict[str, Any]:
        """Gather a snapshot of stats from every module in *state*.

        Returns a plain dictionary suitable for JSON serialisation.
        """
        stats: dict[str, Any] = {}

        try:
            bw = state.bandwidth_monitor.get_current_bandwidth()
            stats["bandwidth"] = bw
        except Exception:
            stats["bandwidth"] = {}

        try:
            ts = state.traffic_stats
            stats["traffic"] = {
                "packets_per_sec": ts.get_packets_per_second(),
                "bytes_per_sec": ts.get_bytes_per_second(),
                "total_packets": ts.get_total_packets(),
                "total_bytes": ts.get_total_bytes(),
                "protocol_distribution": ts.get_protocol_distribution(),
            }
        except Exception:
            stats["traffic"] = {}

        try:
            stats["devices"] = {
                "count": len(state.device_discovery.get_devices()),
            }
        except Exception:
            stats["devices"] = {}

        try:
            fm = state.flow_monitor
            stats["flows"] = fm.get_flow_stats()
        except Exception:
            stats["flows"] = {}

        try:
            stats["dns"] = state.dns_analytics.get_query_stats()
        except Exception:
            stats["dns"] = {}

        try:
            stats["tls"] = state.certificate_inspector.get_certificate_stats()
        except Exception:
            stats["tls"] = {}

        try:
            stats["alerts"] = state.alert_engine.get_alert_stats()
        except Exception:
            stats["alerts"] = {}

        if state.capture_engine is not None:
            try:
                stats["capture"] = state.capture_engine.get_stats()
                stats["capture"]["running"] = state.capture_engine.is_running()
            except Exception:
                stats["capture"] = {}

        return stats
