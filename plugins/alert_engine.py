"""Alert engine plugin for NetSentinel.

Wraps :class:`modules.alert_engine.AlertEngine` behind the standard plugin
interface, providing rule-based alerting as a loadable plugin.
"""

from __future__ import annotations

import time
from typing import Any

from database.db_manager import DatabaseManager
from modules.alert_engine import AlertEngine
from plugins.base import BasePlugin
from utils.logger import setup_logger

logger = setup_logger("netsentinel.plugins.alert_engine")


class AlertEnginePlugin(BasePlugin):
    """Rule-based alerting engine exposed as a NetSentinel plugin.

    Creates and manages an :class:`AlertEngine` instance, forwarding
    every processed packet to the engine for rule evaluation.

    Args:
        db_manager: Shared ``DatabaseManager`` for alert persistence.
        config: Optional ``Config`` for seeding rules.
    """

    def __init__(
        self,
        db_manager: DatabaseManager | None = None,
        config: Any | None = None,
    ) -> None:
        super().__init__()
        self._db = db_manager
        self._config = config
        self._engine: AlertEngine | None = None
        self._event_count: int = 0
        self._alert_count: int = 0
        self._start_time: float = 0.0

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "alert_engine"

    @property
    def description(self) -> str:
        return "Rule-based alerting engine"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "NetSentinel"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Create the underlying :class:`AlertEngine`."""
        if self._db is None:
            raise RuntimeError(
                "AlertEnginePlugin requires a DatabaseManager instance"
            )
        self._engine = AlertEngine(db_manager=self._db, config=self._config)
        self._start_time = time.time()
        logger.info("AlertEnginePlugin initialised with %d rule(s)",
                     len(self._engine.get_rules()))

    def process_packet(self, packet: dict[str, Any]) -> None:
        """Forward *packet* to the alert engine for evaluation."""
        if self._engine is None:
            return

        self._event_count += 1
        try:
            triggered = self._engine.evaluate(packet)
            self._alert_count += len(triggered)
            if triggered:
                for alert in triggered:
                    logger.warning(
                        "ALERT [%s] %s: %s",
                        alert.get("severity", "?"),
                        alert.get("name", "?"),
                        alert.get("message", ""),
                    )
        except Exception as exc:
            logger.error("Alert evaluation error: %s", exc)

    def cleanup(self) -> None:
        logger.info("AlertEnginePlugin cleaned up")

    # ------------------------------------------------------------------
    # Convenience forwarding
    # ------------------------------------------------------------------

    @property
    def engine(self) -> AlertEngine | None:
        """Direct access to the underlying :class:`AlertEngine`."""
        return self._engine

    def add_rule(self, rule: dict[str, Any]) -> None:
        """Add a rule to the engine (convenience wrapper)."""
        if self._engine is not None:
            self._engine.add_rule(rule)

    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule from the engine (convenience wrapper)."""
        if self._engine is not None:
            return self._engine.remove_rule(rule_name)
        return False

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        engine_stats: dict[str, Any] = {}
        if self._engine is not None:
            engine_stats = self._engine.get_alert_stats()

        return {
            "events_evaluated": self._event_count,
            "alerts_triggered": self._alert_count,
            "rule_count": len(self._engine.get_rules()) if self._engine else 0,
            "severity_distribution": engine_stats.get("by_severity", {}),
            "total_stored_alerts": engine_stats.get("total", 0),
            "last_24h_alerts": engine_stats.get("last_24h", 0),
            "uptime_seconds": round(time.time() - self._start_time, 1)
            if self._start_time
            else 0,
        }

    def get_config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "rate_limit_seconds": {
                    "type": "number",
                    "default": 60,
                    "description": "Minimum seconds between repeated alerts for the same rule+source",
                },
            },
        }
