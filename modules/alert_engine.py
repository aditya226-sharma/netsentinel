"""Rule-based alert engine for NetSentinel.

Evaluates network events against a configurable set of rules and persists
triggered alerts to the database.
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict
from typing import Any

from database.db_manager import DatabaseManager
from utils.helpers import generate_id, get_timestamp
from utils.logger import setup_logger

logger = setup_logger("netsentinel.alert_engine")

# Time window (seconds) used by built-in detectors
_PORT_SCAN_WINDOW: float = 60.0
_PORT_SCAN_THRESHOLD: int = 20
_DNS_TUNNEL_LENGTH: int = 50
_BANDWIDTH_SPIKE_BPS: float = 10 * 1024 * 1024  # 10 MB/s
_NXDOMAIN_RATE_THRESHOLD: int = 50
_RATE_LIMIT_SECONDS: float = 60.0

_VALID_SEVERITIES: frozenset[str] = frozenset({
    "critical", "high", "medium", "low", "info",
})


class AlertEngine:
    """Evaluates network events against alert rules and stores triggered alerts.

    Thread-safe: all mutable state is guarded by ``_lock``.

    Args:
        db_manager: Initialized ``DatabaseManager`` for persisting alerts.
        config: Optional ``Config`` object; if ``None`` the engine starts
            with an empty rule set.
    """

    def __init__(
        self,
        db_manager: DatabaseManager,
        config: Any | None = None,
    ) -> None:
        self._db = db_manager
        self._lock = threading.Lock()
        self._rules: list[dict[str, Any]] = []

        # Built-in detector state -------------------------------------------
        # port scan detector: src_ip -> {dst_port: last_seen_timestamp}
        self._port_scan_state: dict[str, dict[int, float]] = defaultdict(dict)
        # bandwidth spike detector: interface -> bytes_per_sec history
        self._bandwidth_history: dict[str, list[tuple[float, float]]] = defaultdict(list)
        # DNS NXDOMAIN rate tracker: src_ip -> [(timestamp, is_nxdomain)]
        self._dns_nxdomain_state: dict[str, list[tuple[float, bool]]] = defaultdict(list)

        # Rate limiting: (rule_name, source_ip) -> last_alert_timestamp
        self._rate_limit: dict[tuple[str, str], float] = {}

        # Load config rules -------------------------------------------------
        if config is not None:
            self._load_config_rules(config)

        logger.info(
            "AlertEngine initialised with %d rule(s)", len(self._rules)
        )

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def _load_config_rules(self, config: Any) -> None:
        """Seed rules from a ``Config`` object."""
        for rule in config.alerts.rules:
            self._rules.append({
                "name": rule.name,
                "condition": rule.condition,
                "severity": rule.severity,
                "message": rule.message,
            })

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Evaluate an event against all loaded rules.

        Args:
            event: Dictionary describing the network event.  Keys vary by
                event type but commonly include ``src_ip``, ``dst_ip``,
                ``dst_port``, ``protocol``, ``dns_query``, ``bytes_per_sec``,
                etc.

        Returns:
            List of alert dictionaries for rules that triggered.
        """
        triggered: list[dict[str, Any]] = []

        with self._lock:
            for rule in self._rules:
                if self._check_rule(rule, event):
                    key = (rule["name"], event.get("src_ip", ""))
                    now = time.time()
                    last = self._rate_limit.get(key, 0.0)
                    if now - last < _RATE_LIMIT_SECONDS:
                        continue
                    self._rate_limit[key] = now

                    alert = self._build_alert(rule, event)
                    self._persist_alert(alert)
                    triggered.append(alert)

        return triggered

    def add_rule(self, rule: dict[str, Any]) -> None:
        """Add a rule at runtime.

        Args:
            rule: Dictionary with at least ``name``, ``condition``,
                ``severity`` and ``message`` keys.
        """
        severity = rule.get("severity", "info").lower()
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity {severity!r}. "
                f"Must be one of {_VALID_SEVERITIES}"
            )
        with self._lock:
            self._rules.append(rule)
        logger.info("Added alert rule: %s", rule.get("name", "unnamed"))

    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule by name.

        Returns:
            ``True`` if a rule was removed, ``False`` if not found.
        """
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.get("name") != rule_name]
            removed = len(self._rules) < before
        if removed:
            logger.info("Removed alert rule: %s", rule_name)
        return removed

    def get_rules(self) -> list[dict[str, Any]]:
        """Return a shallow copy of the current rule list."""
        with self._lock:
            return list(self._rules)

    def get_recent_alerts(
        self,
        limit: int = 50,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch recent alerts from the database.

        Args:
            limit: Maximum number of alerts to return.
            severity: Optional severity filter.

        Returns:
            List of alert dictionaries, most recent first.
        """
        try:
            return self._db.get_alerts(limit=limit, severity_filter=severity)
        except Exception as exc:
            logger.error("Failed to fetch recent alerts: %s", exc)
            return []

    def get_alert_stats(self) -> dict[str, Any]:
        """Return aggregate alert statistics.

        Returns:
            Dictionary with ``total``, ``by_severity`` and ``last_24h`` keys.
        """
        try:
            all_alerts = self._db.get_alerts(limit=100_000)
        except Exception as exc:
            logger.error("Failed to compute alert stats: %s", exc)
            return {"total": 0, "by_severity": {}, "last_24h": 0}

        by_severity: dict[str, int] = defaultdict(int)
        cutoff = time.time() - 86400
        last_24h = 0

        for alert in all_alerts:
            sev = alert.get("severity", "unknown")
            by_severity[sev] += 1
            ts = alert.get("timestamp", "")
            try:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(ts)
                if dt.timestamp() > cutoff:
                    last_24h += 1
            except (ValueError, TypeError, OSError):
                pass

        return {
            "total": len(all_alerts),
            "by_severity": dict(by_severity),
            "last_24h": last_24h,
        }

    # ------------------------------------------------------------------
    # Rule checking
    # ------------------------------------------------------------------

    def _check_rule(self, rule: dict[str, Any], event: dict[str, Any]) -> bool:
        """Check whether a single rule matches the given event."""
        condition = rule.get("condition", "")
        if not condition:
            return False

        # Handle built-in condition names first
        builtins = {
            "high_port_scan": self._builtin_high_port_scan,
            "dns_tunnel_suspect": self._builtin_dns_tunnel_suspect,
            "new_device": self._builtin_new_device,
            "bandwidth_spike": self._builtin_bandwidth_spike,
            "suspicious_dns": self._builtin_suspicious_dns,
        }
        if condition in builtins:
            return builtins[condition](event)

        return self._evaluate_condition(condition, event)

    # ------------------------------------------------------------------
    # Condition evaluator
    # ------------------------------------------------------------------

    def _evaluate_condition(self, condition: str, event: dict[str, Any]) -> bool:
        """Evaluate a human-readable condition string against an event dict.

        Supported operators: ``>``, ``>=``, ``<``, ``<=``, ``==``, ``!=``.

        The left-hand side is treated as an event key (with dotted access
        via a simple split).  The right-hand side is parsed as a number
        when possible, otherwise compared as a string.
        """
        for op in (">=", "<=", "!=", "==", ">", "<"):
            parts = condition.split(op, 1)
            if len(parts) == 2:
                lhs_key = parts[0].strip()
                rhs_raw = parts[1].strip()

                value = self._resolve_key(lhs_key, event)
                if value is None:
                    return False

                rhs: Any
                try:
                    rhs = int(rhs_raw)
                except ValueError:
                    try:
                        rhs = float(rhs_raw)
                    except ValueError:
                        rhs = rhs_raw.strip('"').strip("'")

                try:
                    if op == ">":
                        return value > rhs
                    if op == ">=":
                        return value >= rhs
                    if op == "<":
                        return value < rhs
                    if op == "<=":
                        return value <= rhs
                    if op == "==":
                        return value == rhs
                    if op == "!=":
                        return value != rhs
                except TypeError:
                    return False

        return False

    @staticmethod
    def _resolve_key(key: str, event: dict[str, Any]) -> Any:
        """Resolve a dotted key path against a dictionary."""
        current: Any = event
        for segment in key.split("."):
            if isinstance(current, dict):
                current = current.get(segment)
            else:
                return None
        return current

    # ------------------------------------------------------------------
    # Built-in detectors
    # ------------------------------------------------------------------

    def _builtin_high_port_scan(self, event: dict[str, Any]) -> bool:
        """Detect many SYN packets to different ports from the same IP."""
        src_ip = event.get("src_ip", "")
        dst_port = event.get("dst_port")
        flags = str(event.get("tcp_flags", "")).upper()

        if not src_ip or dst_port is None:
            return False

        # Only count SYN packets (flag 0x02)
        is_syn = "SYN" in flags or (isinstance(flags, str) and "02" in flags)
        if not is_syn:
            return False

        now = time.time()
        ports = self._port_scan_state[src_ip]

        # Prune old entries
        stale = [p for p, t in ports.items() if now - t > _PORT_SCAN_WINDOW]
        for p in stale:
            del ports[p]

        ports[int(dst_port)] = now
        return len(ports) >= _PORT_SCAN_THRESHOLD

    def _builtin_dns_tunnel_suspect(self, event: dict[str, Any]) -> bool:
        """Detect unusually long DNS queries (possible DNS tunneling)."""
        query = event.get("dns_query", "")
        if not query:
            return False
        # Strip the trailing dot
        qname = str(query).rstrip(".")
        return len(qname) > _DNS_TUNNEL_LENGTH

    def _builtin_new_device(self, event: dict[str, Any]) -> bool:
        """Alert when a device is flagged as new in the event dict."""
        return bool(event.get("is_new_device", False))

    def _builtin_bandwidth_spike(self, event: dict[str, Any]) -> bool:
        """Alert on a sudden bandwidth increase."""
        bps = event.get("bytes_per_sec", 0)
        try:
            return float(bps) > _BANDWIDTH_SPIKE_BPS
        except (TypeError, ValueError):
            return False

    def _builtin_suspicious_dns(self, event: dict[str, Any]) -> bool:
        """Alert on high NXDOMAIN rate from a single source."""
        src_ip = event.get("src_ip", "")
        response_code = str(event.get("dns_response_code", "")).upper()
        if not src_ip:
            return False

        now = time.time()
        is_nxdomain = response_code in ("NXDOMAIN", "3")
        self._dns_nxdomain_state[src_ip].append((now, is_nxdomain))

        # Prune entries older than the window
        entries = self._dns_nxdomain_state[src_ip]
        self._dns_nxdomain_state[src_ip] = [
            (t, v) for t, v in entries if now - t <= _PORT_SCAN_WINDOW
        ]

        nxdomain_count = sum(1 for _, v in self._dns_nxdomain_state[src_ip] if v)
        return nxdomain_count >= _NXDOMAIN_RATE_THRESHOLD

    # ------------------------------------------------------------------
    # Alert persistence
    # ------------------------------------------------------------------

    def _build_alert(self, rule: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        """Construct an alert dict from a rule and event."""
        message = rule.get("message", "")
        # Simple template substitution: {{key}}
        for match in re.finditer(r"\{\{(\w+)\}\}", message):
            key = match.group(1)
            value = event.get(key, match.group(0))
            message = message.replace(match.group(0), str(value))

        return {
            "id": generate_id(),
            "timestamp": get_timestamp(),
            "severity": rule.get("severity", "info"),
            "name": rule.get("name", "unnamed"),
            "message": message,
            "source_ip": event.get("src_ip", ""),
            "details": str(event),
        }

    def _persist_alert(self, alert: dict[str, Any]) -> None:
        """Store an alert in the database, logging on failure."""
        try:
            self._db.insert_alert(alert)
        except Exception as exc:
            logger.error("Failed to persist alert %s: %s", alert.get("name"), exc)
