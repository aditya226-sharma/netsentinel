"""TLS/SSL session monitoring plugin for NetSentinel.

Tracks Server Name Indications (SNIs), cipher suites, TLS versions and
certificate expiry.  Flags weak ciphers and outdated protocol versions.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from plugins.base import BasePlugin
from utils.logger import setup_logger

logger = setup_logger("netsentinel.plugins.tls_monitor")

# TLS versions considered weak or deprecated
_WEAK_TLS_VERSIONS: frozenset[str] = frozenset({
    "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1",
})

# Known weak cipher keywords
_WEAK_CIPHER_KEYWORDS: frozenset[str] = frozenset({
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon",
})


class TlsMonitorPlugin(BasePlugin):
    """Monitors TLS/SSL sessions and certificates.

    Records SNI, cipher suite and version for every observed TLS
    handshake.  Reports weak cipher usage and outdated TLS versions.
    """

    def __init__(self) -> None:
        super().__init__()
        self._session_count: int = 0
        self._unique_sn_is: set[str] = set()
        self._sni_counts: dict[str, int] = defaultdict(int)
        self._cipher_counts: dict[str, int] = defaultdict(int)
        self._version_counts: dict[str, int] = defaultdict(int)
        self._weak_cipher_count: int = 0
        self._weak_version_count: int = 0
        self._cert_expiring_soon: int = 0
        self._start_time: float = 0.0

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "tls_monitor"

    @property
    def description(self) -> str:
        return "Monitors TLS/SSL sessions and certificates"

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
        self._start_time = time.time()
        logger.info("TlsMonitorPlugin initialised")

    def process_packet(self, packet: dict[str, Any]) -> None:
        """Extract TLS metadata from a packet dict.

        Expected keys (when TLS layer is present):
            ``tls_sni`` – Server Name Indication string
            ``tls_cipher`` – negotiated cipher suite name
            ``tls_version`` – TLS protocol version
            ``cert_not_after`` – certificate expiry ISO timestamp (optional)
        """
        sni = packet.get("tls_sni", "")
        cipher = packet.get("tls_cipher", "")
        version = packet.get("tls_version", "")

        # Only count if at least one TLS field is present
        if not sni and not cipher and not version:
            return

        self._session_count += 1

        if sni:
            sni_lower = str(sni).lower()
            self._unique_sn_is.add(sni_lower)
            self._sni_counts[sni_lower] += 1

        if cipher:
            cipher_str = str(cipher)
            self._cipher_counts[cipher_str] += 1
            if self._is_weak_cipher(cipher_str):
                self._weak_cipher_count += 1
                logger.warning("Weak cipher detected: %s", cipher_str)

        if version:
            version_str = str(version)
            self._version_counts[version_str] += 1
            if version_str in _WEAK_TLS_VERSIONS:
                self._weak_version_count += 1
                logger.warning("Weak TLS version detected: %s", version_str)

        # Certificate expiry check
        not_after = packet.get("cert_not_after", "")
        if not_after:
            if self._is_cert_expiring_soon(str(not_after)):
                self._cert_expiring_soon += 1

    def cleanup(self) -> None:
        logger.info("TlsMonitorPlugin cleaned up")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_weak_cipher(cipher: str) -> bool:
        cipher_upper = cipher.upper()
        return any(kw in cipher_upper for kw in _WEAK_CIPHER_KEYWORDS)

    @staticmethod
    def _is_cert_expiring_soon(not_after: str, days: int = 30) -> bool:
        """Return True if the certificate expires within *days* days."""
        try:
            from datetime import datetime, timezone, timedelta
            expiry = datetime.fromisoformat(not_after)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return expiry <= datetime.now(timezone.utc) + timedelta(days=days)
        except (ValueError, TypeError, OSError):
            return False

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        return {
            "session_count": self._session_count,
            "unique_sn_is": len(self._unique_sn_is),
            "cipher_distribution": dict(
                sorted(self._cipher_counts.items(), key=lambda kv: kv[1], reverse=True)
            ),
            "version_distribution": dict(
                sorted(self._version_counts.items(), key=lambda kv: kv[1], reverse=True)
            ),
            "weak_cipher_count": self._weak_cipher_count,
            "weak_version_count": self._weak_version_count,
            "cert_expiring_soon": self._cert_expiring_soon,
            "top_sn_is": dict(
                sorted(self._sni_counts.items(), key=lambda kv: kv[1], reverse=True)[:20]
            ),
            "uptime_seconds": round(time.time() - self._start_time, 1)
            if self._start_time
            else 0,
        }

    def get_config_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "cert_expiry_days": {
                    "type": "integer",
                    "default": 30,
                    "description": "Days before expiry to flag a certificate",
                },
            },
        }
