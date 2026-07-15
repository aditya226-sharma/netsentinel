"""TLS ClientHello / ServerHello metadata extraction and inspection.

Parses SNI from ClientHello and cipher suite from ServerHello to build
a metadata log of TLS sessions visible on the wire.
"""

from __future__ import annotations

import struct
import threading
import time
from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from database.db_manager import DatabaseManager
from utils.logger import setup_logger
from utils.helpers import generate_id, get_timestamp

logger = setup_logger("netsentinel.modules.certificate_inspector")

_TLS_HANDSHAKE_TYPE: int = 22
_TLS_CLIENT_HELLO: int = 1
_TLS_SERVER_HELLO: int = 2
_TLS_SNI_EXTENSION: int = 0x0000

_CIPHER_SUITE_NAMES: dict[int, str] = {
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

_TLS_VERSION_MAP: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


class CertificateInspector:
    """Extracts TLS handshake metadata from captured traffic.

    Parses ClientHello messages to extract SNI (Server Name Indication)
    and ServerHello messages to extract the selected cipher suite.  Does
    not decrypt payload -- only inspects unencrypted handshake headers.

    Usage:
        inspector = CertificateInspector(db_manager)
        inspector.process_packet(pkt)
        sessions = inspector.get_tls_sessions()
        stats = inspector.get_certificate_stats()
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        self._db = db_manager
        self._lock = threading.Lock()

        self._tls_sessions: dict[str, dict[str, Any]] = {}
        self._recent_sessions: list[dict[str, Any]] = []
        self._max_recent: int = 500
        self._snis: set[str] = set()
        self._issuers: dict[str, int] = {}
        self._cipher_counts: dict[str, int] = {}

    def process_packet(self, packet: Packet) -> None:
        """Inspect a packet for TLS handshake data.

        Only processes TCP packets on port 443 (or other TLS ports)
        whose payload begins with a TLS record header.

        Args:
            packet: Scapy packet to inspect.
        """
        try:
            if not (packet.haslayer(IP) and packet.haslayer(TCP)):
                return

            tcp = packet[TCP]
            if tcp.dport != 443 and tcp.sport != 443:
                return

            payload = bytes(tcp.payload)
            if len(payload) < 6:
                return

            content_type = payload[0]
            if content_type != _TLS_HANDSHAKE_TYPE:
                return

            tls_version = struct.unpack("!H", payload[1:3])[0]
            tls_version_name = _TLS_VERSION_MAP.get(tls_version, f"0x{tls_version:04x}")

            handshake_type = payload[5] if len(payload) > 5 else 0
            handshake_data = payload[6:]

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if handshake_type == _TLS_CLIENT_HELLO:
                self._parse_client_hello(
                    handshake_data, src_ip, dst_ip, tls_version_name, tcp.sport
                )
            elif handshake_type == _TLS_SERVER_HELLO:
                self._parse_server_hello(
                    handshake_data, src_ip, dst_ip, tls_version_name, tcp.dport
                )

        except Exception as exc:
            logger.debug("Error inspecting TLS packet: %s", exc)

    def _parse_client_hello(
        self,
        data: bytes,
        src_ip: str,
        dst_ip: str,
        version: str,
        sport: int,
    ) -> None:
        """Parse a ClientHello handshake for the SNI extension.

        Args:
            data: Handshake payload after the 5-byte header.
            src_ip: Client IP address.
            dst_ip: Server IP address.
            version: TLS version string.
            sport: Client source port.
        """
        try:
            if len(data) < 34:
                return

            sni = self._extract_sni_from_client_hello(data)
            if not sni:
                return

            flow_key = f"{src_ip}:{sport}->{dst_ip}:443"
            timestamp = get_timestamp()

            with self._lock:
                self._snis.add(sni)
                session_record = {
                    "id": generate_id(),
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "sni": sni,
                    "issuer": "",
                    "subject": "",
                    "serial": "",
                    "not_before": "",
                    "not_after": "",
                    "version": version,
                    "cipher": "",
                    "direction": "client_hello",
                }
                self._tls_sessions[flow_key] = session_record
                self._recent_sessions.append(session_record)
                if len(self._recent_sessions) > self._max_recent:
                    self._recent_sessions = self._recent_sessions[-self._max_recent:]

            logger.debug("TLS ClientHello: %s -> %s (SNI: %s)", src_ip, dst_ip, sni)

        except Exception as exc:
            logger.debug("Error parsing ClientHello: %s", exc)

    def _extract_sni_from_client_hello(self, data: bytes) -> str:
        """Extract the SNI hostname from a ClientHello extension block.

        Args:
            data: ClientHello body after the 5-byte handshake header.

        Returns:
            SNI hostname string, or empty string if not found.
        """
        try:
            offset = 0
            if len(data) < 34:
                return ""

            offset = 32  # skip random(32)
            session_id_len = data[offset]
            offset += 1 + session_id_len

            if offset + 2 > len(data):
                return ""
            cipher_suites_len = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2 + cipher_suites_len

            if offset >= len(data):
                return ""
            compression_len = data[offset]
            offset += 1 + compression_len

            if offset + 2 > len(data):
                return ""
            extensions_len = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2

            ext_end = offset + extensions_len
            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type = struct.unpack("!H", data[offset:offset + 2])[0]
                ext_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                offset += 4

                if ext_type == _TLS_SNI_EXTENSION:
                    return self._parse_sni_extension(data[offset:offset + ext_len])

                offset += ext_len

        except Exception:
            pass
        return ""

    def _parse_sni_extension(self, data: bytes) -> str:
        """Parse the SNI extension value to extract the hostname.

        Args:
            data: Raw SNI extension data.

        Returns:
            Hostname string.
        """
        try:
            if len(data) < 5:
                return ""

            sni_list_len = struct.unpack("!H", data[0:2])[0]
            name_type = data[2]
            name_len = struct.unpack("!H", data[3:5])[0]

            if name_type == 0 and len(data) >= 5 + name_len:
                return data[5:5 + name_len].decode("ascii", errors="replace")

        except Exception:
            pass
        return ""

    def _parse_server_hello(
        self,
        data: bytes,
        src_ip: str,
        dst_ip: str,
        version: str,
        dport: int,
    ) -> None:
        """Parse a ServerHello handshake for the selected cipher suite.

        Args:
            data: Handshake payload after the 5-byte header.
            src_ip: Server IP address.
            dst_ip: Client IP address.
            version: TLS version string.
            dport: Server destination port (the client's sport).
        """
        try:
            if len(data) < 38:
                return

            offset = 32  # skip random(32)
            session_id_len = data[offset]
            offset += 1 + session_id_len

            if offset + 2 > len(data):
                return ""

            cipher_suite_raw = struct.unpack("!H", data[offset:offset + 2])[0]
            cipher_name = _CIPHER_SUITE_NAMES.get(
                cipher_suite_raw, f"UNKNOWN(0x{cipher_suite_raw:04x})"
            )

            client_ip = dst_ip
            flow_key = f"{client_ip}:{dport}->{src_ip}:443"

            with self._lock:
                self._cipher_counts[cipher_name] = self._cipher_counts.get(cipher_name, 0) + 1

                existing = self._tls_sessions.get(flow_key)
                if existing:
                    existing["cipher"] = cipher_name
                    existing["direction"] = "server_hello"
                else:
                    session_record = {
                        "id": generate_id(),
                        "timestamp": get_timestamp(),
                        "src_ip": src_ip,
                        "dst_ip": client_ip,
                        "sni": "",
                        "issuer": "",
                        "subject": "",
                        "serial": "",
                        "not_before": "",
                        "not_after": "",
                        "version": version,
                        "cipher": cipher_name,
                        "direction": "server_hello",
                    }
                    self._tls_sessions[flow_key] = session_record
                    self._recent_sessions.append(session_record)
                    if len(self._recent_sessions) > self._max_recent:
                        self._recent_sessions = self._recent_sessions[-self._max_recent:]

            logger.debug(
                "TLS ServerHello: %s -> %s (cipher: %s)",
                src_ip, client_ip, cipher_name,
            )

        except Exception as exc:
            logger.debug("Error parsing ServerHello: %s", exc)

    def get_tls_sessions(self) -> list[dict[str, Any]]:
        """Return all observed TLS sessions.

        Returns:
            List of TLS session dictionaries.
        """
        with self._lock:
            return list(self._tls_sessions.values())

    def get_certificate_stats(self) -> dict[str, Any]:
        """Return aggregate TLS statistics.

        Returns:
            Dictionary with keys:
            ``unique_snis``, ``unique_issuers``, ``cipher_distribution``,
            ``total_sessions``.
        """
        with self._lock:
            return {
                "unique_snis": len(self._snis),
                "unique_issuers": len(self._issuers),
                "cipher_distribution": dict(self._cipher_counts),
                "total_sessions": len(self._tls_sessions),
            }

    def get_expired_certificates(self) -> list[dict[str, Any]]:
        """Return TLS sessions whose certificates are expired.

        Since we cannot extract certificate details from unencrypted
        ServerHello data, this returns an empty list.  A full TLS proxy
        or certificate transparency log integration would populate this.

        Returns:
            Empty list (placeholder for future implementation).
        """
        return []

    def get_certificate_by_sni(self, sni: str) -> dict[str, Any] | None:
        """Look up a TLS session by its SNI.

        Args:
            sni: Server Name Indication to search for.

        Returns:
            The first matching TLS session dictionary, or ``None``.
        """
        target = sni.lower()
        with self._lock:
            for session in self._tls_sessions.values():
                if session.get("sni", "").lower() == target:
                    return session
        return None
