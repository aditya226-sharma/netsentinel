"""TLS record and ClientHello parser for NetSentinel.

Parses the outer TLS record header and, when the record contains a
ClientHello handshake, extracts SNI, supported versions, and cipher
suites.
"""

from __future__ import annotations

import struct
from typing import Any

from scapy.layers.inet import TCP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.tls")

_TLS_VERSIONS: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

_TLS_RECORD_TYPES: dict[int, str] = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "ApplicationData",
    255: "Heartbeat",
}

_HANDSHAKE_TYPES: dict[int, str] = {
    0: "HelloRequest",
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    14: "ServerHelloDone",
    16: "ClientKeyExchange",
}

_COMMON_CIPHER_SUITES: dict[int, str] = {
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

# ClientHello minimum size (2 bytes version + 32 bytes random + 1 byte session id len)
_CLIENT_HELLO_MIN = 35


class TLSParser:
    """Parse the TLS record layer and ClientHello from a TCP packet.

    Usage::

        parser = TLSParser()
        info = parser.parse(packet)
        if info and info.get("sni"):
            print(info["sni"])
    """

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract TLS metadata from a TCP packet.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet expected to contain a TCP payload.

        Returns
        -------
        dict | None
            Dictionary with TLS fields or ``None`` when the payload does
            not start with a valid TLS record.
        """
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(bytes):
                return None

            raw_payload: bytes = bytes(packet[TCP].payload)
            if len(raw_payload) < 5:
                return None

            # Parse TLS record header: type (1), version (2), length (2)
            record_type = raw_payload[0]
            record_version = struct.unpack("!H", raw_payload[1:3])[0]
            record_length = struct.unpack("!H", raw_payload[3:5])[0]

            if record_type not in _TLS_RECORD_TYPES:
                return None

            result: dict[str, Any] = {
                "record_type": _TLS_RECORD_TYPES.get(record_type, f"UNKNOWN({record_type})"),
                "version": _TLS_VERSIONS.get(record_version, f"0x{record_version:04X}"),
                "version_raw": record_version,
                "record_length": record_length,
                "sni": "",
                "cipher_suite": "",
                "cipher_suite_name": "",
                "extensions": [],
                "handshake_type": "",
            }

            # Try to parse the handshake message inside the record
            if record_type == 22 and len(raw_payload) >= 6:
                result.update(self._parse_handshake(raw_payload[5:]))

        except Exception:
            logger.debug("Error parsing TLS record, skipping")
            return None

        return result

    def _parse_handshake(self, data: bytes) -> dict[str, Any]:
        """Parse a TLS handshake message body.

        Parameters
        ----------
        data : bytes
            The payload following the 5-byte TLS record header.

        Returns
        -------
        dict
            Partial result dict with handshake-specific fields.
        """
        if len(data) < 4:
            return {}

        hs_type = data[0]
        hs_length = (data[1] << 16) | (data[2] << 8) | data[3]
        result: dict[str, Any] = {
            "handshake_type": _HANDSHAKE_TYPES.get(
                hs_type, f"UNKNOWN({hs_type})"
            ),
        }

        if hs_type != 1:  # Not ClientHello
            return result

        body = data[4:]
        if len(body) < _CLIENT_HELLO_MIN:
            return result

        # ClientHello body: version(2) + random(32) + session_id_len(1) + ...
        offset = 2 + 32  # skip version + random
        if offset >= len(body):
            return result

        session_id_len = body[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(body):
            return result

        # Cipher suites
        cipher_suites_len = struct.unpack("!H", body[offset : offset + 2])[0]
        offset += 2

        first_cipher = 0
        if cipher_suites_len >= 2:
            first_cipher = struct.unpack("!H", body[offset : offset + 2])[0]
            result["cipher_suite"] = f"0x{first_cipher:04X}"
            result["cipher_suite_name"] = _COMMON_CIPHER_SUITES.get(
                first_cipher, "UNKNOWN"
            )

        offset += cipher_suites_len
        if offset >= len(body):
            return result

        # Compression methods
        comp_len = body[offset]
        offset += 1 + comp_len
        if offset + 2 > len(body):
            return result

        # Extensions
        ext_total_len = struct.unpack("!H", body[offset : offset + 2])[0]
        offset += 2
        ext_end = min(offset + ext_total_len, len(body))

        extensions: list[dict[str, Any]] = []
        sni = ""

        while offset + 4 <= ext_end:
            ext_type = struct.unpack("!H", body[offset : offset + 2])[0]
            ext_len = struct.unpack("!H", body[offset + 2 : offset + 4])[0]
            offset += 4
            ext_data = body[offset : offset + ext_len]
            offset += ext_len

            ext_info: dict[str, Any] = {"type": f"0x{ext_type:04X}"}

            # SNI extension (type 0x0000)
            if ext_type == 0x0000 and len(ext_data) >= 5:
                name_list_len = struct.unpack("!H", ext_data[1:3])[0]
                if len(ext_data) >= 5:
                    name_type = ext_data[3]
                    name_len = struct.unpack("!H", ext_data[4:6])[0] if len(ext_data) >= 6 else 0
                    if name_type == 0 and name_len > 0:
                        sni = ext_data[6 : 6 + name_len].decode(
                            "ascii", errors="replace"
                        )
                        ext_info["name"] = sni

            extensions.append(ext_info)

        result["sni"] = sni
        result["extensions"] = extensions
        return result
