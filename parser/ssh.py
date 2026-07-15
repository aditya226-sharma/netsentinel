"""SSH banner parser for NetSentinel.

Inspects TCP payloads for the SSH protocol version exchange banner
(e.g. ``SSH-2.0-OpenSSH_9.6``) and extracts version strings.
"""

from __future__ import annotations

import re
from typing import Any

from scapy.layers.inet import TCP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.ssh")

# SSH-2.0-OpenSSH_9.6  or  SSH-1.99-OpenSSH_9.6
_SSH_BANNER_RE = re.compile(rb"^(SSH-[\d.]+-\S+)")


class SSHParser:
    """Parse an SSH banner from a TCP payload.

    Usage::

        parser = SSHParser()
        info = parser.parse(packet)
        if info:
            print(info["version_string"])
    """

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract SSH banner metadata from a TCP packet.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet expected to contain a TCP payload.

        Returns
        -------
        dict | None
            Dictionary with SSH fields or ``None`` when the payload does
            not begin with a valid SSH banner.
        """
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(bytes):
                return None

            raw_payload: bytes = bytes(packet[TCP].payload)
            if len(raw_payload) < 8:
                return None

            # Read just the first line (max 255 bytes per RFC 4253)
            first_line_end = raw_payload.find(b"\n")
            if first_line_end == -1:
                first_line_end = min(len(raw_payload), 255)

            first_line = raw_payload[:first_line_end].rstrip(b"\r")

            banner_match = _SSH_BANNER_RE.match(first_line)
            if not banner_match:
                return None

            version_string = banner_match.group(1).decode(
                "ascii", errors="replace"
            )

            # Split into protocol version and software version
            parts = version_string.split("-", 2)
            protocol_version = parts[1] if len(parts) > 1 else ""
            software_version = parts[2] if len(parts) > 2 else ""

            result: dict[str, Any] = {
                "version_string": version_string,
                "protocol_version": protocol_version,
                "software_version": software_version,
            }

        except Exception:
            logger.debug("Error parsing SSH banner, skipping")
            return None

        return result
