"""IPv4 packet parser for NetSentinel.

Extracts key IPv4 header fields from a scapy packet.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import IP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.ipv4")


class IPv4Parser:
    """Parse the IPv4 layer of a scapy packet.

    Usage::

        parser = IPv4Parser()
        info = parser.parse(packet)
        if info:
            print(info["src_ip"])
    """

    _FLAG_NAMES: dict[int, str] = {
        0x0200: "DF",
        0x0100: "MF",
    }

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract IPv4 header metadata.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet that is expected to contain an IP layer.

        Returns
        -------
        dict | None
            A dictionary with IPv4 fields or ``None`` when the packet does
            not contain an IP layer or cannot be parsed.
        """
        try:
            ip_layer = packet[IP]
            if ip_layer is None:
                return None
        except IndexError:
            return None

        try:
            flags_int = int(ip_layer.flags)
            flag_names = []
            for bit, name in self._FLAG_NAMES.items():
                if flags_int & bit:
                    flag_names.append(name)
        except Exception:
            flag_names = []

        try:
            result: dict[str, Any] = {
                "src_ip": str(ip_layer.src),
                "dst_ip": str(ip_layer.dst),
                "version": int(ip_layer.version),
                "ihl": int(ip_layer.ihl),
                "ttl": int(ip_layer.ttl),
                "protocol": int(ip_layer.proto),
                "total_length": int(ip_layer.len),
                "flags": ",".join(flag_names) if flag_names else "",
                "fragment_offset": int(ip_layer.frag),
            }
        except Exception:
            logger.debug("Malformed IPv4 packet, skipping")
            return None

        return result
