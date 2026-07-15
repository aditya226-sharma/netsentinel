"""UDP datagram parser for NetSentinel.

Extracts UDP header fields from a scapy packet.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import UDP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.udp")


class UDPParser:
    """Parse the UDP layer of a scapy packet.

    Usage::

        parser = UDPParser()
        info = parser.parse(packet)
        if info:
            print(info["src_port"])
    """

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract UDP datagram metadata.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet expected to contain a UDP layer.

        Returns
        -------
        dict | None
            Dictionary with UDP fields or ``None`` when the packet lacks
            a UDP layer or is malformed.
        """
        try:
            udp_layer = packet[UDP]
            if udp_layer is None:
                return None
        except IndexError:
            return None

        try:
            result: dict[str, Any] = {
                "src_port": int(udp_layer.sport),
                "dst_port": int(udp_layer.dport),
                "length": int(udp_layer.len),
            }
        except Exception:
            logger.debug("Malformed UDP datagram, skipping")
            return None

        return result
