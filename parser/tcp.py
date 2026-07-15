"""TCP segment parser for NetSentinel.

Extracts TCP header fields including flags, options, and payload length.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import TCP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.tcp")


class TCPParser:
    """Parse the TCP layer of a scapy packet.

    Usage::

        parser = TCPParser()
        info = parser.parse(packet)
        if info:
            print(info["dst_port"])
    """

    _FLAG_MAP: dict[str, str] = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract TCP segment metadata.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet expected to contain a TCP layer.

        Returns
        -------
        dict | None
            Dictionary with TCP fields or ``None`` when the packet lacks
            a TCP layer or is malformed.
        """
        try:
            tcp_layer = packet[TCP]
            if tcp_layer is None:
                return None
        except IndexError:
            return None

        try:
            flags_str = str(tcp_layer.flags)
            parsed_flags: dict[str, bool] = {}
            for letter, name in self._FLAG_MAP.items():
                parsed_flags[name] = letter in flags_str

            # Parse TCP options
            options: list[str] = []
            if tcp_layer.options:
                for opt in tcp_layer.options:
                    if isinstance(opt, tuple) and len(opt) == 2:
                        name, value = opt
                        options.append(f"{name}={value}")
                    elif isinstance(opt, str):
                        options.append(opt)

            data_length = len(tcp_layer.payload)

            result: dict[str, Any] = {
                "src_port": int(tcp_layer.sport),
                "dst_port": int(tcp_layer.dport),
                "seq": int(tcp_layer.seq),
                "ack": int(tcp_layer.ack),
                "flags": parsed_flags,
                "window": int(tcp_layer.window),
                "options": options,
                "data_length": data_length,
            }
        except Exception:
            logger.debug("Malformed TCP segment, skipping")
            return None

        return result
