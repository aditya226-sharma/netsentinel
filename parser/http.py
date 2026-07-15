"""HTTP metadata parser for NetSentinel.

Inspects TCP payloads for HTTP request/response patterns and extracts
method, URI, Host, User-Agent, status codes, etc.  This parser is
lightweight – it does not perform full HTTP parsing.
"""

from __future__ import annotations

import re
from typing import Any

from scapy.layers.inet import TCP
from scapy.packet import Packet

from utils.logger import setup_logger

logger = setup_logger("netsentinel.parser.http")

# Well-known HTTP methods
_HTTP_METHODS = frozenset({
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT",
})

_REQUEST_LINE_RE = re.compile(
    rb"^(GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/\d\.\d"
)
_RESPONSE_LINE_RE = re.compile(rb"^HTTP/\d\.\d\s+(\d{3})")

_HEADER_RE = re.compile(rb"^([A-Za-z0-9\-]+):\s*(.+)$")


class HTTPParser:
    """Parse an HTTP request or response from a TCP payload.

    Usage::

        parser = HTTPParser()
        info = parser.parse(packet)
        if info:
            print(info["method"])
    """

    def parse(self, packet: Packet) -> dict[str, Any] | None:
        """Extract HTTP metadata from a TCP packet.

        Parameters
        ----------
        packet : scapy.packet.Packet
            A raw scapy packet expected to contain TCP + payload.

        Returns
        -------
        dict | None
            Dictionary with HTTP metadata or ``None`` when the payload
            does not look like valid HTTP.
        """
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(bytes):
                return None

            raw_payload: bytes = bytes(packet[TCP].payload)
            if len(raw_payload) < 10:
                return None

            # Quick heuristic: must start with "HTTP/" or an HTTP method
            first_line_end = raw_payload.find(b"\r\n")
            if first_line_end == -1:
                return None

            first_line = raw_payload[:first_line_end]

            is_request = False
            is_response = False
            method = ""
            uri = ""
            status_code = 0

            req_match = _REQUEST_LINE_RE.match(first_line)
            if req_match:
                is_request = True
                method = req_match.group(1).decode("ascii", errors="replace")
                uri = req_match.group(2).decode("ascii", errors="replace")
            else:
                resp_match = _RESPONSE_LINE_RE.match(first_line)
                if resp_match:
                    is_response = True
                    status_code = int(resp_match.group(1))
                else:
                    return None

            # Parse headers up to a reasonable limit
            headers: dict[str, str] = {}
            offset = first_line_end + 2
            max_scan = min(len(raw_payload), 8192)
            empty_line_pos = -1

            while offset < max_scan:
                line_end = raw_payload.find(b"\r\n", offset)
                if line_end == -1:
                    break

                line = raw_payload[offset:line_end]
                if not line:
                    empty_line_pos = line_end
                    break

                header_match = _HEADER_RE.match(line)
                if header_match:
                    hname = header_match.group(1).decode("ascii", errors="replace").lower()
                    hval = header_match.group(2).decode("utf-8", errors="replace").strip()
                    headers[hname] = hval

                offset = line_end + 2

            content_length = 0
            cl_header = headers.get("content-length")
            if cl_header is not None:
                try:
                    content_length = int(cl_header)
                except ValueError:
                    content_length = 0

            result: dict[str, Any] = {
                "method": method,
                "uri": uri,
                "status_code": status_code,
                "host": headers.get("host", ""),
                "user_agent": headers.get("user-agent", ""),
                "content_type": headers.get("content-type", ""),
                "content_length": content_length,
                "is_request": is_request,
                "is_response": is_response,
            }

        except Exception:
            logger.debug("Error parsing HTTP payload, skipping")
            return None

        return result
