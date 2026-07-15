"""Packet capture engine for NetSentinel.

Wraps scapy's sniff facility in a thread-safe, controllable capture
loop that feeds raw packets to an optional callback for downstream
processing.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from scapy.all import IP, IPv6, Raw, sniff  # noqa: F401 – side-effect imports
from scapy.packet import Packet

from utils.logger import setup_logger
from utils.helpers import get_timestamp

logger = setup_logger("netsentinel.capture.engine")


class PacketCaptureEngine:
    """Thread-safe packet capture engine built on top of scapy.

    Parameters
    ----------
    interface : str | None
        Network interface to sniff on.  When *None* scapy auto-detects.
    bpf_filter : str | None
        Optional BPF (Berkeley Packet Filter) expression.
    packet_callback : callable | None
        Invoked for every captured packet with the raw scapy
        :class:`~scapy.packet.Packet` as its sole argument.
    db_manager : Any | None
        Optional :class:`~database.db_manager.DatabaseManager` instance.
        Currently unused by the engine itself but reserved for future
        direct-insert paths.
    """

    def __init__(
        self,
        interface: str | None = None,
        bpf_filter: str | None = None,
        packet_callback: Callable[[Packet], Any] | None = None,
        db_manager: Any | None = None,
    ) -> None:
        self._interface: str | None = interface or None
        self._bpf_filter: str | None = bpf_filter or None
        self._callback = packet_callback
        self._db_manager = db_manager

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        # Statistics
        self._packets_captured: int = 0
        self._bytes_captured: int = 0
        self._start_time: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start packet capture in a background daemon thread.

        Raises:
            RuntimeError: If capture is already running.
        """
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("Capture is already running")

            self._stop_event.clear()
            self._packets_captured = 0
            self._bytes_captured = 0
            self._start_time = time.monotonic()

            self._thread = threading.Thread(
                target=self._capture_loop,
                name="netsentinel-capture",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "Capture started on interface=%s bpf=%s",
                self._interface or "<auto>",
                self._bpf_filter or "<none>",
            )

    def stop(self) -> None:
        """Stop packet capture gracefully and wait for the thread to finish."""
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                logger.debug("Capture is not running, nothing to stop")
                return
            self._stop_event.set()

        self._thread.join(timeout=10.0)
        with self._lock:
            if self._thread and self._thread.is_alive():
                logger.warning("Capture thread did not stop within timeout")
            else:
                logger.info("Capture stopped")
            self._thread = None

    def is_running(self) -> bool:
        """Return ``True`` if the capture thread is currently active."""
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def get_stats(self) -> dict[str, Any]:
        """Return capture statistics.

        Returns
        -------
        dict
            Keys: ``packets_captured``, ``bytes_captured``, ``uptime``.
        """
        with self._lock:
            uptime = time.monotonic() - self._start_time if self._start_time else 0.0
            return {
                "packets_captured": self._packets_captured,
                "bytes_captured": self._bytes_captured,
                "uptime": uptime,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _capture_loop(self) -> None:
        """Main capture loop executed in the daemon thread."""
        try:
            logger.debug("Entering capture loop")
            sniff(
                iface=self._interface,
                filter=self._bpf_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            logger.critical(
                "Permission denied – capture requires root / admin privileges"
            )
        except OSError as exc:
            if self._stop_event.is_set():
                logger.debug("Capture loop interrupted by stop event")
            else:
                logger.critical("OS error during capture: %s", exc)
        except Exception as exc:
            if self._stop_event.is_set():
                logger.debug("Capture loop interrupted by stop event")
            else:
                logger.exception("Unexpected error in capture loop: %s", exc)
        finally:
            logger.debug("Capture loop exited")

    def _process_packet(self, packet: Packet) -> None:
        """Process a single captured packet.

        Updates internal statistics and invokes the user-supplied
        callback when one is registered.

        Parameters
        ----------
        packet : scapy.packet.Packet
            The raw captured packet.
        """
        try:
            pkt_len = len(packet)
        except Exception:
            pkt_len = 0

        with self._lock:
            self._packets_captured += 1
            self._bytes_captured += pkt_len

        if self._callback is not None:
            try:
                self._callback(packet)
            except Exception:
                logger.exception(
                    "Error in packet callback for packet index %d",
                    self._packets_captured,
                )
