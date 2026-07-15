"""Abstract base class for all NetSentinel plugins."""

from __future__ import annotations

import abc
from typing import Any


class BasePlugin(abc.ABC):
    """Abstract base class that every NetSentinel plugin must inherit from.

    Plugins are discovered, loaded and managed by ``PluginLoader``.  Each
    concrete subclass must provide the required metadata properties and
    implement the three lifecycle methods: ``initialize``, ``process_packet``
    and ``cleanup``.

    Lifecycle
    ---------
    1. ``on_load()``  – called right after import.
    2. ``initialize()`` – set up resources (threads, sockets, state …).
    3. ``process_packet(packet)`` – invoked for every captured packet.
    4. ``cleanup()`` – tear down resources.
    5. ``on_unload()`` – called just before the plugin reference is dropped.
    """

    def __init__(self) -> None:
        self._enabled: bool = True

    # ------------------------------------------------------------------
    # Required metadata (override in subclass)
    # ------------------------------------------------------------------

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Short, unique identifier for the plugin (e.g. ``dns_monitor``)."""

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """One-line human-readable description."""

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Semantic version string (e.g. ``"1.0.0"``)."""

    @property
    @abc.abstractmethod
    def author(self) -> str:
        """Plugin author name."""

    # ------------------------------------------------------------------
    # Enabled flag
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Whether the plugin is currently active."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = bool(value)

    # ------------------------------------------------------------------
    # Required lifecycle methods
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def initialize(self) -> None:
        """Set up any resources the plugin needs.

        Called once after the plugin has been loaded.
        """

    @abc.abstractmethod
    def process_packet(self, packet: dict[str, Any]) -> None:
        """Process a single captured packet.

        Args:
            packet: Parsed packet data as a dictionary.
        """

    @abc.abstractmethod
    def cleanup(self) -> None:
        """Release resources held by the plugin.

        Called once when the plugin is about to be unloaded.
        """

    # ------------------------------------------------------------------
    # Optional overrides
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return plugin-specific statistics.

        Subclasses should override this to expose useful counters / gauges.

        Returns:
            Dictionary of statistic name to value.
        """
        return {}

    def get_config_schema(self) -> dict[str, Any] | None:
        """Return a JSON-Schema-like dict describing the plugin's config.

        Returns:
            Schema dictionary or ``None`` if the plugin has no configuration.
        """
        return None

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    def on_load(self) -> None:
        """Hook called immediately after the plugin module is imported.

        Override to perform lightweight tasks that must happen before
        ``initialize()``.
        """

    def on_unload(self) -> None:
        """Hook called just before the plugin instance is discarded.

        Override to perform final bookkeeping after ``cleanup()``.
        """
