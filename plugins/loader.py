"""Dynamic plugin loader for NetSentinel.

Discovers, imports, validates and manages plugin modules at runtime using
``importlib``.  Every loaded plugin must subclass :class:`BasePlugin`.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Any

from database.db_manager import DatabaseManager
from plugins.base import BasePlugin
from utils.logger import setup_logger

logger = setup_logger("netsentinel.plugin_loader")


class PluginLoader:
    """Discovers and manages the lifecycle of NetSentinel plugins.

    Args:
        plugins_dir: Filesystem path to the directory containing plugin
            modules.
        db_manager: Shared ``DatabaseManager`` passed to every plugin.
    """

    def __init__(self, plugins_dir: str | Path, db_manager: DatabaseManager) -> None:
        self._plugins_dir = Path(plugins_dir).resolve()
        self._db = db_manager
        self._loaded: dict[str, BasePlugin] = {}

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover_plugins(self) -> list[str]:
        """Scan the plugins directory and return available plugin names.

        A valid plugin module must:
        * Be a ``.py`` file (not ``__init__.py`` or ``base.py``).
        * Contain at least one class that is a direct subclass of
          :class:`BasePlugin`.

        Returns:
            Sorted list of discovered plugin names (module stems).
        """
        if not self._plugins_dir.is_dir():
            logger.warning("Plugins directory does not exist: %s", self._plugins_dir)
            return []

        excluded = {"__init__", "base", "loader"}
        names: list[str] = []

        for path in sorted(self._plugins_dir.glob("*.py")):
            stem = path.stem
            if stem in excluded:
                continue
            names.append(stem)

        logger.debug("Discovered %d plugin(s): %s", len(names), names)
        return names

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_plugin(self, plugin_name: str) -> BasePlugin:
        """Dynamically import a plugin module and return its primary instance.

        The module must define exactly one concrete :class:`BasePlugin`
        subclass.  An instance is created and its lifecycle hooks are
        invoked.

        Args:
            plugin_name: Name of the plugin module (without ``.py``).

        Returns:
            Instantiated and initialised :class:`BasePlugin`.

        Raises:
            ImportError: If the module cannot be found or imported.
            TypeError: If the module does not contain a valid plugin class.
        """
        if plugin_name in self._loaded:
            logger.debug("Plugin '%s' already loaded", plugin_name)
            return self._loaded[plugin_name]

        module_path = self._plugins_dir / f"{plugin_name}.py"
        if not module_path.exists():
            raise ImportError(
                f"Plugin module not found: {module_path}"
            )

        spec = importlib.util.spec_from_file_location(
            f"netsentinel.plugins.{plugin_name}",
            str(module_path),
        )
        if spec is None or spec.loader is None:
            raise ImportError(
                f"Cannot create module spec for {module_path}"
            )

        module = importlib.util.module_from_spec(spec)
        # Temporarily register so the module can import sibling modules
        sys.modules[module.__name__] = module

        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as exc:
            sys.modules.pop(module.__name__, None)
            logger.error("Failed to import plugin '%s': %s", plugin_name, exc)
            raise ImportError(
                f"Failed to import plugin '{plugin_name}': {exc}"
            ) from exc

        plugin_class = self._find_plugin_class(module, plugin_name)
        instance = self._instantiate(plugin_class, plugin_name)

        # Store before calling lifecycle hooks so the reference exists
        self._loaded[plugin_name] = instance

        try:
            instance.on_load()
            instance.initialize()
        except Exception as exc:
            logger.error(
                "Plugin '%s' failed during initialisation: %s",
                plugin_name,
                exc,
            )
            self._loaded.pop(plugin_name, None)
            raise

        logger.info(
            "Loaded plugin: %s v%s by %s",
            instance.name,
            instance.version,
            instance.author,
        )
        return instance

    def load_all_plugins(self) -> dict[str, BasePlugin]:
        """Discover and load every available plugin.

        Errors for individual plugins are logged and skipped so that one
        broken plugin does not prevent others from loading.

        Returns:
            Mapping of plugin name to its :class:`BasePlugin` instance.
        """
        for name in self.discover_plugins():
            if name in self._loaded:
                continue
            try:
                self.load_plugin(name)
            except Exception:
                # load_plugin already logs the error
                pass

        return dict(self._loaded)

    # ------------------------------------------------------------------
    # Unloading
    # ------------------------------------------------------------------

    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a single plugin, calling its cleanup hooks.

        Args:
            plugin_name: Name of the plugin to unload.

        Returns:
            ``True`` if the plugin was unloaded, ``False`` if not found.
        """
        plugin = self._loaded.pop(plugin_name, None)
        if plugin is None:
            logger.warning("Cannot unload unknown plugin: %s", plugin_name)
            return False

        try:
            plugin.cleanup()
            plugin.on_unload()
        except Exception as exc:
            logger.error(
                "Error during plugin '%s' unload: %s", plugin_name, exc
            )

        # Remove from sys.modules as well
        module_name = f"netsentinel.plugins.{plugin_name}"
        sys.modules.pop(module_name, None)

        logger.info("Unloaded plugin: %s", plugin_name)
        return True

    def unload_all(self) -> None:
        """Unload every currently loaded plugin."""
        for name in list(self._loaded):
            self.unload_plugin(name)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_plugin(self, plugin_name: str) -> BasePlugin | None:
        """Return a loaded plugin by name, or ``None``."""
        return self._loaded.get(plugin_name)

    def get_loaded_plugins(self) -> dict[str, BasePlugin]:
        """Return a shallow copy of the loaded-plugins mapping."""
        return dict(self._loaded)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _find_plugin_class(module: Any, plugin_name: str) -> type[BasePlugin]:
        """Locate the first concrete ``BasePlugin`` subclass in *module*."""
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BasePlugin)
                and obj is not BasePlugin
            ):
                return obj  # type: ignore[return-value]

        raise TypeError(
            f"Plugin module '{plugin_name}' does not contain a "
            f"class that inherits from BasePlugin"
        )

    @staticmethod
    def _instantiate(cls: type[BasePlugin], plugin_name: str) -> BasePlugin:
        """Create an instance of a plugin class, handling init errors."""
        try:
            return cls()
        except Exception as exc:
            raise TypeError(
                f"Cannot instantiate plugin class {cls.__name__!r} "
                f"from '{plugin_name}': {exc}"
            ) from exc
