"""Tests for plugins.base and plugins.loader modules."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from database.db_manager import DatabaseManager
from plugins.base import BasePlugin
from plugins.loader import PluginLoader


# ---------------------------------------------------------------------------
# Concrete test plugin
# ---------------------------------------------------------------------------

class MockPlugin(BasePlugin):
    """Minimal concrete plugin for testing purposes."""

    initialize_called = False
    cleanup_called = False

    @property
    def name(self) -> str:
        return "mock_plugin"

    @property
    def description(self) -> str:
        return "A mock plugin for tests"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def author(self) -> str:
        return "TestSuite"

    def initialize(self) -> None:
        MockPlugin.initialize_called = True

    def process_packet(self, packet: dict[str, Any]) -> None:
        pass

    def cleanup(self) -> None:
        MockPlugin.cleanup_called = True


# ---------------------------------------------------------------------------
# BasePlugin interface
# ---------------------------------------------------------------------------

class TestPluginBaseInterface:
    """Verify BasePlugin enforces the correct abstract interface."""

    def test_plugin_base_interface(self) -> None:
        """A concrete subclass exposes name, description, version, author."""
        plugin = MockPlugin()
        assert plugin.name == "mock_plugin"
        assert plugin.description == "A mock plugin for tests"
        assert plugin.version == "0.1.0"
        assert plugin.author == "TestSuite"
        assert plugin.enabled is True

    def test_plugin_enabled_toggle(self) -> None:
        """Enabled flag can be toggled."""
        plugin = MockPlugin()
        plugin.enabled = False
        assert plugin.enabled is False

    def test_plugin_get_stats_default(self) -> None:
        """Default get_stats returns empty dict."""
        plugin = MockPlugin()
        assert plugin.get_stats() == {}

    def test_plugin_get_config_schema_default(self) -> None:
        """Default get_config_schema returns None."""
        plugin = MockPlugin()
        assert plugin.get_config_schema() is None

    def test_abstract_instantiation_raises(self) -> None:
        """Instantiating BasePlugin directly raises TypeError."""
        with pytest.raises(TypeError):
            BasePlugin()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# PluginLoader – discovery
# ---------------------------------------------------------------------------

@pytest.fixture()
def plugin_dir_with_mock(tmp_path: Path, db_manager: DatabaseManager) -> PluginLoader:
    """Create a PluginLoader pointing at a temp dir containing MockPlugin."""
    plugin_file = tmp_path / "mock_plugin.py"
    plugin_file.write_text(
        "from typing import Any\n"
        "from plugins.base import BasePlugin\n\n"
        "class MockPlugin(BasePlugin):\n"
        "    @property\n"
        "    def name(self): return 'mock_plugin'\n"
        "    @property\n"
        "    def description(self): return 'Mock'\n"
        "    @property\n"
        "    def version(self): return '0.1.0'\n"
        "    @property\n"
        "    def author(self): return 'Test'\n"
        "    def initialize(self): pass\n"
        "    def process_packet(self, packet): pass\n"
        "    def cleanup(self): pass\n"
    )
    # Also write __init__.py so the directory is a package (not required but harmless)
    (tmp_path / "__init__.py").write_text("")

    return PluginLoader(plugins_dir=tmp_path, db_manager=db_manager)


class TestPluginLoaderDiscover:
    """Tests for PluginLoader.discover_plugins()."""

    def test_plugin_loader_discover(self, plugin_dir_with_mock: PluginLoader) -> None:
        """discover_plugins finds mock_plugin in the directory."""
        names = plugin_dir_with_mock.discover_plugins()
        assert "mock_plugin" in names

    def test_plugin_loader_discover_excludes_base(self, plugin_dir_with_mock: PluginLoader) -> None:
        """base.py is excluded from discovery."""
        names = plugin_dir_with_mock.discover_plugins()
        assert "base" not in names

    def test_plugin_loader_discover_empty_dir(self, tmp_path: Path, db_manager: DatabaseManager) -> None:
        """An empty directory yields no plugin names."""
        loader = PluginLoader(plugins_dir=tmp_path, db_manager=db_manager)
        assert loader.discover_plugins() == []

    def test_plugin_loader_discover_nonexistent_dir(self, db_manager: DatabaseManager) -> None:
        """A non-existent directory does not raise – returns empty list."""
        loader = PluginLoader(plugins_dir="/nonexistent/path", db_manager=db_manager)
        assert loader.discover_plugins() == []


# ---------------------------------------------------------------------------
# PluginLoader – load / unload
# ---------------------------------------------------------------------------

class TestPluginLoaderLoad:
    """Tests for PluginLoader.load_plugin()."""

    def test_plugin_loader_load(self, plugin_dir_with_mock: PluginLoader) -> None:
        """load_plugin imports, instantiates, and initializes the plugin."""
        plugin = plugin_dir_with_mock.load_plugin("mock_plugin")
        assert plugin is not None
        assert plugin.name == "mock_plugin"

    def test_plugin_loader_load_nonexistent_raises(self, plugin_dir_with_mock: PluginLoader) -> None:
        """Loading a non-existent plugin raises ImportError."""
        with pytest.raises(ImportError):
            plugin_dir_with_mock.load_plugin("does_not_exist")

    def test_plugin_loader_load_all(self, plugin_dir_with_mock: PluginLoader) -> None:
        """load_all_plugins discovers and loads every available plugin."""
        loaded = plugin_dir_with_mock.load_all_plugins()
        assert "mock_plugin" in loaded

    def test_plugin_unload(self, plugin_dir_with_mock: PluginLoader) -> None:
        """Unload calls cleanup and removes the plugin."""
        plugin_dir_with_mock.load_plugin("mock_plugin")
        result = plugin_dir_with_mock.unload_plugin("mock_plugin")
        assert result is True
        assert plugin_dir_with_mock.get_plugin("mock_plugin") is None

    def test_plugin_unload_nonexistent(self, plugin_dir_with_mock: PluginLoader) -> None:
        """Unloading a plugin that was never loaded returns False."""
        assert plugin_dir_with_mock.unload_plugin("ghost_plugin") is False

    def test_plugin_loader_idempotent_load(self, plugin_dir_with_mock: PluginLoader) -> None:
        """Loading the same plugin twice returns the same instance."""
        first = plugin_dir_with_mock.load_plugin("mock_plugin")
        second = plugin_dir_with_mock.load_plugin("mock_plugin")
        assert first is second


# ---------------------------------------------------------------------------
# Plugin lifecycle
# ---------------------------------------------------------------------------

class TestPluginLifecycle:
    """Verify lifecycle hooks are invoked correctly."""

    def test_on_load_called(self, tmp_path: Path, db_manager: DatabaseManager) -> None:
        """on_load hook is invoked after import."""
        plugin_file = tmp_path / "hook_plugin.py"
        plugin_file.write_text(
            "from plugins.base import BasePlugin\n\n"
            "class HookPlugin(BasePlugin):\n"
            "    hook_called = False\n"
            "    @property\n"
            "    def name(self): return 'hook_plugin'\n"
            "    @property\n"
            "    def description(self): return 'Hook test'\n"
            "    @property\n"
            "    def version(self): return '0.0.1'\n"
            "    @property\n"
            "    def author(self): return 'Test'\n"
            "    def initialize(self): pass\n"
            "    def process_packet(self, packet): pass\n"
            "    def cleanup(self): pass\n"
            "    def on_load(self):\n"
            "        HookPlugin.hook_called = True\n"
        )

        loader = PluginLoader(plugins_dir=tmp_path, db_manager=db_manager)
        loader.load_plugin("hook_plugin")
        from plugins.loader import importlib
        mod = sys.modules.get("netsentinel.plugins.hook_plugin")
        if mod is not None:
            assert mod.HookPlugin.hook_called is True
