# Plugin Development Guide

## Plugin Architecture Overview

NetSentinel's plugin system allows you to extend functionality with custom analysis modules, protocol parsers, and alert generators.

```
┌─────────────────────────────────────────────────────────────────┐
│                      Plugin System                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Plugin Loader                         │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │  │
│  │  │ Discovery│  │ Loading  │  │Validation│             │  │
│  │  └──────────┘  └──────────┘  └──────────┘             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│                              ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    BasePlugin                            │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │  │
│  │  │ initialize│  │ process  │  │ cleanup  │             │  │
│  │  └──────────┘  └──────────┘  └──────────┘             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│           ┌──────────────────┼──────────────────┐             │
│           │                  │                  │             │
│           ▼                  ▼                  ▼             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  Your Plugin │  │  Your Plugin │  │  Your Plugin │       │
│  │   (DNS)      │  │   (Custom)   │  │   (Alert)    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## BasePlugin Class API

```python
from abc import ABC, abstractmethod
from typing import Any, Optional
from netsentinel.plugins.base import BasePlugin

class BasePlugin(ABC):
    """Abstract base class for all NetSentinel plugins."""

    # Plugin metadata (required)
    name: str = "BasePlugin"
    version: str = "1.0.0"
    description: str = "Base plugin"
    author: str = ""

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the plugin.

        Called once when the plugin is loaded.
        Return True if initialization succeeds.

        Returns:
            bool: True if initialization successful.
        """
        pass

    @abstractmethod
    def process(self, data: dict[str, Any]) -> Optional[dict]:
        """Process incoming data.

        Called for each packet/event that matches the plugin's
        registered event types.

        Args:
            data: Dictionary containing parsed packet data or event.

        Returns:
            Optional dict with processing results, or None.
        """
        pass

    def cleanup(self) -> None:
        """Clean up plugin resources.

        Called when the plugin is unloaded or the application shuts down.
        Override this to release resources.
        """
        pass

    def on_alert(self, alert: dict) -> Optional[dict]:
        """Handle generated alerts.

        Called when any alert is generated. Can modify or suppress alerts.

        Args:
            alert: Alert dictionary.

        Returns:
            Modified alert or None to suppress.
        """
        return alert

    def get_config_schema(self) -> Optional[dict]:
        """Return configuration schema for this plugin.

        Returns:
            JSON schema dict for plugin configuration.
        """
        return None
```

## Creating a New Plugin (Step by Step)

### Step 1: Create Plugin Directory

```bash
cd plugins/
mkdir my_plugin/
touch my_plugin/__init__.py
touch my_plugin/plugin.py
touch my_plugin/manifest.json
```

### Step 2: Create Manifest

```json
{
    "name": "my_plugin",
    "version": "1.0.0",
    "description": "My custom NetSentinel plugin",
    "author": "Your Name",
    "email": "you@example.com",
    "entry_point": "plugin.py",
    "class_name": "MyPlugin",
    "event_types": ["dns", "tls", "traffic"],
    "config_schema": {
        "type": "object",
        "properties": {
            "threshold": {
                "type": "number",
                "default": 100,
                "description": "Alert threshold"
            }
        }
    }
}
```

### Step 3: Implement Plugin

```python
# plugins/my_plugin/plugin.py

from typing import Any, Optional
from netsentinel.plugins.base import BasePlugin

class MyPlugin(BasePlugin):
    """Custom DNS monitoring plugin."""

    name = "my_plugin"
    version = "1.0.0"
    description = "Custom DNS query monitor"
    author = "Your Name"

    def __init__(self):
        self.query_count = 0
        self.suspicious_domains = []
        self.threshold = 100

    def initialize(self) -> bool:
        """Initialize plugin resources."""
        # Load configuration
        config = self.get_config()
        if config:
            self.threshold = config.get("threshold", 100)

        # Load suspicious domain list
        self._load_suspicious_domains()

        self.log_info(f"Initialized with threshold: {self.threshold}")
        return True

    def process(self, data: dict[str, Any]) -> Optional[dict]:
        """Process DNS query data."""
        if data.get("type") != "dns":
            return None

        self.query_count += 1
        query_name = data.get("query_name", "")

        # Check for suspicious domains
        for domain in self.suspicious_domains:
            if domain in query_name:
                return {
                    "alert": True,
                    "severity": "high",
                    "type": "suspicious_dns",
                    "message": f"Suspicious DNS query: {query_name}",
                    "details": {
                        "query_name": query_name,
                        "matched_domain": domain,
                        "src_ip": data.get("src_ip")
                    }
                }

        # Track query frequency
        if self.query_count % self.threshold == 0:
            return {
                "stats": True,
                "queries_processed": self.query_count
            }

        return None

    def cleanup(self) -> None:
        """Cleanup resources."""
        self.log_info(f"Processed {self.query_count} queries total")

    def _load_suspicious_domains(self) -> None:
        """Load suspicious domain list."""
        # Load from config file or database
        self.suspicious_domains = [
            "malware.example.com",
            "phishing.example.com",
            "c2.example.com"
        ]
```

### Step 4: Test Plugin

```python
# tests/test_plugins/test_my_plugin.py

import pytest
from plugins.my_plugin.plugin import MyPlugin

class TestMyPlugin:
    def setup_method(self):
        self.plugin = MyPlugin()
        self.plugin.initialize()

    def test_process_normal_dns(self):
        data = {
            "type": "dns",
            "query_name": "www.example.com",
            "query_type": "A",
            "src_ip": "192.168.1.100"
        }
        result = self.plugin.process(data)
        assert result is None

    def test_process_suspicious_dns(self):
        data = {
            "type": "dns",
            "query_name": "malware.example.com",
            "query_type": "A",
            "src_ip": "192.168.1.100"
        }
        result = self.plugin.process(data)
        assert result is not None
        assert result["alert"] is True
        assert result["severity"] == "high"

    def test_cleanup(self):
        self.plugin.cleanup()
        # No assertion needed, just ensure no errors
```

## Plugin Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                    Plugin Lifecycle                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐                                                   │
│  │ Discovery│  Scan plugins/ directory for manifests            │
│  └────┬─────┘                                                   │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │ Loading  │  Import plugin module                             │
│  └────┬─────┘                                                   │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │Validation│  Validate manifest and class structure            │
│  └────┬─────┘                                                   │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │Initialize│  Call plugin.initialize()                         │
│  └────┬─────┘                                                   │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐               │
│  │ Process  │────▶│ Process  │────▶│ Process  │──▶ ...        │
│  │  (loop)  │     │  (loop)  │     │  (loop)  │               │
│  └────┬─────┘     └──────────┘     └──────────┘               │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │ Cleanup  │  Call plugin.cleanup() on shutdown                │
│  └──────────┘                                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Lifecycle Methods

| Method | When Called | Purpose |
|--------|------------|---------|
| `initialize()` | Plugin load | Set up resources |
| `process()` | Each event | Process data |
| `cleanup()` | Plugin unload | Release resources |
| `on_alert()` | Alert generated | Filter/modify alerts |
| `get_config_schema()` | Config loading | Define config structure |

## Available APIs in Plugins

### Logging

```python
# Use built-in logging methods
self.log_debug("Debug message")
self.log_info("Info message")
self.log_warning("Warning message")
self.log_error("Error message")
```

### Configuration

```python
# Get plugin-specific configuration
config = self.get_config()
threshold = config.get("threshold", 100)
```

### Database Access

```python
# Access database (read-only)
db = self.get_database()

# Execute query
results = db.execute(
    "SELECT * FROM dns_queries WHERE query_name LIKE ?",
    (f"%{domain}%",)
).fetchall()
```

### Alert Generation

```python
# Generate an alert
self.create_alert(
    type="custom_alert",
    severity="high",
    source_ip="192.168.1.100",
    message="Custom alert message",
    details={"key": "value"}
)
```

### Event Publishing

```python
# Publish custom event
self.publish_event(
    channel="custom",
    event_type="my_event",
    data={"key": "value"}
)
```

### Statistics

```python
# Update plugin statistics
self.update_stats(
    queries_processed=100,
    alerts_generated=5
)
```

### Utility Methods

```python
# Resolve IP to hostname
hostname = self.resolve_hostname("192.168.1.1")

# Get device info
device = self.get_device_by_ip("192.168.1.1")

# Format bytes
formatted = self.format_bytes(1048576)  # "1.0 MB"

# Calculate time delta
delta = self.time_ago("2024-01-15T10:30:00Z")  # "5 minutes ago"
```

## Plugin Configuration

### config.json

```json
{
    "plugins": {
        "enabled": true,
        "directory": "plugins/",
        "config": {
            "my_plugin": {
                "threshold": 100,
                "alert_on_suspicious": true,
                "log_level": "INFO"
            },
            "custom_dns_monitor": {
                "tracked_domains": ["example.com", "test.com"],
                "alert_threshold": 50
            }
        }
    }
}
```

### Accessing Configuration in Plugin

```python
def initialize(self) -> bool:
    config = self.get_config()

    if config:
        self.threshold = config.get("threshold", 100)
        self.tracked_domains = config.get("tracked_domains", [])

    return True
```

## Registering Plugins

### Automatic Registration

Plugins in the `plugins/` directory with valid manifests are automatically discovered and loaded.

### Manual Registration

```python
from netsentinel.plugins.loader import PluginLoader

loader = PluginLoader()

# Load specific plugin
loader.load_plugin("plugins/my_plugin/")

# Load all plugins
loader.load_all()

# Get loaded plugins
plugins = loader.get_plugins()
```

### Plugin Discovery

The plugin loader scans for:

1. `manifest.json` in plugin directories
2. Valid Python module with entry point class
3. Class inheriting from `BasePlugin`

## Example Plugin: Custom DNS Monitor

```python
# plugins/dns_monitor/plugin.py

from collections import defaultdict
from typing import Any, Optional
from netsentinel.plugins.base import BasePlugin

class DNSMonitorPlugin(BasePlugin):
    """Monitor DNS queries for suspicious patterns."""

    name = "dns_monitor"
    version = "1.0.0"
    description = "DNS query pattern monitor"
    author = "NetSentinel"

    def __init__(self):
        self.query_counts = defaultdict(int)
        self.domain_queries = defaultdict(set)
        self.time_window = 300  # 5 minutes
        self.max_queries = 1000

    def initialize(self) -> bool:
        """Initialize DNS monitor."""
        config = self.get_config()
        if config:
            self.time_window = config.get("time_window", 300)
            self.max_queries = config.get("max_queries", 1000)

        self.log_info(
            f"DNS Monitor initialized: "
            f"window={self.time_window}s, "
            f"max_queries={self.max_queries}"
        )
        return True

    def process(self, data: dict[str, Any]) -> Optional[dict]:
        """Process DNS query."""
        if data.get("type") != "dns":
            return None

        query_name = data.get("query_name", "")
        src_ip = data.get("src_ip", "")

        # Track queries per source IP
        self.query_counts[src_ip] += 1
        self.domain_queries[src_ip].add(query_name)

        # Check for excessive queries
        if self.query_counts[src_ip] > self.max_queries:
            return self._create_alert(
                "dns_flood",
                "high",
                src_ip,
                f"DNS flood detected: {self.query_counts[src_ip]} queries"
            )

        # Check for DNS tunneling patterns
        if self._is_suspicious_query(query_name):
            return self._create_alert(
                "suspicious_dns",
                "medium",
                src_ip,
                f"Suspicious DNS query: {query_name}"
            )

        return None

    def _is_suspicious_query(self, query_name: str) -> bool:
        """Check if DNS query is suspicious."""
        # Check for very long subdomains (potential tunneling)
        parts = query_name.split(".")
        for part in parts:
            if len(part) > 50:
                return True

        # Check for high entropy in subdomain
        if self._calculate_entropy(query_name.split(".")[0]) > 4.0:
            return True

        return False

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        import math
        from collections import Counter

        counter = Counter(text)
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        return entropy

    def _create_alert(
        self,
        alert_type: str,
        severity: str,
        source_ip: str,
        message: str
    ) -> dict:
        """Create alert dictionary."""
        return {
            "alert": True,
            "type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "message": message,
            "plugin": self.name,
            "details": {
                "query_count": self.query_counts[source_ip],
                "unique_domains": len(self.domain_queries[source_ip])
            }
        }

    def cleanup(self) -> None:
        """Cleanup resources."""
        total_queries = sum(self.query_counts.values())
        self.log_info(
            f"DNS Monitor cleanup: "
            f"processed {total_queries} queries"
        )
        self.query_counts.clear()
        self.domain_queries.clear()
```

## Testing Plugins

### Unit Tests

```python
import pytest
from unittest.mock import Mock, patch
from plugins.dns_monitor.plugin import DNSMonitorPlugin

class TestDNSMonitorPlugin:
    def setup_method(self):
        self.plugin = DNSMonitorPlugin()

    @patch('netsentinel.plugins.base.BasePlugin.get_config')
    def test_initialize(self, mock_config):
        mock_config.return_value = {
            "time_window": 600,
            "max_queries": 500
        }
        result = self.plugin.initialize()
        assert result is True
        assert self.plugin.time_window == 600

    def test_process_normal_query(self):
        self.plugin.initialize()
        data = {
            "type": "dns",
            "query_name": "www.example.com",
            "src_ip": "192.168.1.1"
        }
        result = self.plugin.process(data)
        assert result is None

    def test_process_long_subdomain(self):
        self.plugin.initialize()
        data = {
            "type": "dns",
            "query_name": "a" * 60 + ".example.com",
            "src_ip": "192.168.1.1"
        }
        result = self.plugin.process(data)
        assert result is not None
        assert result["alert"] is True

    def test_process_flood_detection(self):
        self.plugin.initialize()
        # Simulate many queries
        for i in range(1001):
            self.plugin.process({
                "type": "dns",
                "query_name": f"query{i}.example.com",
                "src_ip": "192.168.1.1"
            })

        # Next query should trigger alert
        result = self.plugin.process({
            "type": "dns",
            "query_name": "final.example.com",
            "src_ip": "192.168.1.1"
        })
        assert result is not None
        assert result["type"] == "dns_flood"
```

### Integration Tests

```python
import pytest
from netsentinel.plugins.loader import PluginLoader

class TestDNSMonitorIntegration:
    def test_plugin_loading(self):
        loader = PluginLoader()
        loader.load_plugin("plugins/dns_monitor/")
        plugins = loader.get_plugins()
        assert "dns_monitor" in plugins

    def test_plugin_lifecycle(self):
        loader = PluginLoader()
        loader.load_plugin("plugins/dns_monitor/")
        plugin = loader.get_plugin("dns_monitor")

        # Test initialize
        assert plugin.initialize() is True

        # Test processing
        result = plugin.process({
            "type": "dns",
            "query_name": "test.example.com",
            "src_ip": "192.168.1.1"
        })

        # Test cleanup
        plugin.cleanup()
```

### Running Plugin Tests

```bash
# Run all plugin tests
pytest tests/test_plugins/

# Run specific plugin tests
pytest tests/test_plugins/test_dns_monitor.py -v

# Run with coverage
pytest tests/test_plugins/ --cov=plugins/
```

## Best Practices

### Code Quality

| Practice | Description |
|----------|-------------|
| Type Hints | Use Python type annotations |
| Docstrings | Document all public methods |
| Error Handling | Catch and handle exceptions gracefully |
| Logging | Use plugin logging methods |
| Testing | Write unit and integration tests |

### Performance

| Practice | Description |
|----------|-------------|
| Minimize Work | Process only relevant events |
| Cache Results | Cache expensive computations |
| Batch Operations | Batch database inserts |
| Release Resources | Clean up in cleanup() |
| Avoid Blocking | Don't block the main thread |

### Security

| Practice | Description |
|----------|-------------|
| Input Validation | Validate all input data |
| Sanitize Output | Sanitize any user-facing data |
| No Secrets | Don't hardcode credentials |
| Least Privilege | Request only needed permissions |

### Documentation

| Practice | Description |
|----------|-------------|
| README | Include plugin README.md |
| Manifest | Complete manifest.json |
| Examples | Provide usage examples |
| API Docs | Document public API |

## Plugin Manifest Reference

```json
{
    "name": "plugin_name",
    "version": "1.0.0",
    "description": "Plugin description",
    "author": "Author Name",
    "email": "author@example.com",
    "url": "https://github.com/author/plugin",
    "license": "MIT",
    "entry_point": "plugin.py",
    "class_name": "PluginClassName",
    "dependencies": [],
    "event_types": ["dns", "tls", "traffic", "alerts"],
    "config_schema": {
        "type": "object",
        "properties": {}
    },
    "min_netsentinel_version": "1.0.0",
    "tags": ["dns", "monitoring", "security"]
}
```

### Manifest Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Unique plugin name |
| version | string | Yes | Semantic version |
| description | string | Yes | Brief description |
| author | string | Yes | Author name |
| entry_point | string | Yes | Python file containing plugin class |
| class_name | string | Yes | Class name in entry point |
| event_types | array | No | Event types to process |
| config_schema | object | No | JSON schema for configuration |
| dependencies | array | No | Required packages |
| min_netsentinel_version | string | No | Minimum required version |
