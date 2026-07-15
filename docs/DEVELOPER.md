# Developer Guide

## Setting Up Development Environment

```bash
# Clone with development tools
git clone https://github.com/youruser/NetSentinel.git
cd NetSentinel

# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate

# Install all dependencies including dev tools
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install dashboard dependencies
cd dashboard && npm install && cd ..

# Initialize database
python -m netsentinel.db.init

# Run in development mode
python -m netsentinel --dev
```

### Development Dependencies

| Package | Purpose |
|---------|---------|
| pytest | Testing framework |
| pytest-cov | Coverage reporting |
| black | Code formatting |
| ruff | Linting |
| mypy | Type checking |
| pre-commit | Git hooks |
| ipython | Interactive shell |

## Project Structure

```
NetSentinel/
├── netsentinel/               # Main Python package
│   ├── __init__.py           # Package initialization
│   ├── __main__.py           # Entry point
│   ├── config.py             # Configuration loader
│   ├── capture/              # Packet capture engine
│   │   ├── __init__.py
│   │   ├── engine.py         # Scapy-based capture
│   │   └── interface.py      # Interface detection
│   ├── parsers/              # Protocol parsers
│   │   ├── __init__.py
│   │   ├── base.py           # BaseParser class
│   │   ├── tcp.py            # TCP parser
│   │   ├── udp.py            # UDP parser
│   │   ├── icmp.py           # ICMP parser
│   │   ├── dns.py            # DNS parser
│   │   ├── tls.py            # TLS/SSL parser
│   │   └── http.py           # HTTP parser
│   ├── analysis/             # Analysis modules
│   │   ├── __init__.py
│   │   ├── traffic.py        # Traffic analyzer
│   │   ├── dns.py            # DNS analyzer
│   │   ├── tls.py            # TLS analyzer
│   │   └── alerts.py         # Alert generator
│   ├── db/                   # Database layer
│   │   ├── __init__.py
│   │   ├── init.py           # Schema initialization
│   │   ├── models.py         # Data models
│   │   └── queries.py        # SQL queries
│   ├── api/                  # FastAPI endpoints
│   │   ├── __init__.py
│   │   ├── app.py            # FastAPI app
│   │   ├── routes/           # API route modules
│   │   │   ├── devices.py
│   │   │   ├── traffic.py
│   │   │   ├── dns.py
│   │   │   ├── tls.py
│   │   │   ├── alerts.py
│   │   │   ├── stats.py
│   │   │   ├── capture.py
│   │   │   └── export.py
│   │   └── websocket.py      # WebSocket manager
│   ├── plugins/              # Plugin system
│   │   ├── __init__.py
│   │   ├── base.py           # BasePlugin class
│   │   └── loader.py         # Plugin auto-loader
│   ├── cli/                  # Command-line interface
│   │   ├── __init__.py
│   │   └── main.py           # Typer CLI commands
│   └── reports/              # Report generation
│       ├── __init__.py
│       ├── html.py           # HTML report
│       ├── pdf.py            # PDF report
│       └── json.py           # JSON/CSV export
├── dashboard/                # React frontend
│   ├── src/
│   │   ├── App.jsx           # Main application
│   │   ├── components/       # React components
│   │   ├── pages/            # Page components
│   │   ├── hooks/            # Custom React hooks
│   │   └── utils/            # Utility functions
│   ├── public/               # Static assets
│   ├── package.json          # npm dependencies
│   └── vite.config.js        # Build configuration
├── plugins/                  # User plugins directory
├── data/                     # Database and captured data
├── logs/                     # Application logs
├── tests/                    # Test suite
│   ├── test_parsers/
│   ├── test_analysis/
│   ├── test_api/
│   └── test_db/
├── config.json               # Application configuration
├── requirements.txt          # Python dependencies
├── requirements-dev.txt      # Development dependencies
├── install.sh                # Installation script
└── netsentinel.egg-info/     # Package metadata
```

## Code Conventions

### Python Style (PEP 8)

- Use 4 spaces for indentation (no tabs)
- Maximum line length: 88 characters (Black default)
- Use snake_case for functions and variables
- Use PascalCase for classes
- Use UPPER_CASE for constants

### Type Hints

```python
from typing import Optional
from pydantic import BaseModel

def get_device(mac: str) -> Optional[Device]:
    """Get a device by MAC address."""
    pass

async def process_packet(packet: bytes) -> dict[str, any]:
    """Process a captured packet."""
    pass

class DeviceInfo(BaseModel):
    mac: str
    ip: str
    hostname: Optional[str] = None
    vendor: str = ""
```

### Docstrings (Google Style)

```python
def analyze_traffic(
    interface: str,
    duration: int,
    filter_expr: Optional[str] = None
) -> TrafficReport:
    """Analyze network traffic on an interface.

    Captures packets for the specified duration and generates
    a traffic analysis report.

    Args:
        interface: Network interface name (e.g., 'eth0').
        duration: Capture duration in seconds.
        filter_expr: Optional BPF filter expression.

    Returns:
        TrafficReport containing analysis results.

    Raises:
        CaptureError: If the interface is not available.
        PermissionError: If insufficient privileges.
    """
    pass
```

### Import Order

```python
# Standard library
import os
import sys
from pathlib import Path

# Third-party
import fastapi
import scapy.all as scapy
from sqlalchemy import create_engine

# Local
from netsentinel.config import settings
from netsentinel.db.models import Device
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=netsentinel --cov-report=html

# Run specific test file
pytest tests/test_parsers/test_dns.py

# Run tests matching a pattern
pytest -k "dns"

# Run in verbose mode
pytest -v

# Run and stop on first failure
pytest -x
```

### Writing Tests

```python
import pytest
from netsentinel.parsers.dns import DNSParser

class TestDNSParser:
    def test_parse_query(self):
        parser = DNSParser()
        result = parser.parse(dns_query_packet)
        assert result["domain"] == "example.com"
        assert result["query_type"] == "A"

    def test_parse_response(self):
        parser = DNSParser()
        result = parser.parse(dns_response_packet)
        assert result["query_type"] == "A"
        assert "192.0.2.1" in result["answers"]

    @pytest.mark.parametrize("query_type,expected", [
        ("A", 1),
        ("AAAA", 28),
        ("CNAME", 5),
        ("MX", 15),
    ])
    def test_query_type_mapping(self, query_type, expected):
        assert DNSParser.TYPE_MAP[query_type] == expected
```

## Adding New Protocol Parsers

### Step 1: Create Parser Module

```python
# netsentinel/parsers/ssh.py

from netsentinel.parsers.base import BaseParser
from dataclasses import dataclass

@dataclass
class SSHInfo:
    protocol_version: str
    kex_init: dict
    cipher: str
    mac: str
    compression: str

class SSHParser(BaseParser):
    """Parse SSH protocol packets."""

    PROTOCOL = "SSH"
    PORTS = {22}

    def can_handle(self, packet) -> bool:
        """Check if packet is SSH."""
        return packet.haslayer("TCP") and \
               packet["TCP"].dport in self.PORTS or \
               packet["TCP"].sport in self.PORTS

    def parse(self, packet) -> SSHInfo:
        """Parse SSH packet and extract information."""
        payload = bytes(packet["TCP"].payload)

        if len(payload) < 8:
            return None

        # Parse SSH banner or key exchange
        version = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore")

        return SSHInfo(
            protocol_version=version,
            kex_init={},
            cipher="unknown",
            mac="unknown",
            compression="none"
        )

    def to_dict(self, info: SSHInfo) -> dict:
        """Convert parsed info to dictionary."""
        return {
            "protocol": self.PROTOCOL,
            "version": info.protocol_version,
            "cipher": info.cipher,
            "mac": info.mac,
            "compression": info.compression
        }
```

### Step 2: Register Parser

```python
# netsentinel/parsers/__init__.py

from .ssh import SSHParser

PARSERS = [
    SSHParser,
    # ... other parsers
]
```

### Step 3: Add Tests

```python
# tests/test_parsers/test_ssh.py

import pytest
from netsentinel.parsers.ssh import SSHParser

class TestSSHParser:
    def setup_method(self):
        self.parser = SSHParser()

    def test_can_handle_ssh_packet(self, ssh_packet):
        assert self.parser.can_handle(ssh_packet) is True

    def test_parse_version(self, ssh_banner_packet):
        result = self.parser.parse(ssh_banner_packet)
        assert "SSH-2.0" in result.protocol_version
```

## Adding New Analysis Modules

### Step 1: Create Analyzer

```python
# netsentinel/analysis/anomaly.py

from netsentinel.analysis.base import BaseAnalyzer
from netsentinel.db.queries import get_recent_flows
from datetime import datetime, timedelta

class AnomalyDetector(BaseAnalyzer):
    """Detect anomalous network behavior."""

    def __init__(self):
        self.baseline = {}
        self.threshold = 2.0  # Standard deviations

    def analyze(self, time_window: int = 300) -> list[dict]:
        """Analyze traffic for anomalies."""
        flows = get_recent_flows(time_window)
        anomalies = []

        # Calculate baseline
        baseline_stats = self._calculate_baseline(flows)

        # Detect anomalies
        for flow in flows:
            score = self._calculate_anomaly_score(flow, baseline_stats)
            if score > self.threshold:
                anomalies.append({
                    "type": "traffic_anomaly",
                    "severity": self._score_to_severity(score),
                    "source_ip": flow["src_ip"],
                    "details": f"Anomaly score: {score:.2f}"
                })

        return anomalies

    def _calculate_baseline(self, flows):
        """Calculate baseline statistics."""
        pass

    def _calculate_anomaly_score(self, flow, baseline):
        """Calculate anomaly score for a flow."""
        pass

    def _score_to_severity(self, score):
        """Convert anomaly score to severity level."""
        if score > 4.0:
            return "critical"
        elif score > 3.0:
            return "high"
        elif score > 2.0:
            return "medium"
        return "low"
```

### Step 2: Register Analyzer

```python
# netsentinel/analysis/__init__.py

from .anomaly import AnomalyDetector

ANALYZERS = [
    AnomalyDetector,
]
```

## Building the Dashboard

### Development

```bash
cd dashboard

# Start dev server with hot reload
npm run dev

# Access at http://localhost:5173
```

### Production Build

```bash
cd dashboard

# Build optimized bundle
npm run build

# Output: dashboard/dist/
```

### Adding a New Component

```jsx
// dashboard/src/components/TrafficChart.jsx

import { useEffect, useRef } from 'react';
import { Chart } from 'chart.js';

export default function TrafficChart({ data }) {
    const chartRef = useRef(null);
    const chartInstance = useRef(null);

    useEffect(() => {
        if (chartInstance.current) {
            chartInstance.current.destroy();
        }

        const ctx = chartRef.current.getContext('2d');
        chartInstance.current = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.timestamps,
                datasets: [{
                    label: 'Bandwidth (Mbps)',
                    data: data.values,
                    borderColor: '#3b82f6',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        return () => {
            if (chartInstance.current) {
                chartInstance.current.destroy();
            }
        };
    }, [data]);

    return (
        <div className="h-64">
            <canvas ref={chartRef} />
        </div>
    );
}
```

## Database Schema

### Core Tables

```sql
-- Devices table
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT UNIQUE NOT NULL,
    ip TEXT,
    hostname TEXT,
    vendor TEXT DEFAULT '',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1
);

-- Traffic flows
CREATE TABLE traffic_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    packets_sent INTEGER DEFAULT 0,
    packets_received INTEGER DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    duration REAL DEFAULT 0
);

-- DNS queries
CREATE TABLE dns_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    query_name TEXT NOT NULL,
    query_type TEXT NOT NULL,
    response_code TEXT,
    answers TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- TLS sessions
CREATE TABLE tls_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    sni TEXT,
    issuer TEXT,
    subject TEXT,
    not_before TIMESTAMP,
    not_after TIMESTAMP,
    version TEXT,
    cipher_suite TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Alerts
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    message TEXT NOT NULL,
    details TEXT,
    acknowledged BOOLEAN DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bandwidth statistics
CREATE TABLE bandwidth_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL,
    bytes_in INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Indexes

```sql
CREATE INDEX idx_devices_mac ON devices(mac);
CREATE INDEX idx_devices_ip ON devices(ip);
CREATE INDEX idx_flows_src ON traffic_flows(src_ip);
CREATE INDEX idx_flows_dst ON traffic_flows(dst_ip);
CREATE INDEX idx_flows_protocol ON traffic_flows(protocol);
CREATE INDEX idx_dns_query ON dns_queries(query_name);
CREATE INDEX idx_dns_src ON dns_queries(src_ip);
CREATE INDEX idx_tls_sni ON tls_sessions(sni);
CREATE INDEX idx_alerts_type ON alerts(type);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_time ON alerts(timestamp);
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI (Typer)                             │
│   start | dashboard | capture | report | devices | stats       │
└───────────────┬─────────────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Application Core                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │  Config  │  │  Plugin  │  │ Scheduler│  │  Logger  │      │
│  │  Loader  │  │  Loader  │  │          │  │          │      │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │
└───────────────┬─────────────────────────────────────────────────┘
                │
        ┌───────┴───────┐
        │               │
        ▼               ▼
┌───────────────┐ ┌───────────────┐
│  API Server   │ │   Capture     │
│  (FastAPI)    │ │   Engine      │
│  WebSocket    │ │   (Scapy)     │
└───────┬───────┘ └───────┬───────┘
        │                 │
        │        ┌────────┴────────┐
        │        │                 │
        │        ▼                 ▼
        │  ┌──────────┐     ┌──────────┐
        │  │ Protocol │     │ Analysis │
        │  │ Parsers  │     │ Modules  │
        │  └──────────┘     └──────────┘
        │        │                 │
        │        └────────┬────────┘
        │                 │
        ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Database Layer (SQLite)                       │
│                    WAL Mode | Auto-vacuum                        │
└─────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Dashboard (React SPA)                        │
│   Overview | Devices | Traffic | DNS | TLS | Alerts | Capture   │
└─────────────────────────────────────────────────────────────────┘
```

## Design Patterns

| Pattern | Usage | Location |
|---------|-------|----------|
| **Factory** | Parser creation | `parsers/__init__.py` |
| **Strategy** | Report generation | `reports/` |
| **Observer** | WebSocket updates | `api/websocket.py` |
| **Plugin** | Extensible analysis | `plugins/base.py` |
| **Singleton** | Configuration | `config.py` |
| **Repository** | Database access | `db/queries.py` |
| **Builder** | Query construction | `db/queries.py` |
| **Async** | API handlers | `api/routes/` |

## Contributing Process

### 1. Fork and Branch

```bash
git clone https://github.com/youruser/NetSentinel.git
cd NetSentinel
git checkout -b feature/my-feature
```

### 2. Make Changes

- Follow code conventions
- Add type hints
- Write docstrings
- Add tests

### 3. Run Quality Checks

```bash
# Format code
black netsentinel/

# Lint
ruff check netsentinel/

# Type check
mypy netsentinel/

# Run tests
pytest --cov=netsentinel
```

### 4. Commit

```bash
git add .
git commit -m "feat: add SSH protocol parser"
```

Follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Tests
- `refactor:` Code refactoring
- `chore:` Maintenance

### 5. Push and Create PR

```bash
git push origin feature/my-feature
```

Create a Pull Request with:
- Clear description
- Reference any issues
- Screenshots for UI changes
- Test results
