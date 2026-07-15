<div align="center">

```
 _   _      _    ____  _____            _     _                         
| \ | | ___|  _ \|  _ \| ____|_ __   ___| |__ | |__   ___   __ _ _ __  
|  \| |/ _ \ |_) | |_) |  _| | '_ \ / _ \ '_ \| '_ \ / _ \ / _` | '_ \ 
| |\  |  __/  _ <|  _ <| |___| | | |  __/ |_) | |_) | (_) | (_| | | | |
|_| \_|\___|_| \_\_| \_\_____|_| |_|\___|_.__/|_.__/ \___/ \__,_|_| |_|
```

**Network Traffic Analysis & Security Monitoring Framework**

[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Ubuntu%20%7C%20Debian-orange.svg)]()

</div>

---

## Features

- [x] Real-time network packet capture and analysis
- [x] Protocol parsing (TCP, UDP, ICMP, DNS, TLS, HTTP)
- [x] Device discovery and tracking
- [x] Bandwidth monitoring and statistics
- [x] DNS query logging and analysis
- [x] TLS/SSL session inspection
- [x] Security alert generation
- [x] Interactive web dashboard (React + Chart.js)
- [x] RESTful API with WebSocket support
- [x] Plugin system for custom analyzers
- [x] Report generation (HTML, PDF, JSON, CSV)
- [x] CLI interface with Rich output
- [x] SQLite database with WAL mode
- [x] Export captured data in multiple formats

## Quick Start

```bash
# Clone the repository
git clone https://github.com/youruser/NetSentinel.git
cd NetSentinel

# Install dependencies
./install.sh

# Or install manually
pip install -r requirements.txt
cd dashboard && npm install && npm run build && cd ..

# Start the application
netsentinel start
```

Open `http://localhost:8000` in your browser to access the dashboard.

## Screenshots

| View | Description |
|------|-------------|
| **Overview** | Real-time bandwidth, protocol distribution, and device count |
| **Devices** | Discovered network devices with traffic details |
| **Traffic** | Flow analysis, top talkers, and destination maps |
| **DNS** | Query logs, top domains, and error tracking |
| **TLS** | Session details, certificate info, and expiry alerts |
| **Alerts** | Security events and anomaly notifications |
| **Capture** | Interface selection and packet capture controls |

## CLI Usage

```bash
# Start the full application
netsentinel start

# Open dashboard in browser
netsentinel dashboard

# Capture packets on a specific interface
netsentinel capture --interface eth0 --duration 60

# View network statistics
netsentinel stats

# List discovered devices
netsentinel devices

# Generate a report
netsentinel report --format html --output report.html

# Export captured data
netsentinel export --format json --output data.json

# View active alerts
netsentinel alerts

# Check capture status
netsentinel capture --status
```

## API Overview

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | List discovered devices |
| `/api/traffic/overview` | GET | Traffic summary |
| `/api/dns/queries` | GET | DNS query log |
| `/api/tls/sessions` | GET | TLS session data |
| `/api/alerts` | GET | Security alerts |
| `/api/stats/overview` | GET | Network statistics |
| `/api/capture/start` | POST | Start packet capture |
| `/api/export/json` | GET | Export data as JSON |

Full API documentation: [docs/API.md](docs/API.md)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        NetSentinel                              │
├──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│   CLI    │ Dashboard│   API    │WebSocket │   Plugin System     │
│ (Typer)  │ (React)  │(FastAPI) │ Manager  │  (BasePlugin)       │
├──────────┴──────────┴──────────┴──────────┴─────────────────────┤
│                      Analysis Layer                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Protocol │  │ Traffic  │  │   DNS    │  │   TLS    │       │
│  │ Parsers  │  │ Analyzer │  │ Analyzer │  │ Analyzer │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
├─────────────────────────────────────────────────────────────────┤
│                    Capture Engine (Scapy)                       │
├─────────────────────────────────────────────────────────────────┤
│                   Database Layer (SQLite/WAL)                   │
└─────────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.12+, FastAPI |
| Packet Capture | Scapy |
| Database | SQLite (WAL mode) |
| Frontend | React, Tailwind CSS |
| Charts | Chart.js |
| Real-time | WebSocket |
| CLI | Typer, Rich |
| API Docs | OpenAPI/Swagger |

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Developer Guide](docs/DEVELOPER.md)
- [API Reference](docs/API.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Plugin Development](docs/PLUGIN_DEV.md)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [docs/DEVELOPER.md](docs/DEVELOPER.md) for detailed contribution guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
