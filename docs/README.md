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
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Ubuntu%20%7C%20Debian-orange.svg)]()

</div>

---

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](INSTALLATION.md) | Setup and installation instructions |
| [Developer Guide](DEVELOPER.md) | Contributing and development setup |
| [API Reference](API.md) | Complete REST API documentation |
| [Architecture](ARCHITECTURE.md) | System design and architecture |
| [Plugin Development](PLUGIN_DEV.md) | Creating custom plugins |

## Quick Links

- **Getting Started:** See [Installation Guide](INSTALLATION.md)
- **API Docs:** See [API Reference](API.md) or visit `/docs` when running
- **Contributing:** See [Developer Guide](DEVELOPER.md)
- **Plugins:** See [Plugin Development](PLUGIN_DEV.md)

## Features

- Real-time packet capture and analysis
- Protocol parsing (TCP, UDP, ICMP, DNS, TLS, HTTP)
- Device discovery and tracking
- Security alert generation
- Web dashboard with real-time updates
- Plugin system for custom analyzers
- Report generation (HTML, PDF, JSON, CSV)

## Quick Start

```bash
git clone https://github.com/youruser/NetSentinel.git
cd NetSentinel
./install.sh
netsentinel start
```

Open `http://localhost:8000` to access the dashboard.

## CLI Commands

```bash
netsentinel start          # Start the application
netsentinel dashboard      # Open dashboard in browser
netsentinel capture        # Capture packets
netsentinel report         # Generate report
netsentinel devices        # List devices
netsentinel alerts         # View alerts
netsentinel stats          # Show statistics
netsentinel export         # Export data
```

## Support

- **Issues:** [GitHub Issues](https://github.com/youruser/NetSentinel/issues)
- **Documentation:** This directory
- **API Docs:** Available at `/docs` endpoint when running

## License

MIT License - see [LICENSE](../LICENSE)
