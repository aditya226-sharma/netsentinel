# NetSentinel

Network Traffic Analysis & Security Monitoring Framework.

## Features

- **Real-time packet capture** with BPF filtering
- **Device discovery** with MAC/IP/hostname tracking
- **Bandwidth monitoring** per interface and per device
- **DNS analytics** with query logging and tunneling detection
- **TLS/SSL certificate inspection** with expiry alerts
- **Traffic flow monitoring** with protocol distribution
- **Security alert engine** with customizable rules
- **Web dashboard** with real-time updates via WebSocket
- **REST API** with JWT authentication
- **Plugin system** for extensibility
- **Report generation** (HTML, PDF, JSON, CSV)

## Quick Start

```bash
pip install -r requirements.txt
python -m cli --help
```

Start capturing:

```bash
sudo python -m cli start -i eth0
```

Open the web dashboard at http://localhost:8000

## Commands

- `netsentinel start` - Start API server with packet capture
- `netsentinel dashboard` - Start and open web dashboard
- `netsentinel capture` - Foreground packet capture with live stats
- `netsentinel report` - Generate traffic analysis reports
- `netsentinel devices` - List discovered network devices
- `netsentinel alerts` - Show security alerts
- `netsentinel interfaces` - List network interfaces
- `netsentinel stats` - Show traffic statistics
- `netsentinel export` - Export data to JSON/CSV

## Configuration

Configuration is read from `config/default.yaml`. Environment variables prefixed with `NETSENTINEL_` override config values at runtime.

## Project Structure

```
netsentinel/
├── api/           # FastAPI REST API & WebSocket
├── capture/       # Packet capture engine
├── cli.py         # Typer CLI entry point
├── config/        # Configuration management
├── database/      # SQLite database layer
├── modules/       # Analysis modules
├── parser/        # Protocol parsers
├── plugins/       # Plugin system
├── reports/       # Report generation
├── utils/         # Utilities & helpers
└── dashboard/     # Frontend web application
```

## License

MIT
