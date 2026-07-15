# Installation Guide

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.12+ | Core runtime |
| pip | 24.0+ | Package management |
| libpcap | 1.10+ | Packet capture |
| Node.js | 18+ | Dashboard build |
| npm | 9+ | Dashboard dependencies |

### System Packages

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3-pip \
    libpcap-dev build-essential nodejs npm git
```

**Kali Linux:**
```bash
sudo apt update
sudo apt install -y python3-pip libpcap-dev build-essential nodejs npm git
```

## Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| Kali Linux | Full | Recommended |
| Ubuntu 22.04+ | Full | |
| Debian 12+ | Full | |
| Other Linux | Partial | May need manual libpcap setup |
| macOS | Experimental | Limited capture support |
| Windows | Not Supported | Use WSL2 |

## Quick Install

```bash
git clone https://github.com/youruser/NetSentinel.git
cd NetSentinel
chmod +x install.sh
./install.sh
```

The install script will:
1. Create a Python virtual environment
2. Install all Python dependencies
3. Build the React dashboard
4. Initialize the database
5. Create the `netsentinel` CLI command

## Manual Install

### Step 1: Clone and Setup Python Environment

```bash
git clone https://github.com/youruser/NetSentinel.git
cd NetSentinel

# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Install System Dependencies

```bash
# Install libpcap (if not already installed)
sudo apt install libpcap-dev

# Install Node.js (if not already installed)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### Step 3: Build Dashboard

```bash
cd dashboard
npm install
npm run build
cd ..
```

### Step 4: Initialize Database

```bash
python -m netsentinel.db.init
```

### Step 5: Create CLI Entry Point

```bash
pip install -e .
```

Or create a symlink:

```bash
chmod +x netsentinel/cli/main.py
ln -s $(pwd)/netsentinel/cli/main.py /usr/local/bin/netsentinel
```

## Virtual Environment Management

```bash
# Activate
source venv/bin/activate

# Deactivate
deactivate

# Recreate if corrupted
rm -rf venv
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Dashboard Build

The dashboard is a React SPA served from the FastAPI backend.

```bash
cd dashboard

# Install dependencies
npm install

# Development mode (hot reload)
npm run dev

# Production build
npm run build

# Output goes to: dashboard/dist/
```

Build output is automatically served by the API server at `http://localhost:8000`.

## Configuration

Copy the example configuration:

```bash
cp config.example.json config.json
```

Edit `config.json`:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8000
  },
  "capture": {
    "interface": "auto",
    "promiscuous": true,
    "buffer_size": 65536,
    "max_packets": 0
  },
  "database": {
    "path": "data/netsentinel.db",
    "wal_mode": true
  },
  "logging": {
    "level": "INFO",
    "file": "logs/netsentinel.log"
  },
  "alerts": {
    "enabled": true,
    "threshold_packets_per_sec": 1000,
    "suspicious_ports": [4444, 5555, 6666, 31337]
  }
}
```

### Configuration Options

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| server | host | `0.0.0.0` | API bind address |
| server | port | `8000` | API port |
| capture | interface | `auto` | Network interface (auto-detect if unset) |
| capture | promiscuous | `true` | Promiscuous mode |
| capture | buffer_size | `65536` | Capture buffer size |
| database | path | `data/netsentinel.db` | SQLite database path |
| database | wal_mode | `true` | Enable WAL journal mode |
| logging | level | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| alerts | enabled | `true` | Enable alert generation |

## Troubleshooting

### Permission Denied on Capture

```bash
# Run with sudo for packet capture
sudo netsentinel start

# Or set capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3.12)
```

### Port Already in Use

```bash
# Find process using port 8000
lsof -i :8000

# Kill it
kill -9 <PID>

# Or use a different port
netsentinel start --port 8080
```

### Dashboard Not Loading

```bash
# Rebuild dashboard
cd dashboard
rm -rf node_modules dist
npm install
npm run build
```

### Database Errors

```bash
# Delete and recreate database
rm -f data/netsentinel.db data/netsentinel.db-wal data/netsentinel.db-shm
python -m netsentinel.db.init
```

### Import Errors

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### libpcap Not Found

```bash
# Debian/Ubuntu
sudo apt install libpcap-dev

# Verify installation
pkg-config --libs libpcap
```

## Verifying Installation

```bash
# Check Python version
python --version
# Expected: Python 3.12.x

# Check netsentinel command
netsentinel --version
# Expected: NetSentinel 1.0.0

# Check database
ls -la data/netsentinel.db
# Expected: File exists

# Check dashboard
ls -la dashboard/dist/index.html
# Expected: File exists

# Test API server
netsentinel start &
sleep 3
curl http://localhost:8000/api/stats/overview
# Expected: JSON response with network statistics

# Stop the server
netsentinel stop
```
