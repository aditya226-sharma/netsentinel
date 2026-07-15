# Architecture Document

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           NetSentinel                                    │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Presentation Layer                          │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  │   │
│  │  │    CLI    │  │ Dashboard │  │    API    │  │ WebSocket │  │   │
│  │  │  (Typer)  │  │  (React)  │  │ (FastAPI) │  │  Manager  │  │   │
│  │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  │   │
│  └────────┼──────────────┼──────────────┼──────────────┼──────────┘   │
│           │              │              │              │                │
│  ┌────────┴──────────────┴──────────────┴──────────────┴──────────┐   │
│  │                      Application Layer                         │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │   │
│  │  │  Config  │  │  Plugin  │  │ Scheduler│  │  Logger  │      │   │
│  │  │  Manager │  │  System  │  │          │  │          │      │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │   │
│  └────────────────────────┬───────────────────────────────────────┘   │
│                           │                                           │
│  ┌────────────────────────┴───────────────────────────────────────┐   │
│  │                       Core Layer                                │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │                   Capture Engine                        │   │   │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │   │   │
│  │  │  │ Interface│  │  Packet  │  │   BPF    │             │   │   │
│  │  │  │ Detector │  │  Capture │  │  Filter  │             │   │   │
│  │  │  └──────────┘  └──────────┘  └──────────┘             │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │                  Protocol Parsers                       │   │   │
│  │  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐│   │   │
│  │  │  │ TCP  │ │ UDP  │ │ ICMP │ │ DNS  │ │ TLS  │ │ HTTP ││   │   │
│  │  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘│   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │                  Analysis Modules                       │   │   │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │   │   │
│  │  │  │ Traffic  │  │   DNS    │  │   TLS    │             │   │   │
│  │  │  │ Analyzer │  │ Analyzer │  │ Analyzer │             │   │   │
│  │  │  └──────────┘  └──────────┘  └──────────┘             │   │   │
│  │  │  ┌──────────┐  ┌──────────┐                           │   │   │
│  │  │  │  Alert   │  │ Anomaly  │                           │   │   │
│  │  │  │Generator │  │ Detector │                           │   │   │
│  │  │  └──────────┘  └──────────┘                           │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      Storage Layer                              │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │                  Database (SQLite)                       │   │   │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │   │   │
│  │  │  │ Devices  │  │ Flows    │  │ DNS      │             │   │   │
│  │  │  └──────────┘  └──────────┘  └──────────┘             │   │   │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │   │   │
│  │  │  │ TLS      │  │ Alerts   │  │ Stats    │             │   │   │
│  │  │  └──────────┘  └──────────┘  └──────────┘             │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### Capture Engine

**Location:** `netsentinel/capture/`

The Capture Engine is responsible for raw packet acquisition from network interfaces.

| Component | File | Description |
|-----------|------|-------------|
| `Engine` | `engine.py` | Core capture loop using Scapy |
| `InterfaceDetector` | `interface.py` | Auto-detect available interfaces |

**Key Responsibilities:**
- Interface discovery and selection
- Packet capture with BPF filters
- Buffer management for high-throughput scenarios
- Graceful shutdown and resource cleanup

**Threading Model:**
- Main capture thread (blocking)
- Packet queue thread (producer)
- Analysis workers (consumer pool)

```python
# Simplified capture flow
class CaptureEngine:
    def __init__(self, interface: str, filter: str):
        self.interface = interface
        self.filter = filter
        self.packet_queue = Queue(maxsize=10000)
        self.workers = []

    async def start(self):
        """Start capture engine."""
        # Start worker threads
        for _ in range(self.num_workers):
            worker = Thread(target=self._process_worker)
            worker.start()
            self.workers.append(worker)

        # Start capture
        sniff(
            iface=self.interface,
            filter=self.filter,
            prn=self._packet_handler,
            store=False
        )
```

### Protocol Parsers

**Location:** `netsentinel/parsers/`

Protocol parsers extract structured data from raw packet payloads.

| Parser | File | Protocols |
|--------|------|-----------|
| `BaseParser` | `base.py` | Abstract base class |
| `TCPParser` | `tcp.py` | TCP segments |
| `UDPParser` | `udp.py` | UDP datagrams |
| `ICMPParser` | `icmp.py` | ICMP messages |
| `DNSParser` | `dns.py` | DNS queries/responses |
| `TLSParser` | `tls.py` | TLS/SSL handshakes |
| `HTTPParser` | `http.py` | HTTP requests/responses |

**Parser Interface:**
```python
class BaseParser(ABC):
    @abstractmethod
    def can_handle(self, packet) -> bool:
        """Check if parser can handle this packet."""
        pass

    @abstractmethod
    def parse(self, packet) -> Any:
        """Parse packet and return structured data."""
        pass

    @abstractmethod
    def to_dict(self, parsed_data) -> dict:
        """Convert parsed data to dictionary."""
        pass
```

### Analysis Modules

**Location:** `netsentinel/analysis/`

Analysis modules process parsed data to generate insights and alerts.

| Module | File | Purpose |
|--------|------|---------|
| `TrafficAnalyzer` | `traffic.py` | Bandwidth and flow analysis |
| `DNSAnalyzer` | `dns.py` | DNS query pattern analysis |
| `TLSAnalyzer` | `tls.py` | Certificate and encryption analysis |
| `AlertGenerator` | `alerts.py` | Security alert generation |

**Analysis Pipeline:**
```
Packet → Parser → Analyzer → Database → Alert/API/WebSocket
```

### Database Layer

**Location:** `netsentinel/db/`

SQLite database with WAL mode for concurrent reads.

| Component | File | Purpose |
|-----------|------|---------|
| `init.py` | Schema creation | Table and index setup |
| `models.py` | Data models | Pydantic models |
| `queries.py` | SQL queries | Database operations |

**Performance Optimizations:**
- WAL journal mode for concurrent access
- Batch inserts for high-throughput capture
- Prepared statements for repeated queries
- Automatic vacuum scheduling

### API Layer

**Location:** `netsentinel/api/`

FastAPI application with RESTful endpoints and WebSocket support.

| Component | File | Purpose |
|-----------|------|---------|
| `app.py` | Application | FastAPI setup and configuration |
| `routes/` | Endpoints | API route handlers |
| `websocket.py` | WebSocket | Real-time communication |

**API Design Principles:**
- RESTful resource naming
- Consistent response format
- Pagination for list endpoints
- Query parameter filtering
- Proper HTTP status codes

### WebSocket Manager

**Location:** `netsentinel/api/websocket.py`

Manages real-time bidirectional communication with dashboard clients.

**Features:**
- Channel-based subscription system
- Automatic reconnection handling
- Message queuing for offline clients
- Broadcast to multiple clients

### Plugin System

**Location:** `netsentinel/plugins/`

Extensible architecture for custom analysis modules.

| Component | File | Purpose |
|-----------|------|---------|
| `BasePlugin` | `base.py` | Abstract plugin interface |
| `Loader` | `loader.py` | Auto-discovery and loading |

**Plugin Lifecycle:**
```
Discovery → Loading → Registration → Initialization → Processing → Cleanup
```

### Dashboard

**Location:** `dashboard/`

React single-page application with real-time updates.

| Component | Purpose |
|-----------|---------|
| `App.jsx` | Main application shell |
| `pages/` | Page components |
| `components/` | Reusable UI components |
| `hooks/` | Custom React hooks |
| `utils/` | Utility functions |

**Features:**
- Real-time WebSocket updates
- Responsive design (Tailwind CSS)
- Interactive charts (Chart.js)
- Dark/light theme support

### CLI

**Location:** `netsentinel/cli/`

Command-line interface built with Typer and Rich.

**Commands:**
| Command | Description |
|---------|-------------|
| `start` | Start the application |
| `dashboard` | Open dashboard in browser |
| `capture` | Capture packets |
| `report` | Generate reports |
| `devices` | List devices |
| `alerts` | View alerts |
| `stats` | Show statistics |
| `export` | Export data |
| `interfaces` | List interfaces |
| `update` | Update configuration |

### Report Generator

**Location:** `netsentinel/reports/`

Generates reports in multiple formats.

| Format | File | Description |
|--------|------|-------------|
| HTML | `html.py` | Interactive HTML reports |
| PDF | `pdf.py` | Print-ready PDF reports |
| JSON | `json.py` | Machine-readable exports |
| CSV | `csv.py` | Spreadsheet-compatible exports |

## Data Flow Diagrams

### Packet Capture Flow

```
┌──────────────┐
│   Network    │
│   Interface  │
└──────┬───────┘
       │ Raw Packets
       ▼
┌──────────────┐
│    Scapy     │
│    Sniff     │
└──────┬───────┘
       │ Packet Objects
       ▼
┌──────────────┐
│   Packet     │
│   Queue      │
└──────┬───────┘
       │
       ├───────────────────┐
       │                   │
       ▼                   ▼
┌──────────────┐    ┌──────────────┐
│   Protocol   │    │    Raw       │
│   Parsers    │    │    Store     │
└──────┬───────┘    └──────────────┘
       │ Parsed Data
       ▼
┌──────────────┐
│   Analysis   │
│   Modules    │
└──────┬───────┘
       │ Insights
       ├───────────────────┐
       │                   │
       ▼                   ▼
┌──────────────┐    ┌──────────────┐
│   Database   │    │   Alerts     │
│   Storage    │    │  Generator   │
└──────┬───────┘    └──────┬───────┘
       │                   │
       └─────────┬─────────┘
                 │
                 ▼
        ┌──────────────┐
        │   WebSocket  │
        │   Broadcast  │
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │  Dashboard   │
        │   Clients    │
        └──────────────┘
```

### API Request Flow

```
┌──────────────┐
│    Client    │
│  (Browser/   │
│   CLI)       │
└──────┬───────┘
       │ HTTP Request
       ▼
┌──────────────┐
│   FastAPI    │
│   Router     │
└──────┬───────┘
       │
       ├─── Authentication Middleware ───┐
       │                                │
       ▼                                ▼
┌──────────────┐                 ┌──────────────┐
│   Route      │                 │   401/403    │
│   Handler    │                 │   Response   │
└──────┬───────┘                 └──────────────┘
       │
       ▼
┌──────────────┐
│  Database    │
│   Query      │
└──────┬───────┘
       │ Results
       ▼
┌──────────────┐
│  Response    │
│  Formatting  │
└──────┬───────┘
       │ JSON Response
       ▼
┌──────────────┐
│    Client    │
└──────────────┘
```

### Plugin Loading Flow

```
┌──────────────┐
│   Startup    │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Scan       │
│   plugins/   │
│   directory  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Load       │
│   Plugin     │
│   Manifests  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Validate   │
│   Plugin     │
│   Structure  │
└──────┬───────┘
       │
       ├───────────────┐
       │               │
       ▼               ▼
┌──────────────┐ ┌──────────────┐
│   Register   │ │   Skip       │
│   Plugin     │ │   (Invalid)  │
└──────┬───────┘ └──────────────┘
       │
       ▼
┌──────────────┐
│   Initialize │
│   Plugin     │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Ready for  │
│   Processing │
└──────────────┘
```

## Class Hierarchy

```
BaseParser
├── TCPParser
├── UDPParser
├── ICMPParser
├── DNSParser
├── TLSParser
└── HTTPParser

BaseAnalyzer
├── TrafficAnalyzer
├── DNSAnalyzer
├── TLSAnalyzer
├── AlertGenerator
└── AnomalyDetector

BasePlugin
├── CustomDNSMonitor
├── BandwidthAlert
└── [User Plugins...]

BaseModel (Pydantic)
├── DeviceInfo
├── TrafficFlow
├── DNSQuery
├── TLSSession
└── Alert
```

## Threading Model

```
┌─────────────────────────────────────────────────────────────────┐
│                        Main Thread                              │
│                     (Event Loop)                                │
└───────────────┬─────────────────────────────────────────────────┘
                │
    ┌───────────┴───────────┐
    │                       │
    ▼                       ▼
┌──────────────┐     ┌──────────────┐
│  API Server  │     │   Capture    │
│   (FastAPI)  │     │   Engine     │
│  [Thread]    │     │  [Thread]    │
└──────┬───────┘     └──────┬───────┘
       │                    │
       │                    ├──────────────────────┐
       │                    │                      │
       │                    ▼                      ▼
       │            ┌──────────────┐      ┌──────────────┐
       │            │   Packet     │      │   Analysis   │
       │            │   Queue      │      │   Workers    │
       │            │  [Queue]     │      │ [4 Threads]  │
       │            └──────────────┘      └──────────────┘
       │
       ├──────────────────────┐
       │                      │
       ▼                      ▼
┌──────────────┐      ┌──────────────┐
│  WebSocket   │      │   Plugin     │
│   Manager    │      │   Workers    │
│  [Thread]    │      │ [2 Threads]  │
└──────────────┘      └──────────────┘
```

**Thread Pool Configuration:**

| Thread | Count | Purpose |
|--------|-------|---------|
| Main | 1 | Event loop management |
| API | 1 | FastAPI server |
| Capture | 1 | Packet sniffing |
| Analysis | 4 | Packet processing |
| WebSocket | 1 | Client communication |
| Plugin | 2 | Plugin processing |
| **Total** | **10** | |

## Database Schema (ER Diagram)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SQLite Database                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐         ┌─────────────────┐                          │
│  │     devices     │         │  traffic_flows   │                          │
│  ├─────────────────┤         ├─────────────────┤                          │
│  │ PK id           │◄────┐   │ PK id           │                          │
│  │    mac (UNIQUE) │     │   │ FK src_mac ─────┤                          │
│  │    ip           │     ├───│    src_ip       │                          │
│  │    hostname     │     │   │    dst_ip       │                          │
│  │    vendor       │     │   │    src_port     │                          │
│  │    first_seen   │     │   │    dst_port     │                          │
│  │    last_seen    │     │   │    protocol     │                          │
│  │    is_active    │     │   │    bytes_sent   │                          │
│  └─────────────────┘     │   │    bytes_recv   │                          │
│                          │   │    first_seen   │                          │
│                          │   │    last_seen    │                          │
│                          │   │    duration     │                          │
│                          │   └─────────────────┘                          │
│                          │                                                  │
│  ┌─────────────────┐    │   ┌─────────────────┐                          │
│  │   dns_queries   │    │   │  tls_sessions   │                          │
│  ├─────────────────┤    │   ├─────────────────┤                          │
│  │ PK id           │    │   │ PK id           │                          │
│  │ FK src_mac ─────┤    │   │ FK src_mac ─────┤                          │
│  │    src_ip       │    │   │    src_ip       │                          │
│  │    query_name   │    │   │    dst_ip       │                          │
│  │    query_type   │    │   │    dst_port     │                          │
│  │    response_code│    │   │    sni          │                          │
│  │    answers      │    │   │    issuer       │                          │
│  │    timestamp    │    │   │    subject      │                          │
│  └─────────────────┘    │   │    not_before   │                          │
│                         │   │    not_after    │                          │
│                         │   │    version      │                          │
│                         │   │    cipher_suite │                          │
│                         │   │    timestamp    │                          │
│                         │   └─────────────────┘                          │
│                         │                                                  │
│  ┌─────────────────┐    │   ┌─────────────────┐                          │
│  │     alerts      │    │   │ bandwidth_stats  │                          │
│  ├─────────────────┤    │   ├─────────────────┤                          │
│  │ PK id           │    │   │ PK id           │                          │
│  │    type         │    │   │    interface    │                          │
│  │    severity     │    │   │    bytes_in     │                          │
│  │ FK src_mac ─────┤────┘   │    bytes_out    │                          │
│  │    source_ip    │        │    timestamp    │                          │
│  │    dest_ip      │        └─────────────────┘                          │
│  │    message      │                                                      │
│  │    details      │                                                      │
│  │    acknowledged │                                                      │
│  │    timestamp    │                                                      │
│  └─────────────────┘                                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

Legend:
  PK = Primary Key
  FK = Foreign Key
  ─── = Relationship
```

## Security Considerations

### Network Security

| Concern | Mitigation |
|---------|------------|
| Packet capture requires root | Use capabilities or dedicated user |
| API authentication | JWT with expiration |
| WebSocket connections | Token validation on connect |
| Data in transit | HTTPS/TLS for API (production) |

### Data Security

| Concern | Mitigation |
|---------|------------|
| Sensitive data storage | Encrypt PII fields at rest |
| Database access | File permissions (0600) |
| Log files | Rotate and restrict access |
| Exports | Sanitize sensitive data |

### Access Control

| Layer | Control |
|-------|---------|
| CLI | System user permissions |
| API | JWT authentication |
| Database | File system permissions |
| Network | Interface-based capture limits |

## Performance Considerations

### Capture Performance

| Metric | Target | Optimization |
|--------|--------|--------------|
| Packets/sec | 100,000+ | Zero-copy capture |
| Latency | <1ms | Async processing |
| Memory | <512MB | Ring buffer |
| CPU | <50% | Multi-threaded |

### Database Performance

| Metric | Target | Optimization |
|--------|--------|--------------|
| Write throughput | 10,000/sec | Batch inserts |
| Read latency | <10ms | Indexed queries |
| Database size | <10GB | Auto-vacuum |
| Concurrent reads | 100+ | WAL mode |

### API Performance

| Metric | Target | Optimization |
|--------|--------|--------------|
| Response time | <100ms | Query optimization |
| Throughput | 1,000 req/sec | Connection pooling |
| WebSocket | 100 clients | Message batching |

### Memory Management

```
┌─────────────────────────────────────────────────────────────────┐
│                     Memory Layout                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Python Process                          │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │   │
│  │  │  Heap    │  │   Stack  │  │  I/O     │             │   │
│  │  │  (256MB) │  │  (8MB)   │  │  Buffer  │             │   │
│  │  │          │  │          │  │  (32MB)  │             │   │
│  │  └──────────┘  └──────────┘  └──────────┘             │   │
│  └─────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Shared Memory                           │   │
│  │  ┌──────────────────────────────────────────────────┐  │   │
│  │  │              Packet Ring Buffer                   │  │   │
│  │  │                    (64MB)                         │  │   │
│  │  └──────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Scaling Considerations

| Scale | Strategy |
|-------|----------|
| Single host | Current architecture |
| Multiple interfaces | Parallel capture engines |
| High throughput | Distributed capture agents |
| Long-term storage | Database archiving |
| Multiple users | Connection pooling |
