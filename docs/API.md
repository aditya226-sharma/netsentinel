# API Documentation

## Base URL

```
http://localhost:8000
```

## Authentication

NetSentinel uses JWT (JSON Web Token) for API authentication.

### Obtaining a Token

```bash
POST /api/auth/token
Content-Type: application/json

{
    "username": "admin",
    "password": "your_password"
}
```

**Response:**
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer"
}
```

### Using the Token

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/devices
```

### Token Expiration

Tokens expire after 24 hours. Use the refresh endpoint:

```bash
POST /api/auth/refresh
Authorization: Bearer <token>
```

---

## Device Endpoints

### GET /api/devices

List all discovered network devices.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| active | bool | true | Show only active devices |
| page | int | 1 | Page number |
| limit | int | 50 | Results per page |

**Response:**
```json
{
    "devices": [
        {
            "id": 1,
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.168.1.100",
            "hostname": "workstation-01",
            "vendor": "Intel Corporation",
            "first_seen": "2024-01-15T10:30:00Z",
            "last_seen": "2024-01-15T14:45:00Z",
            "is_active": true,
            "total_bytes": 104857600,
            "total_packets": 52428
        }
    ],
    "total": 25,
    "page": 1,
    "pages": 1
}
```

### GET /api/devices/{mac}

Get details for a specific device by MAC address.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| mac | string | Device MAC address |

**Response:**
```json
{
    "mac": "AA:BB:CC:DD:EE:FF",
    "ip": "192.168.1.100",
    "hostname": "workstation-01",
    "vendor": "Intel Corporation",
    "first_seen": "2024-01-15T10:30:00Z",
    "last_seen": "2024-01-15T14:45:00Z",
    "is_active": true,
    "protocols": {
        "TCP": 15000,
        "UDP": 8000,
        "DNS": 3000,
        "TLS": 2500
    },
    "top_connections": [
        {
            "dst_ip": "142.250.80.46",
            "dst_port": 443,
            "bytes": 52428800,
            "protocol": "TLS"
        }
    ]
}
```

### GET /api/devices/stats

Get device statistics summary.

**Response:**
```json
{
    "total_devices": 25,
    "active_devices": 18,
    "new_devices_24h": 3,
    "top_talkers": [
        {
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.168.1.100",
            "hostname": "workstation-01",
            "bytes_total": 104857600
        }
    ]
}
```

---

## Traffic Endpoints

### GET /api/traffic/overview

Get traffic overview statistics.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "1h" | Time period (1h, 6h, 24h, 7d) |

**Response:**
```json
{
    "period": "1h",
    "total_bytes_in": 524288000,
    "total_bytes_out": 1048576000,
    "total_packets": 2097152,
    "avg_bandwidth_mbps": 12.5,
    "peak_bandwidth_mbps": 45.2,
    "unique_sources": 15,
    "unique_destinations": 42
}
```

### GET /api/traffic/top-talkers

Get top talkers by bandwidth usage.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "1h" | Time period |
| limit | int | 10 | Number of results |

**Response:**
```json
{
    "top_talkers": [
        {
            "ip": "192.168.1.100",
            "mac": "AA:BB:CC:DD:EE:FF",
            "hostname": "workstation-01",
            "bytes_total": 52428800,
            "bytes_in": 31457280,
            "bytes_out": 20971520,
            "percentage": 28.5
        }
    ]
}
```

### GET /api/traffic/top-destinations

Get top destination IPs.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "1h" | Time period |
| limit | int | 10 | Number of results |

**Response:**
```json
{
    "top_destinations": [
        {
            "ip": "142.250.80.46",
            "port": 443,
            "protocol": "TLS",
            "bytes": 104857600,
            "packets": 52428,
            "percentage": 15.2
        }
    ]
}
```

### GET /api/traffic/flows

Get network flow records.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| src_ip | string | - | Filter by source IP |
| dst_ip | string | - | Filter by destination IP |
| protocol | string | - | Filter by protocol |
| port | int | - | Filter by port |
| period | string | "1h" | Time period |
| limit | int | 100 | Number of results |

**Response:**
```json
{
    "flows": [
        {
            "id": 12345,
            "src_ip": "192.168.1.100",
            "dst_ip": "142.250.80.46",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": 1024,
            "bytes_received": 65536,
            "packets_sent": 10,
            "packets_received": 45,
            "duration": 12.5,
            "first_seen": "2024-01-15T10:30:00Z",
            "last_seen": "2024-01-15T10:30:12Z"
        }
    ],
    "total": 500
}
```

---

## DNS Endpoints

### GET /api/dns/queries

Get DNS query log.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| src_ip | string | - | Filter by source IP |
| domain | string | - | Filter by domain (partial match) |
| query_type | string | - | Filter by query type (A, AAAA, MX, etc.) |
| period | string | "1h" | Time period |
| limit | int | 100 | Number of results |

**Response:**
```json
{
    "queries": [
        {
            "id": 5678,
            "src_ip": "192.168.1.100",
            "query_name": "www.example.com",
            "query_type": "A",
            "response_code": "NOERROR",
            "answers": ["93.184.216.34"],
            "timestamp": "2024-01-15T10:30:00Z"
        }
    ],
    "total": 1250
}
```

### GET /api/dns/stats

Get DNS statistics.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "1h" | Time period |

**Response:**
```json
{
    "total_queries": 12500,
    "unique_domains": 342,
    "query_types": {
        "A": 8000,
        "AAAA": 2000,
        "CNAME": 1500,
        "MX": 500,
        "TXT": 300,
        "PTR": 200
    },
    "response_codes": {
        "NOERROR": 11000,
        "NXDOMAIN": 1200,
        "SERVFAIL": 200,
        "REFUSED": 100
    },
    "avg_response_time_ms": 15.2
}
```

### GET /api/dns/top-domains

Get most queried domains.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "1h" | Time period |
| limit | int | 10 | Number of results |

**Response:**
```json
{
    "top_domains": [
        {
            "domain": "google.com",
            "query_count": 2500,
            "unique_clients": 15,
            "query_types": ["A", "AAAA", "CNAME"]
        },
        {
            "domain": "cloudflare.com",
            "query_count": 1800,
            "unique_clients": 12,
            "query_types": ["A", "AAAA"]
        }
    ]
}
```

### GET /api/dns/errors

Get DNS errors and anomalies.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "1h" | Time period |
| error_type | string | - | Filter by error type |

**Response:**
```json
{
    "errors": [
        {
            "src_ip": "192.168.1.105",
            "query_name": "suspicious-domain.xyz",
            "query_type": "A",
            "response_code": "NXDOMAIN",
            "timestamp": "2024-01-15T10:30:00Z",
            "reason": "Domain not found"
        }
    ],
    "summary": {
        "total_errors": 150,
        "nxdomain": 100,
        "servfail": 30,
        "refused": 20
    }
}
```

---

## TLS Endpoints

### GET /api/tls/sessions

Get TLS session information.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| src_ip | string | - | Filter by source IP |
| sni | string | - | Filter by SNI (partial match) |
| expired | bool | - | Filter expired certificates |
| period | string | "1h" | Time period |
| limit | int | 100 | Number of results |

**Response:**
```json
{
    "sessions": [
        {
            "id": 9012,
            "src_ip": "192.168.1.100",
            "dst_ip": "142.250.80.46",
            "dst_port": 443,
            "sni": "www.google.com",
            "issuer": "GTS CA 1C3",
            "subject": "www.google.com",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2024-03-31T23:59:59Z",
            "version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "is_expired": false,
            "timestamp": "2024-01-15T10:30:00Z"
        }
    ],
    "total": 850
}
```

### GET /api/tls/stats

Get TLS statistics.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "1h" | Time period |

**Response:**
```json
{
    "total_sessions": 8500,
    "tls_versions": {
        "TLSv1.3": 6000,
        "TLSv1.2": 2500
    },
    "top_ciphers": [
        {
            "cipher": "TLS_AES_256_GCM_SHA384",
            "count": 3500
        },
        {
            "cipher": "TLS_AES_128_GCM_SHA256",
            "count": 2500
        }
    ],
    "expired_certificates": 5,
    "self_signed_certificates": 2
}
```

### GET /api/tls/expired

Get sessions with expired certificates.

**Response:**
```json
{
    "expired": [
        {
            "id": 9012,
            "src_ip": "192.168.1.105",
            "dst_ip": "192.168.1.200",
            "sni": "internal.local",
            "issuer": "Self-Signed",
            "subject": "internal.local",
            "not_after": "2023-12-31T23:59:59Z",
            "days_expired": 15,
            "timestamp": "2024-01-15T10:30:00Z"
        }
    ],
    "count": 5
}
```

---

## Alert Endpoints

### GET /api/alerts

Get security alerts.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| severity | string | - | Filter by severity (low, medium, high, critical) |
| type | string | - | Filter by alert type |
| acknowledged | bool | - | Filter by acknowledgment status |
| limit | int | 50 | Number of results |
| offset | int | 0 | Result offset |

**Response:**
```json
{
    "alerts": [
        {
            "id": 1,
            "type": "port_scan",
            "severity": "high",
            "source_ip": "10.0.0.100",
            "destination_ip": "192.168.1.0/24",
            "message": "Port scan detected from 10.0.0.100",
            "details": "Scanned 256 ports in 60 seconds",
            "acknowledged": false,
            "timestamp": "2024-01-15T10:30:00Z"
        }
    ],
    "total": 45,
    "unacknowledged": 12
}
```

### GET /api/alerts/stats

Get alert statistics.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "24h" | Time period |

**Response:**
```json
{
    "total_alerts": 150,
    "by_severity": {
        "critical": 5,
        "high": 25,
        "medium": 60,
        "low": 60
    },
    "by_type": {
        "port_scan": 30,
        "suspicious_dns": 45,
        "tls_anomaly": 20,
        "bandwidth_spike": 25,
        "new_device": 30
    },
    "timeline": [
        {
            "timestamp": "2024-01-15T10:00:00Z",
            "count": 15
        }
    ]
}
```

---

## Statistics Endpoints

### GET /api/stats/overview

Get overall network statistics.

**Response:**
```json
{
    "uptime": 86400,
    "packets_captured": 10485760,
    "bytes_captured": 5242880000,
    "active_flows": 250,
    "devices": {
        "total": 25,
        "active": 18
    },
    "alerts": {
        "total": 150,
        "unacknowledged": 12
    },
    "capture_interface": "eth0",
    "capture_status": "running"
}
```

### GET /api/stats/bandwidth

Get bandwidth statistics over time.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "1h" | Time period |
| interval | string | "1m" | Data interval (1m, 5m, 15m, 1h) |

**Response:**
```json
{
    "period": "1h",
    "interval": "1m",
    "data": [
        {
            "timestamp": "2024-01-15T10:00:00Z",
            "bytes_in": 1048576,
            "bytes_out": 2097152,
            "bandwidth_mbps": 2.0
        }
    ],
    "summary": {
        "avg_in_mbps": 5.2,
        "avg_out_mbps": 8.5,
        "peak_in_mbps": 45.2,
        "peak_out_mbps": 62.1
    }
}
```

### GET /api/stats/protocols

Get protocol distribution statistics.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "1h" | Time period |

**Response:**
```json
{
    "protocols": [
        {
            "name": "TCP",
            "packets": 5242880,
            "bytes": 3145728000,
            "percentage": 60.5
        },
        {
            "name": "UDP",
            "packets": 2097152,
            "bytes": 1048576000,
            "percentage": 25.2
        },
        {
            "name": "DNS",
            "packets": 524288,
            "bytes": 52428800,
            "percentage": 8.5
        },
        {
            "name": "ICMP",
            "packets": 131072,
            "bytes": 13107200,
            "percentage": 3.2
        },
        {
            "name": "Other",
            "packets": 131072,
            "bytes": 13107200,
            "percentage": 2.6
        }
    ]
}
```

---

## Capture Endpoints

### POST /api/capture/start

Start packet capture on an interface.

**Request Body:**
```json
{
    "interface": "eth0",
    "filter": "tcp port 80 or tcp port 443",
    "max_packets": 10000,
    "promiscuous": true
}
```

**Response:**
```json
{
    "status": "started",
    "interface": "eth0",
    "filter": "tcp port 80 or tcp port 443",
    "capture_id": "cap_20240115_103000"
}
```

### POST /api/capture/stop

Stop the current packet capture.

**Response:**
```json
{
    "status": "stopped",
    "packets_captured": 5242,
    "bytes_captured": 10485760,
    "duration_seconds": 60
}
```

### GET /api/capture/status

Get current capture status.

**Response:**
```json
{
    "status": "running",
    "interface": "eth0",
    "filter": "tcp port 80 or tcp port 443",
    "packets_captured": 5242,
    "bytes_captured": 10485760,
    "start_time": "2024-01-15T10:30:00Z",
    "uptime_seconds": 60
}
```

### GET /api/capture/interfaces

List available network interfaces.

**Response:**
```json
{
    "interfaces": [
        {
            "name": "eth0",
            "description": "Ethernet adapter",
            "addresses": ["192.168.1.10"],
            "mac": "AA:BB:CC:DD:EE:FF",
            "is_up": true,
            "speed_mbps": 1000
        },
        {
            "name": "lo",
            "description": "Loopback",
            "addresses": ["127.0.0.1"],
            "mac": "00:00:00:00:00:00",
            "is_up": true,
            "speed_mbps": 0
        }
    ]
}
```

---

## Export Endpoints

### GET /api/export/json

Export captured data as JSON.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| data_type | string | required | Data type (devices, flows, dns, tls, alerts) |
| period | string | "24h" | Time period |
| limit | int | 10000 | Maximum records |

**Response:** JSON file download

### GET /api/export/csv

Export captured data as CSV.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| data_type | string | required | Data type (devices, flows, dns, tls, alerts) |
| period | string | "24h" | Time period |
| limit | int | 10000 | Maximum records |

**Response:** CSV file download

---

## WebSocket

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');
```

### Events

#### Subscribe to Channel

```json
{
    "action": "subscribe",
    "channel": "capture"
}
```

**Available Channels:**

| Channel | Description |
|---------|-------------|
| `capture` | Real-time packet capture updates |
| `alerts` | New security alerts |
| `devices` | Device discovery events |
| `bandwidth` | Bandwidth statistics updates |

#### Message Format

```json
{
    "channel": "capture",
    "event": "packet",
    "data": {
        "src_ip": "192.168.1.100",
        "dst_ip": "142.250.80.46",
        "protocol": "TCP",
        "src_port": 54321,
        "dst_port": 443,
        "size": 1024
    },
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Alert Event

```json
{
    "channel": "alerts",
    "event": "new",
    "data": {
        "id": 1,
        "type": "port_scan",
        "severity": "high",
        "source_ip": "10.0.0.100",
        "message": "Port scan detected"
    },
    "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid or missing token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 422 | Unprocessable Entity - Validation error |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

### Error Response Format

```json
{
    "error": {
        "code": 404,
        "message": "Device not found",
        "details": "No device found with MAC address XX:XX:XX:XX:XX:XX"
    }
}
```

### Rate Limiting

API requests are limited to 1000 requests per minute per client. Rate limit headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1705312200
```
