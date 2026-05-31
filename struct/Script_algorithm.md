```
scanner/
├── core/
│   ├── arp_scan.py
│   ├── icmp_scan.py
│   ├── port_scan.py
│   ├── syn_scan.py
│   └── udp_scan.py
│
├── fingerprint/
│   ├── dhcp_fingerprint.py
│   ├── hostname.py
│   ├── http_banner.py
│   ├── mac_lookup.py
│   ├── os_classifier.py
│   └── tcp_fingerprint.py
│
├── alerts.py
├── config.py
├── main.py
├── models.py
├── report.py
└── storage.py

backend/
├── app.py
├── events.py
├── rate_limit.py
├── scan_service.py
└── schemas.py

frontend/
└── index.html

tests/
├── test_alerts.py
├── test_core.py
├── test_mac_lookup.py
├── test_models.py
├── test_phase1_fixes.py
├── test_report.py
└── test_storage.py
```

```markdown
projet/
├── scanner/          # Core scanning logic (Python/Scapy)
├── backend/          # API & WebSocket server (Flask/SocketIO)
├── frontend/         # UI (HTML/JS)
├── tests/            # Test suite
├── docker-compose.yml
├── Dockerfile
├── Makefile
├── requirements.txt
└── deploy.sh


scanner/
│
├── main.py                  # Orchestrator
│
├── core/                    # Base network functions
│   ├── arp_scan.py          # Host discovery (ARP)
│   ├── icmp_scan.py         # Ping discovery
│   ├── port_scan.py         # TCP Port scanning
│   ├── syn_scan.py          # Stealth SYN scanning
│   └── udp_scan.py          # UDP Port scanning
│
├── fingerprint/             # Advanced identification
│   ├── dhcp_fingerprint.py  # DHCP options → device type
│   ├── hostname.py          # DNS/mDNS/LLMNR resolution
│   ├── http_banner.py       # HTTP headers identification
│   ├── mac_lookup.py        # MAC → Vendor (OUI)
│   ├── os_classifier.py     # Final OS/Device verdict
│   └── tcp_fingerprint.py   # TTL + TCP options → OS
│
├── alerts.py                # Alerting logic
├── config.py                # Scanner configuration
├── models.py                # Pydantic models (Device, Port, etc.)
├── report.py                # Report generation
└── storage.py               # SQLite persistence

backend/
│
├── app.py                   # Flask application entry
├── events.py                # WebSocket events
├── rate_limit.py            # API rate limiting
├── scan_service.py          # Async scan management
└── schemas.py               # API request/response schemas
```

## Algo of key files

### models.py
Defines the shared data structures (Pydantic):
- **Device**: IP, MAC, vendor, hostname, ports, status, timestamps, OS fingerprint.
- **Port**: Number, state, service, banner.

### arp_scan.py
- **Input**: Target network (e.g., "192.168.1.0/24").
- **Process**: Sends ARP "who-has" requests via Ethernet broadcast.
- **Output**: List of discovered `Device` objects with IP and MAC.

### icmp_scan.py
- **Process**: Sends ICMP Echo requests (Ping).
- **Target**: Used as fallback or alternative discovery when ARP is restricted.

### port_scan.py / syn_scan.py
- **Process**: Parallel TCP connection attempts or SYN packets to identify open ports.
- **Services**: Maps common ports (22, 80, 443, etc.) to expected services.

### mac_lookup.py
- **Process**: Extracts first 3 bytes (OUI) of the MAC and matches against the IEEE database.
- **Data**: Uses local `oui.txt` or API lookup.

### os_classifier.py
- **Process**: Aggregates data from MAC, TCP (TTL/Window size), HTTP banners, and DHCP to provide a weighted OS guess.

### storage.py
- **Engine**: SQLite.
- **Persistence**: Handles saving scan results and retrieving historical device data for change detection.

### scan_service.py (Backend)
- **Logic**: Orchestrates the scanner from the API, managing background threads and sending real-time updates via SocketIO.

### Dockerfile / docker-compose.yml
- **Dockerfile**: Multi-stage build that installs system dependencies (`libpcap`, `iproute2`), sets up the Python environment, and runs the Uvicorn server.
- **docker-compose.yml**: Manages the container lifecycle, injects environment variables, and critically grants `NET_ADMIN` + `NET_RAW` capabilities required for Scapy to perform raw packet operations (ARP/SYN scans).

### Tests (tests/ folder)
- **test_core.py**: Validates network discovery mechanisms (ARP, ICMP, Port scanning).
- **test_models.py**: Ensures data integrity and validation via Pydantic models.
- **test_storage.py**: Tests SQLite database operations, persistence, and retrieval.
- **test_alerts.py / test_report.py**: Verifies the alerting logic and report generation output.
- **test_mac_lookup.py**: Validates the OUI vendor resolution logic.
