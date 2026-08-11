## *This project has been created as part of the ISTA curriculum a fucked up curriculum.* 

<!-- 9sem -->
<div style="display: flex; justify-content: space-between; align-items: center;">
  <span style="font-size: 45px;">📄</span>
  <span style="font-size: 40px;">🐪</span>
</div>

<p align="center">
  <img src="assets/banner.png" alt="N9PINAX banner" width="100%"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/self--hosted-N9PINAX-e8761a?style=flat-square&labelColor=0f0b06&color=e8761a" alt="Self-Hosted"/>
  <img src="https://img.shields.io/badge/language-Python-f5a040?style=flat-square&labelColor=0f0b06&color=f5a040" alt="Python"/>
  <img src="https://img.shields.io/badge/container-Docker-6a8840?style=flat-square&labelColor=0f0b06&color=6a8840" alt="Docker"/>
  <img src="https://img.shields.io/badge/license-MIT-c44a1a?style=flat-square&labelColor=0f0b06&color=c44a1a" alt="MIT License"/>
  <img src="https://img.shields.io/badge/dashboard-WebSocket-e8761a?style=flat-square&labelColor=0f0b06&color=e8761a" alt="WebSocket"/>
  <img src="https://img.shields.io/badge/alerts-real--time-f5a040?style=flat-square&labelColor=0f0b06&color=f5a040" alt="Real-Time Alerts"/>
</p>

<p align="center">
  <em>A self-hosted network security monitoring and asset discovery platform built around SIEM principles.</em>
</p>

## 📑 Table of Contents

- [Description](#-description)
- [Tech Stack](#-tech-stack)
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [How to Use the Scan Feature](#-how-to-use-the-scan-feature)
- [Default Credentials](#-default-credentials)
- [Architecture](#-architecture)
- [Demo](#-demo)
- [Security Warning](#-security-warning)

---

## Description

> N9pinax is a self-hosted network security monitoring and asset discovery platform built around SIEM principles. It automatically discovers devices on a local network using ARP, ICMP, TCP SYN, and UDP probes, then enriches collected data with vendor identification, operating system fingerprinting, device classification, and hostname resolution. The platform continuously analyzes the network environment, generates rule-based security alerts, and streams results in real time to an interactive web dashboard, providing comprehensive visibility into network assets and potential security risks.

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI + SSE (Server-Sent Events) |
| Scanner engine | Scapy (raw sockets) |
| Frontend | Vanilla JS + HTML |
| Cache | Redis |
| Storage | SQLite |
| Deployment | Docker + Docker Compose |

---

## ✨ Features

- **Automated Asset Discovery** — ARP, ICMP, TCP SYN, and UDP probes sweep the network automatically. No config needed beyond a target CIDR range.
- **Data Enrichment** — Every asset gets vendor ID via OUI lookup, OS fingerprinting via TCP/IP stack analysis, device classification, and hostname resolution.
- **Real-Time Analysis** — Continuous rule-based alert engine fires on anomalies, new devices, port exposures, and behavioral patterns — streamed live via SSE.
- **Interactive Web Dashboard** — Live UI for asset visualization, alert monitoring, and network activity. Built-in filtering, search, and device detail panels.
- **Reports & Export** — Generate and export scan reports directly from the dashboard.
- **Self-Hosted** — Your data never leaves your network. Full control, full customization. No cloud dependency.

---

## 🔧 Prerequisites
- Linux (or Windows WSL2) — raw packet scanning requires a Linux network stack
- Docker 24+ and Docker Compose v2 (its okey if not) 
- Root / sudo privileges for scanning operations

---

## 🐪 Installation

> [!WARNING]
> N9pinax performs active network scanning using raw packets. Only run it on networks you own or have explicit permission to scan. Unauthorized network scanning may be illegal in your jurisdiction.

1. Clone the repository:
```bash
git clone https://github.com/Dna9a/N9PINAX.git
```

2. Navigate to the project directory:
```bash
cd N9PINAX
```

3. Install dependencies and start the platform:
```bash
make start
```

4. Access the web dashboard at :
```shell
# open in web browser
http://localhost:8000
http://<your-server-ip>:8000
```

> **Note**: N9pinax requires root/administrator privileges to perform raw packet scanning (ARP, TCP SYN, ICMP probes).

---

## How to Use the Scan Feature

1. Log in at `http://localhost:8000` with `na9a / 1234`.
2. Navigate to **Scan** in the sidebar.
3. Optionally enter a CIDR range (e.g. `192.168.1.0/24`). Leave blank for auto-detect.
4. Enable optional probes as needed: **Resolve hostnames**, **UDP probes**, **Passive DHCP fingerprint**.
5. Click **Start Scan**.
6. Watch the **Live Device Feed** populate in real time as devices are discovered, and the **Scan Log** for step-by-step output.
7. When the scan completes, the summary card shows hosts found, duration, and alert count.
8. Click **View Devices** to inspect the full device inventory with risk badges and expandable port details.

---

## Environment Variables

Copy `.env.example` to `.env` and adjust for production.

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_JWT_SECRET` | *(required in production)* | JWT signing secret — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `SCANNER_API_HOST` | `0.0.0.0` | Address the uvicorn server binds to |
| `SCANNER_API_PORT` | `8000` | Port the API listens on |
| `SCANNER_API_CORS` | `*` | CORS allowed origins — comma-separated list or `*` |
| `SCANNER_DB_PATH` | `/data/scans.db` | SQLite database path (inside container) |
| `SCANNER_REPORT_PATH` | `/data/scan_report.txt` | Plain-text report path |
| `SCANNER_LOG_PATH` | `/data/scanner.log` | Scanner log path |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection URL (optional — app runs without it) |
| `SCANNER_PORT_TIMEOUT` | `0.5` | Per-port TCP connect timeout (seconds) |
| `SCANNER_MAX_WORKERS_PORTS` | `50` | Concurrent port-scan threads per host |
| `SCANNER_RATE_LIMIT_PPS` | `500` | Outbound packets per second (IDS noise reduction) |
| `SCANNER_ALERTS` | `true` | Enable the SIEM alert engine |
| `SCANNER_DHCP` | `false` | Enable passive DHCP fingerprinting |
| `SCANNER_KEEP_LAST_N_SCANS` | `200` | Max scans retained in the database |


### Example `.env`

```env
SCANNER_JWT_SECRET=your_generated_secret_here
SCANNER_API_HOST=0.0.0.0
SCANNER_API_PORT=8000
SCANNER_API_CORS=*
SCANNER_DB_PATH=/data/scans.db
SCANNER_REPORT_PATH=/data/scan_report.txt
SCANNER_LOG_PATH=/data/scanner.log
REDIS_URL=redis://redis:6379/0
SCANNER_PORT_TIMEOUT=0.5
SCANNER_MAX_WORKERS_PORTS=50
SCANNER_RATE_LIMIT_PPS=500
SCANNER_ALERTS=true
SCANNER_DHCP=false
SCANNER_KEEP_LAST_N_SCANS=200
```

---

## Make Commands

| Command | Description |
|---------|-------------|
| `make up` | Build images (if needed) and start all containers in detached mode |
| `make down` | Stop and remove containers |
| `make restart` | `down` + `up` in one command |
| `make logs` | Tail live logs from all containers |
| `make build` | Force rebuild all Docker images without cache |
| `make status` | Show container status and exposed ports |
| `make uninstall` | Full removal: containers, images, volumes, networks, project directory (prompts for confirmation) |
| `make start` | Bootstrap: install Docker if needed, then build and launch (via `deploy.sh`) |
| `make test` | Run the full pytest suite |
| `make lint` | Run flake8 + mypy static analysis |
| `make fmt` | Format code with black + isort |
| `make clean` | Remove Python caches, `.pyc` files, build artifacts |
| `make clean-all` | Full clean including virtualenv |
| `make run-backend` | Start FastAPI backend locally (no Docker) on `0.0.0.0:8000` |
| `make run-backend-reload` | Same as above with `--reload` for development |
| `make help` | Show all commands with descriptions |

---

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| `na9a` | `1234` | admin |

Change via **Admin → Users** after first login.

---

## Architecture
N9pinax is built using a modular architecture that separates the core components responsible for asset discovery, enrichment, analysis, and visualization. The main components include:
 
- **Scanner** — Performs network scans using ARP, ICMP, TCP SYN, and UDP probes to discover devices on the local network. Requires root privileges for raw socket access.
- **Backend** — FastAPI service handling data enrichment, alert generation, and SSE streaming. Processes raw scan data, enriches it with fingerprinting results, and applies rule-based SIEM logic to identify potential security issues.
- **Frontend** — Static web dashboard built with Vanilla JS. Communicates with the backend via SSE for real-time updates. Provides device inventory, alert monitoring, scan controls, and export functionality.
- **Docker** — The entire platform is containerized using Docker Compose, separating the scanner (privileged, host network) from the API (unprivileged) for proper security isolation.

![Architecture](assets/architecture.png)

```
n9pinax/
├── backend/                     # Backend FastAPI REST + SSE API
│   ├── app.py                   # API routes, authentication, static UI serving
│   ├── scan_service.py          # Scan orchestration + SSE events
│   ├── events.py                # In-memory event bus for inter-component communication
│   └── ...                      # serializers, schemas, rate limiting, Redis cache
├── scanner/                     # Scanning engine and packet handling (requires root privileges)
│   ├── core/                    # ARP / ICMP / SYN / UDP probes and packet handling
│   ├── fingerprint/             # vendor / OS / device fingerprinting
│   ├── alerts.py                # SIEM rules and alert generation
│   ├── report.py                # report/export generation
│   ├── storage.py               # SQLite persistence
│   └── ...                      # models, utilities
├── Frontend/                     # Static UI
│   ├── pages/                   # HTML pages (scan, devices, alerts, reports, admin, notes)
│   ├── js/                      # UI logic, API helpers, SSE handling
│   ├── css/                     # layout styles
│   └── styles/                  # theme and component styles
├── Docker/                      # Deployment
│   ├── Dockerfile               # Application image build
│   ├── docker-compose.yml       # Service orchestration (API, Redis)
│   ├── .env                     # Environment configuration template
│   └── ...                      # deployment scripts
```

---

## 🎬 Demo

> Screenshot or GIF of the dashboard goes here.
> Record with [Kooha](https://github.com/SeaDve/Kooha) (Linux) or [ShareX](https://getsharex.com/) (Windows), export as GIF, and drop in `assets/demo.gif`.

```markdown
![Dashboard demo](assets/demo.gif)
```

---

## 🔒 Security Warning

> [!WARNING]
> N9pinax uses raw packet techniques (ARP spoofing detection, TCP SYN probes, ICMP sweeps) that may trigger IDS/IPS systems on your network. It is intended for use by network administrators on infrastructure they own or manage. **Do not run this tool on networks without explicit authorization.** The authors take no responsibility for misuse.

---

> [!WARNING]
> THIS README IS STILL UNDER CONSTRUCTION 
> ![Builder](https://github.com/Dna9a/Repo-s_assets/blob/main/B2R/lbenay.gif)


<!-- <p align="center">
  <em>Made with <a href="https://your-link.com">Dbvonie</a> as part of the PFE for the fucked up ISTA curriculum</em>
</p> -->

<p align="center">
  <em>Made with <a href="https://github.com/Dbvonie"><span style="color:#ff69b4;">Dbvonie</span></a> as part of the PFE for the fucked up ISTA curriculum</em>
</p>

