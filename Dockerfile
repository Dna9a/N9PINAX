# ── Build stage ────────────────────────────────────────────────────────────────
FROM python:3.14-slim AS build

WORKDIR /app

# Install build deps for bcrypt / cryptography native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/requirements.txt requirements/requirements-web.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt -r requirements-web.txt

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.14-slim

WORKDIR /app

# libpcap  — required by Scapy for raw packet capture
# iproute2 — provides 'ip' for network auto-detection
# libcap2-bin — provides setcap so we can grant CAP_NET_RAW to the Python
#               binary without running the whole container as root
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iproute2 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from build stage
COPY --from=build /usr/local/lib/python3.14 /usr/local/lib/python3.14
COPY --from=build /usr/local/bin /usr/local/bin

# Copy application source.
# The shipped UI is the "Frontend  2" directory (note: two spaces). It is
# copied to ./frontend/ so backend.app's _FRONTEND_DIR (=../frontend) serves it.
COPY scanner/ ./scanner/
COPY backend/  ./backend/
COPY ["Frontend  2/", "./frontend/"]

# Create data directory for SQLite and reports
RUN mkdir -p /data

# Run as non-root by default.
RUN adduser --disabled-password --gecos '' scanner \
    && chown -R scanner:scanner /app /data

# Grant CAP_NET_RAW + CAP_NET_ADMIN as file capabilities on the Python binary.
# docker-compose.yml adds these caps to the container's bounding set via cap_add,
# but for non-root processes they only become effective when set on the file itself.
# This lets the 'scanner' user open raw sockets (ARP/ICMP/SYN) without UID 0.
RUN setcap 'cap_net_raw,cap_net_admin+eip' /usr/local/bin/python3.14

USER scanner

ENV SCANNER_DB_PATH=/data/scans.db
ENV SCANNER_REPORT_PATH=/data/scan_report.txt
ENV SCANNER_LOG_PATH=/data/scanner.log
ENV SCANNER_API_HOST=0.0.0.0
ENV SCANNER_API_PORT=8000

EXPOSE 8000

CMD ["uvicorn", "backend.app:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--log-level", "info"]
