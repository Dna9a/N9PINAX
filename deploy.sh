#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# N9pinax — Network Security Scanner  |  Deploy Script
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem
# Usage:
#   ./deploy.sh          →  Docker Compose deployment (recommended)
#   ./deploy.sh --local  →  Local virtualenv deployment (no Docker)
#   ./deploy.sh --stop   →  Stop and remove Docker containers
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

MODE="${1:-docker}"
VENV_DIR="${HOME}/CamelEnv🐪"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Docker / compose commands (may switch to sudo-prefixed after install)
DOCKER_CMD="docker"
COMPOSE_CMD=""

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════╗"
  echo "  ║       N9pinax — Network Security Scanner         ║"
  echo "  ║       PFE Cybersécurité  🐪                      ║"
  echo "  ╚══════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

info()    { echo -e "${CYAN}[→]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

# ─── Detect compose command ───────────────────────────────────────────────────
_find_compose() {
  if ${DOCKER_CMD} compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="${DOCKER_CMD} compose"
  elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
  else
    COMPOSE_CMD=""
  fi
}

# ─── Install Docker ───────────────────────────────────────────────────────────
_install_docker() {
  warn "Docker not found — installing automatically..."

  # Read distro info
  local os_id="" os_like=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    os_id=$(. /etc/os-release && echo "${ID:-}")
    os_like=$(. /etc/os-release && echo "${ID_LIKE:-}")
  fi

  if [[ "${os_id}" == "arch" || "${os_like}" == *"arch"* ]]; then
    # ── Arch Linux ────────────────────────────────────────────────
    info "Detected Arch Linux — installing via pacman..."
    sudo pacman -Sy --noconfirm docker docker-compose 2>/dev/null \
      || sudo pacman -Sy --noconfirm docker 2>/dev/null

  elif [[ "${os_id}" == "ubuntu" || "${os_id}" == "debian" \
       || "${os_like}" == *"debian"* || "${os_like}" == *"ubuntu"* ]]; then
    # ── Debian / Ubuntu ───────────────────────────────────────────
    info "Detected Debian/Ubuntu — installing via official Docker repo..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq ca-certificates curl gnupg lsb-release
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" \
      | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    local codename
    codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${os_id} ${codename} stable" \
      | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
      docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin

  elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then
    # ── RHEL / Fedora / CentOS ────────────────────────────────────
    info "Detected RPM-based distro — using Docker convenience script..."
    curl -fsSL https://get.docker.com | sudo sh

  else
    # ── Fallback: official convenience script ─────────────────────
    info "Unknown distro — using Docker convenience script..."
    if ! command -v curl &>/dev/null; then
      error "curl is required for the convenience script. Install curl and retry."
    fi
    curl -fsSL https://get.docker.com | sudo sh
  fi

  # Start and enable the Docker daemon
  if command -v systemctl &>/dev/null; then
    sudo systemctl enable docker --now 2>/dev/null || true
  elif command -v service &>/dev/null; then
    sudo service docker start 2>/dev/null || true
  fi

  # Add current user to the docker group so future calls don't need sudo
  if id -nG "${USER}" 2>/dev/null | grep -qv docker; then
    sudo usermod -aG docker "${USER}" 2>/dev/null || true
    warn "Added '${USER}' to the docker group."
    warn "For future sessions, log out and back in (or run: newgrp docker)."
  fi

  # For THIS session: if docker still needs root, prefix with sudo
  if ! docker info &>/dev/null 2>&1; then
    DOCKER_CMD="sudo docker"
    warn "Using 'sudo docker' for this session (group change requires re-login)."
  fi

  success "Docker installed: $(${DOCKER_CMD} --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')"
}

# ─── Ensure Docker + Compose are available ────────────────────────────────────
_ensure_docker() {
  if ! command -v docker &>/dev/null; then
    _install_docker
  else
    success "Docker $(docker --version | cut -d' ' -f3 | tr -d ',')"
  fi

  # Check daemon reachability.
  # Priority: unprivileged → sudo (not in group yet) → start daemon → fail.
  if docker info &>/dev/null 2>&1; then
    : # already works without sudo
  elif sudo docker info &>/dev/null 2>&1; then
    # Daemon is up but socket needs root — user not yet in docker group
    DOCKER_CMD="sudo docker"
    warn "Using 'sudo docker' for this session (re-login to use Docker without sudo)."
  else
    # Daemon may be stopped — try to start it
    info "Docker daemon is not responding — starting it..."
    if command -v systemctl &>/dev/null; then
      sudo systemctl start docker 2>/dev/null || true
    elif command -v service &>/dev/null; then
      sudo service docker start 2>/dev/null || true
    fi
    sleep 2
    if docker info &>/dev/null 2>&1; then
      : # now works unprivileged
    elif sudo docker info &>/dev/null 2>&1; then
      DOCKER_CMD="sudo docker"
      warn "Using 'sudo docker' for this session."
    else
      error "Docker daemon is not running. Start it manually: sudo systemctl start docker"
    fi
  fi

  _find_compose
  if [[ -z "${COMPOSE_CMD}" ]]; then
    # Try to install compose plugin
    warn "Docker Compose not found — attempting to install..."
    if [[ "${DOCKER_CMD}" == "sudo docker" ]] || command -v apt-get &>/dev/null; then
      sudo apt-get install -y -qq docker-compose-plugin 2>/dev/null \
        || sudo apt-get install -y -qq docker-compose 2>/dev/null \
        || true
    elif command -v pacman &>/dev/null; then
      sudo pacman -Sy --noconfirm docker-compose 2>/dev/null || true
    fi
    _find_compose
    [[ -z "${COMPOSE_CMD}" ]] && error "Docker Compose not available. Install it and retry."
  fi

  success "Compose: ${COMPOSE_CMD}"
}

# ─── Portable Python bootstrap (local mode) ───────────────────────────────────
# The project targets Python 3.14 but runs on any CPython >= 3.11. Distro
# package managers name the binary differently (python3.14 on deadsnakes/
# Fedora, plain `python` on Arch), so we discover whatever is available rather
# than hardcoding `python3.14` (audit F-121).

# Echo the path of the first suitable Python interpreter (>=3.11), or nothing.
_find_python() {
  local c
  for c in python3.14 python3.13 python3.12 python3.11 python3 python; do
    if command -v "${c}" &>/dev/null && \
       "${c}" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)' &>/dev/null; then
      command -v "${c}"
      return 0
    fi
  done
  return 1
}

# Install a Python interpreter using the detected distro's package manager.
_install_python() {
  local os_id="" os_like=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    os_id=$(. /etc/os-release && echo "${ID:-}")
    os_like=$(. /etc/os-release && echo "${ID_LIKE:-}")
  fi
  local distro="${os_id} ${os_like}"
  info "Detected distro: ${os_id:-unknown} (like: ${os_like:-n/a})"
  case "${distro}" in
    *arch*|*manjaro*|*endeavour*|*garuda*)
      sudo pacman -Sy --noconfirm --needed python python-pip ;;
    *debian*|*ubuntu*|*mint*|*pop*|*kali*)
      sudo apt-get update -qq
      sudo apt-get install -y -qq software-properties-common ca-certificates
      if sudo add-apt-repository -y ppa:deadsnakes/ppa 2>/dev/null && sudo apt-get update -qq; then
        sudo apt-get install -y -qq python3.14 python3.14-venv python3.14-dev \
          || sudo apt-get install -y -qq python3 python3-venv python3-dev python3-pip
      else
        sudo apt-get install -y -qq python3 python3-venv python3-dev python3-pip
      fi ;;
    *fedora*)
      sudo dnf install -y python3.14 python3.14-devel \
        || sudo dnf install -y python3 python3-devel python3-pip ;;
    *rhel*|*centos*|*rocky*|*alma*)
      sudo dnf install -y python3.14 || sudo dnf install -y python3 python3-pip \
        || sudo yum install -y python3 python3-pip ;;
    *suse*|*opensuse*)
      sudo zypper --non-interactive install python314 python314-pip \
        || sudo zypper --non-interactive install python3 python3-pip ;;
    *alpine*)
      sudo apk add --no-cache python3 py3-pip ;;
    *)
      error "Unrecognised distro '${os_id:-?}'. Install Python 3.14 (or any Python >= 3.11) with your package manager, then re-run." ;;
  esac
}

# ─── Stop mode ───────────────────────────────────────────────────────────────
if [[ "${MODE}" == "--stop" ]]; then
  banner
  info "Stopping Docker containers..."
  _ensure_docker
  cd "${PROJECT_DIR}"
  ${COMPOSE_CMD} down
  success "Stopped."
  exit 0
fi

# ─── Local mode ──────────────────────────────────────────────────────────────
if [[ "${MODE}" == "--local" ]]; then
  banner
  info "Local deployment mode"

  # Find (or install) a suitable Python interpreter — not necessarily named
  # "python3.14" (Arch calls it "python").
  PY="$(_find_python || true)"
  if [[ -z "${PY}" ]]; then
    warn "No suitable Python (>=3.11) found. Attempting to install..."
    _install_python
    PY="$(_find_python || true)"
  fi
  [[ -z "${PY}" ]] && error "Could not find or install a suitable Python 3 (>=3.11)."
  success "Python: $("${PY}" --version 2>&1) (${PY})"
  case "$("${PY}" --version 2>&1)" in
    *" 3.14"*) : ;;
    *) warn "Project targets Python 3.14; using the above instead (fine for local dev)." ;;
  esac

  # Create venv if needed
  if [[ ! -d "${VENV_DIR}" ]]; then
    info "Creating virtualenv at ${VENV_DIR}..."
    "${PY}" -m venv "${VENV_DIR}" \
      || error "venv creation failed — your Python may lack the 'venv' module (Debian/Ubuntu: sudo apt-get install python3-venv)."
  fi

  source "${VENV_DIR}/bin/activate"
  info "Installing dependencies..."
  pip install --quiet --upgrade pip
  pip install --quiet -r "${PROJECT_DIR}/requirements/requirements.txt" \
                        -r "${PROJECT_DIR}/requirements/requirements-web.txt"
  success "Dependencies installed."

  # .env
  if [[ ! -f "${PROJECT_DIR}/.env" ]]; then
    cp "${PROJECT_DIR}/.env.example" "${PROJECT_DIR}/.env"
    warn "Created .env from .env.example — set SCANNER_JWT_SECRET before production use."
  fi
  set -o allexport; source "${PROJECT_DIR}/.env"; set +o allexport

  # Generate JWT secret if missing
  if [[ -z "${SCANNER_JWT_SECRET:-}" || "${SCANNER_JWT_SECRET}" == "replace-with-a-strong-random-secret" ]]; then
    SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s|^SCANNER_JWT_SECRET=.*|SCANNER_JWT_SECRET=${SECRET}|" "${PROJECT_DIR}/.env"
    warn "Generated new SCANNER_JWT_SECRET and saved to .env"
    export SCANNER_JWT_SECRET="${SECRET}"
  fi

  HOST="${SCANNER_API_HOST:-127.0.0.1}"
  PORT="${SCANNER_API_PORT:-8000}"

  echo ""
  success "Starting backend on http://${HOST}:${PORT}"
  info  "Login: na9a / 1234"
  info  "Press Ctrl+C to stop."
  echo ""
  cd "${PROJECT_DIR}"
  uvicorn backend.app:app --host "${HOST}" --port "${PORT}"
  exit 0
fi

# ─── Docker mode (default) ───────────────────────────────────────────────────
banner
info "Docker deployment mode"

_ensure_docker

cd "${PROJECT_DIR}"

# .env setup
if [[ ! -f .env ]]; then
  cp .env.example .env
  warn "Created .env from .env.example"
fi

# Generate JWT secret if placeholder still present
CURRENT_SECRET=$(grep '^SCANNER_JWT_SECRET=' .env | cut -d= -f2- || true)
if [[ -z "${CURRENT_SECRET}" || "${CURRENT_SECRET}" == "replace-with-a-strong-random-secret" ]]; then
  if command -v python3 &>/dev/null; then
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  elif command -v openssl &>/dev/null; then
    SECRET=$(openssl rand -hex 32)
  else
    SECRET="$(date +%s%N | sha256sum | head -c 64)"
  fi
  sed -i "s|^SCANNER_JWT_SECRET=.*|SCANNER_JWT_SECRET=${SECRET}|" .env
  success "Generated SCANNER_JWT_SECRET → saved to .env"
fi

# Read bind config for display
HOST=$(grep '^SCANNER_API_HOST=' .env | cut -d= -f2- || true)
if [[ -z "${HOST}" || "${HOST}" == "0.0.0.0" ]]; then
  HOST="127.0.0.1"
fi
PORT=$(grep '^SCANNER_API_PORT=' .env | cut -d= -f2- || echo "8000")

info "Building Docker image (Python 3.14)..."
${COMPOSE_CMD} build --quiet
success "Image built."

info "Starting container..."
# Clear any state from a previous run first. `down` handles containers this
# compose project still tracks; the explicit rm -f mops up stale containers
# left behind by an interrupted run (their fixed container_names —
# na9a-scanner / na9a-redis — would otherwise cause a name conflict).
${COMPOSE_CMD} down --remove-orphans 2>/dev/null || true
${DOCKER_CMD} rm -f na9a-scanner na9a-redis 2>/dev/null || true
${COMPOSE_CMD} up -d --remove-orphans
success "Container running."

echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  N9pinax is running!${RESET}"
echo -e "  Dashboard : ${CYAN}http://${HOST}:${PORT}${RESET}"
echo -e "  Login     : ${BOLD}na9a${RESET} / ${BOLD}1234${RESET}"
echo -e "  Logs      : ${CYAN}${COMPOSE_CMD} logs -f scanner${RESET}"
echo -e "  Stop      : ${CYAN}./deploy.sh --stop${RESET}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo ""
