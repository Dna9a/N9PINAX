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

  # Check Python 3.14
  if ! command -v python3.14 &>/dev/null; then
    warn "Python 3.14 not found. Attempting to install..."
    if command -v pacman &>/dev/null; then
      sudo pacman -Sy --noconfirm python 2>/dev/null || true
    elif command -v apt-get &>/dev/null; then
      sudo apt-get update -qq
      sudo apt-get install -y software-properties-common
      sudo add-apt-repository -y ppa:deadsnakes/ppa
      sudo apt-get update -qq
      sudo apt-get install -y python3.14 python3.14-venv python3.14-dev
    else
      error "Python 3.14 not found. Install it first."
    fi
  fi
  success "Python $(python3.14 --version)"

  # Create venv if needed
  if [[ ! -d "${VENV_DIR}" ]]; then
    info "Creating virtualenv at ${VENV_DIR}..."
    python3.14 -m venv "${VENV_DIR}"
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
    SECRET=$(python3.14 -c "import secrets; print(secrets.token_hex(32))")
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
${COMPOSE_CMD} up -d
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
