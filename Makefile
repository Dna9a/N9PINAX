# PFE Cybersécurité — Network Security Scanner
# Makefile for development, testing, and deployment
# ABIED Youssef / EL-BARAZI Meriem

# ─────────────────────────────────────────────
# Colors for terminal output
# ─────────────────────────────────────────────

RED = \033[31m
GREEN = \033[32m
YELLOW = \033[33m
BLUE = \033[34m
CYAN = \033[36m
BRIGHT = \033[1m
RESET = \033[0m

# ─────────────────────────────────────────────
# Variables
# ─────────────────────────────────────────────

VENV         ?= $(HOME)/CamelEnv🐪
PYTHON       := $(VENV)/bin/python3
PIP          := $(VENV)/bin/pip
REQUIREMENTS      := requirements/requirements.txt
REQUIREMENTS_WEB  := requirements/requirements-web.txt
REQUIREMENTS_DEV  := requirements/requirements-dev.txt
SCANNER_PKG       := scanner

# ─────────────────────────────────────────────
# Phony targets
# ─────────────────────────────────────────────

.PHONY: help up down restart logs build uninstall purge status start stop install virgin dev test run run-sudo run-backend run-backend-sudo run-backend-reload setup-caps clean clean-py clean-web clean-all lint fmt check all


# ─────────────────────────────────────────────
# Default target
# ─────────────────────────────────────────────

help:
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║$(RESET)$(YELLOW)             Network Security Scanner — Makefile Commands            🐪 🐫$(RESET)$(BLUE)    ║$(RESET)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(GREEN)Docker (recommended):$(RESET)"
	@echo "  make up            — Build images (if needed) and start all containers (detached)"
	@echo "  make down          — Stop and remove containers"
	@echo "  make restart       — Stop then start (down + up)"
	@echo "  make logs          — Tail logs from all containers"
	@echo "  make build         — Force rebuild all Docker images without cache"
	@echo "  make status        — Show container status and exposed ports"
	@echo "  make uninstall     — Full removal: containers, images, volumes, networks, project dir"
	@echo "  make start         — Install Docker if needed, then build and launch"
	@echo ""
	@echo "$(GREEN)Development:$(RESET)"
	@echo "  make install       — Install dependencies from requirements.txt"
	@echo "  make virgin        — Setup a clean environment with Python 3.14 (Debian/Ubuntu)"
	@echo "  make dev           — Install development dependencies (including test tools)"
	@echo ""
	@echo "$(CYAN)Local (no Docker):$(RESET)"
	@echo "  make run                — Run the scanner (auto-detects network)"
	@echo "  make run-sudo           — Run with sudo (required for ARP/raw sockets)"
	@echo "  make ARGS=\"--help\" run   — Pass custom arguments to the scanner"
	@echo "  make run-backend        — Start FastAPI + SSE backend (serves frontend at /)"
	@echo "  make run-backend-sudo   — Same, but with sudo (needed for raw-socket scanning)"
	@echo "  make run-backend-reload — Start backend with auto-reload (uvicorn --reload)"
	@echo "  make setup-caps         — One-time: grant CAP_NET_RAW to Python (no more sudo needed)"
	@echo "  make install-web        — Install web dependencies (FastAPI, uvicorn, sse-starlette)"
	@echo ""
	@echo "$(YELLOW)Quality & Testing:$(RESET)"
	@echo "  make lint          — Run flake8 and mypy checks"
	@echo "  make fmt           — Format code with black/isort"
	@echo "  make test          — Run pytest suite"
	@echo ""
	@echo "$(RED)Cleanup:$(RESET)"
	@echo "  make clean         — Remove cache, compiled files, databases"
	@echo "  make clean-py      — Remove Python caches, venvs, and scanner build artifacts"
	@echo "  make clean-web     — Remove web build artifacts and uninstall web deps (if venv active)"
	@echo "  make clean-all     — Full clean: remove caches, web artifacts, venv and build artifacts"	@echo "  make purge         — Clean all scan data (database and results)"	@echo ""
	@echo "$(GREEN)Meta:$(RESET)"
	@echo "  make koulxi         — Full setup, test, and run sequence (virgin + install + test + run-backend)"
	@echo ""
	
# ─────────────────────────────────────────────
# Docker Compose targets
# ─────────────────────────────────────────────

# Detect compose command once
_COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

up:
	@echo "$(GREEN)🚀 Starting N9pinax (docker compose)...$(RESET)"
	@$(_COMPOSE) up --build -d
	@echo "$(GREEN)✓ Platform is up. Open http://localhost:8000 in your browser.$(RESET)"
	@echo "$(YELLOW)  From other devices: http://<this-machine-IP>:8000$(RESET)"

down:
	@echo "$(RED)🛑 Stopping N9pinax...$(RESET)"
	@$(_COMPOSE) down
	@echo "$(GREEN)✓ Containers stopped.$(RESET)"

restart: down up

logs:
	@$(_COMPOSE) logs -f

build:
	@echo "$(CYAN)🔨 Rebuilding Docker images (no cache)...$(RESET)"
	@$(_COMPOSE) build --no-cache
	@echo "$(GREEN)✓ Images rebuilt.$(RESET)"

status:
	@echo "$(CYAN)📊 Container status:$(RESET)"
	@$(_COMPOSE) ps
	@echo ""
	@echo "$(CYAN)🔌 Exposed ports:$(RESET)"
	@docker ps --format "table {{.Names}}\t{{.Ports}}" 2>/dev/null || true

uninstall:
	@echo "$(RED)$(BRIGHT)⚠  WARNING: This will PERMANENTLY remove all containers, images, volumes,$(RESET)"
	@echo "$(RED)$(BRIGHT)   networks, and DELETE the project directory from disk.$(RESET)"
	@echo ""
	@read -p "  Type YES to confirm complete removal: " _confirm; \
	if [ "$$_confirm" = "YES" ]; then \
		echo "$(RED)Stopping containers...$(RESET)"; \
		$(_COMPOSE) down --volumes --remove-orphans 2>/dev/null || true; \
		echo "$(RED)Removing Docker images...$(RESET)"; \
		docker rmi na9a-scanner:latest 2>/dev/null || true; \
		echo "$(RED)Removing project directory...$(RESET)"; \
		rm -rf "$(shell pwd)"; \
		echo "$(GREEN)✓ N9pinax removed.$(RESET)"; \
	else \
		echo "$(YELLOW)Cancelled.$(RESET)"; \
	fi

# ─────────────────────────────────────────────
# One-command bootstrap (wraps deploy.sh)
# ─────────────────────────────────────────────

start:
	@chmod +x deploy.sh
	@bash deploy.sh

stop:
	@chmod +x deploy.sh
	@bash deploy.sh --stop

# ─────────────────────────────────────────────
# Installation
# ─────────────────────────────────────────────

virgin:
	@echo "$(CYAN)🌱 Preparing environment with Python 3.14...$(RESET)"
	@if ! command -v python3.14 > /dev/null; then \
		echo "$(YELLOW)Python 3.14 not found. Attempting to install...$(RESET)"; \
		sudo apt-get update && sudo apt-get install -y software-properties-common; \
		sudo add-apt-repository -y PPA:deadsnakes/ppa; \
		sudo apt-get update && sudo apt-get install -y python3.14 python3.14-venv python3.14-dev; \
	fi
	@echo "$(RED)🧹 Removing existing environment at $(VENV)...$(RESET)"
	@rm -rf $(VENV)
	@echo "$(GREEN)👾 Creating venv at $(VENV)...$(RESET)"
	@python3.14 -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@$(PIP) install -r $(REQUIREMENTS)
	@echo "$(CYAN)🖇 Adding aliases to shell config files...$(RESET)"
	@if [ -f ~/.bashrc ]; then \
		if ! grep -q "alias na9a=" ~/.bashrc; then \
			echo "alias na9a='source $(VENV)/bin/activate'" >> ~/.bashrc; \
			echo "alias tfi='deactivate'" >> ~/.bashrc; \
			echo "$(BLUE)✓ Aliases added to ~/.bashrc$(RESET)"; \
		fi \
	fi
	@if [ -f ~/.zshrc ]; then \
		if ! grep -q "alias na9a=" ~/.zshrc; then \
			echo "alias na9a='source $(VENV)/bin/activate'" >> ~/.zshrc; \
			echo "alias tfi='deactivate'" >> ~/.zshrc; \
			echo "$(BLUE)✓ Aliases added to ~/.zshrc$(RESET)"; \
		fi \
	fi
	@echo ""
	@echo "$(GREEN)✓ Virgin environment setup complete! 🐪$(RESET)"
	@echo "$(YELLOW)To use the new alias, run:$(RESET) source ~/.bashrc (or ~/.zshrc)"
	@echo "$(YELLOW)Then simply type:$(RESET) na9a"

install:
	@echo "$(GREEN)📦 Installing dependencies...$(RESET)"
	@$(PIP) install -r $(REQUIREMENTS)
	@echo "$(GREEN)✓ Dependencies installed!$(RESET)"

dev: install
	@echo "$(BLUE)🔧 Installing development/test dependencies...$(RESET)"
	@$(PIP) install -r $(REQUIREMENTS_DEV)
	@echo "$(BLUE)✓ Development tools installed!$(RESET)"

# ─────────────────────────────────────────────
# Running the scanner
# ─────────────────────────────────────────────

run:
	@echo "$(CYAN)🚀 Starting Network Security Scanner...$(RESET)"
	@$(PYTHON) -m $(SCANNER_PKG).main $(ARGS)

run-sudo:
	@echo "$(CYAN)🚀 Starting with sudo (required for raw sockets)...$(RESET)"
	@sudo $(VENV)/bin/python3 -m $(SCANNER_PKG).main $(ARGS)

run-list:
	@echo "$(CYAN)📜 Listing previous scans...$(RESET)"
	@$(PYTHON) -m $(SCANNER_PKG).main --list

run-backend:
	@echo "$(CYAN)🌐 Starting FastAPI + SSE backend (http://0.0.0.0:8000)...$(RESET)"
	@if command -v uvicorn > /dev/null 2>&1; then \
		echo "$(CYAN)→ Running with uvicorn$(RESET)"; \
		uvicorn backend.app:app --host 0.0.0.0 --port 8000; \
	else \
		echo "$(YELLOW)uvicorn not found, falling back to python -m backend$(RESET)"; \
		SCANNER_API_HOST=0.0.0.0 $(PYTHON) -m backend; \
	fi

# Run the backend as root so ARP/SYN scanning works without additional setup.
# sudo will prompt for your password once. Use this for local dev when you
# haven't run 'make setup-caps' yet.
run-backend-sudo:
	@echo "$(CYAN)🌐 Starting FastAPI + SSE backend with sudo (http://0.0.0.0:8000)...$(RESET)"
	@echo "$(YELLOW)  Sudo required for raw-socket scanning (ARP/ICMP/SYN).$(RESET)"
	@if [ -f .env ]; then export $$(cat .env | grep -v '^#' | xargs); fi; \
	if command -v uvicorn > /dev/null 2>&1; then \
		sudo -E $(PYTHON) -m uvicorn backend.app:app --host 0.0.0.0 --port 8000; \
	else \
		sudo -E SCANNER_API_HOST=0.0.0.0 $(PYTHON) -m backend; \
	fi

# One-time setup: grant CAP_NET_RAW + CAP_NET_ADMIN to the Python binary so
# raw-socket scanning works without sudo for future runs.
# Run this once after install; re-run if Python is upgraded.
setup-caps:
	@echo "$(CYAN)🔑 Granting CAP_NET_RAW + CAP_NET_ADMIN to Python (requires sudo)...$(RESET)"
	@PY=$$(command -v python3.14 2>/dev/null || command -v python3 2>/dev/null); \
	REAL=$$(readlink -f "$$PY"); \
	echo "  → setcap on $$REAL"; \
	sudo setcap 'cap_net_raw,cap_net_admin+eip' "$$REAL"; \
	echo "$(GREEN)✓ Done. You can now run 'make run-backend' without sudo for scanning.$(RESET)"

# Development target: auto-reload on code changes (requires uvicorn)
run-backend-reload:
	@echo "$(CYAN)🌐 Starting FastAPI + SSE backend (dev, --reload, http://0.0.0.0:8000)...$(RESET)"
	@if command -v uvicorn > /dev/null 2>&1; then \
		uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload; \
	else \
		echo "$(RED)Error: uvicorn is not installed. Run 'make install-web' first.$(RESET)"; exit 1; \
	fi

install-web:
	@echo "$(BLUE)📦 Installing web dependencies (FastAPI + SSE)...$(RESET)"
	@$(PIP) install -r $(REQUIREMENTS_WEB)
	@echo "$(BLUE)✓ Web dependencies installed!$(RESET)"

# ─────────────────────────────────────────────
# Code quality & testing
# ─────────────────────────────────────────────

lint:
	@echo "$(YELLOW)🔍 Running flake8...$(RESET)"
	@flake8 $(SCANNER_PKG) --max-line-length=120 --ignore=E501,W503,E203
	@echo "$(YELLOW)🔍 Running mypy...$(RESET)"
	@mypy $(SCANNER_PKG) --ignore-missing-imports

fmt:
	@echo "$(CYAN)✨ Formatting code...$(RESET)"
	@black $(SCANNER_PKG) --line-length=120
	@isort $(SCANNER_PKG)

check: lint
	@echo "$(GREEN)✓ All checks passed! 🐪$(RESET)"

test:
	@echo "$(YELLOW)🧪 Running tests...$(RESET)"
	@$(PYTHON) -m pytest . -v 2>/dev/null || echo "$(YELLOW)ℹ pytest not installed. Run 'make dev' first.$(RESET)"
	@echo "$(GREEN)✓ Tests complete!$(RESET)"
	@echo "$(YELLOW)🧪 Running verification tests ...$(RESET)"
	@$(PYTHON) -m pytest tests/
	@echo "$(GREEN)✓ Test and verification tests complete! 🐪$(RESET)"

# ─────────────────────────────────────────────
# Everything in one command (virgin setup + install + test + run)
# ─────────────────────────────────────────────

koulxi:
	@echo "$(CYAN)🚀 Running full setup and tests that's gonna take time 😒🐪...$(RESET)"
	@$(MAKE) --no-print-directory virgin
	@echo "$(CYAN)Sourcing environment... 👾 $(RESET)"
	@sh_name=$$(basename "$$SHELL" 2>/dev/null) || sh_name=""; \
	case "$$sh_name" in \
		zsh) [ -f ~/.zshrc ] && $$SHELL -c '. ~/.zshrc' || true ;; \
		bash) [ -f ~/.bashrc ] && $$SHELL -c '. ~/.bashrc' || true ;; \
		*) if [ -f ~/.bashrc ]; then $$SHELL -c '. ~/.bashrc'; elif [ -f ~/.zshrc ]; then $$SHELL -c '. ~/.zshrc'; fi ;; \
	esac
	@echo "$(CYAN)Entering environment... 🎮$(RESET)"
	@echo "$(CYAN)Activating venv and running remaining steps non-interactively...$(RESET)"
	@if [ -f $(VENV)/bin/activate ]; then \
		$$SHELL -c 'source $(VENV)/bin/activate && $(MAKE) --no-print-directory dev && $(MAKE) --no-print-directory test && $(MAKE) --no-print-directory install-web && $(MAKE) --no-print-directory run-backend'; \
	else \
		echo "$(YELLOW)Venv not found at $(VENV). Run 'make virgin' first.$(RESET)"; \
	fi
	@echo "$(GREEN)✓ Full setup and run complete! 🐪$(RESET)"
	@echo "$(GREEN)✓ Full setup and run complete! 🐪$(RESET)"

# ─────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────

clean:
	@echo "$(RED)🧹 Cleaning cache & data...   🐪$(RESET)"
	@find . -type d -name __pycache__ -exec rm -rf {} +
	@find . -type d -name ".mypy_cache" -exec rm -rf {} +
	@find . -type d -name ".pytest_cache" -exec rm -rf {} +
	@find . -type d -name ".ruff_cache" -exec rm -rf {} +
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.log" -delete || true
	@find . -type f -name ".DS_Store" -delete || true
	@rm -rf node_modules frontend/node_modules frontend/dist frontend/build || true
	@rm -f scanner/data/scans.db* scanner/data/export_*.json scanner/data/export_*.csv
	@rm -f .coverage || true
	@echo "$(GREEN)✓ Cleaned!         🐪$(RESET)"


clean-py:
	@echo "$(RED)🧹 Cleaning Python caches, venvs, and scanner artifacts...   🐪$(RESET)"
	@find . -type d -name __pycache__ -exec rm -rf {} +
	@find . -type d -name ".mypy_cache" -exec rm -rf {} +
	@find . -type d -name ".pytest_cache" -exec rm -rf {} +
	@find . -type f -name "*.pyc" -delete
	@rm -rf build dist *.egg-info scanner.egg-info || true
	@rm -rf .venv venv env na9a $(VENV) || true
	@if [ -n "$$VIRTUAL_ENV" ]; then \
		echo "Detected active venv: $$VIRTUAL_ENV — attempting to uninstall requirements in-venv..."; \
		if [ -f "$$VIRTUAL_ENV/bin/pip" ]; then $$VIRTUAL_ENV/bin/pip uninstall -y -r /requirements/requirements.txt /requirements/requirements-dev.txt || true; fi; \
	fi
	@echo "$(GREEN)✓ Python clean complete!         🐪$(RESET)"


clean-web:
	@echo "$(RED)🧹 Cleaning web build artifacts and (optionally) uninstalling web deps...   🐪$(RESET)"
	@rm -rf node_modules frontend/node_modules frontend/dist frontend/build || true
	@if [ -n "$$VIRTUAL_ENV" ]; then \
		if [ -f "$$VIRTUAL_ENV/bin/pip" ]; then $$VIRTUAL_ENV/bin/pip uninstall -y -r /requirementsrequirements-web.txt || true; fi; \
	fi
	@echo "$(GREEN)✓ Web clean complete!         🐪$(RESET)"


clean-all: clean-py clean-web clean
	@echo "$(RED)🧹 Removing venv & build artifacts...   🐪$(RESET)"
	@rm -rf $(VENV) build dist *.egg-info .coverage htmlcov
	@echo "$(GREEN)✓ Full clean complete!         🐪$(RESET)"

purge:
	@echo "$(RED)🧨 Purging all scan data (database and results)...   🐪$(RESET)"
	@rm -f scanner/data/scans.db*
	@rm -f scanner/data/hostname_cache.json
	@rm -f scanner/data/export_*.json scanner/data/export_*.csv
	@echo "$(GREEN)✓ Data purged!         🐪$(RESET)"

# ─────────────────────────────────────────────
# Meta targets
# ─────────────────────────────────────────────

all: install check
	@echo ""
	@echo "$(BRIGHT)$(GREEN)🎉 Setup complete! Run 'make run' to start scanning.       🐪$(RESET)"
