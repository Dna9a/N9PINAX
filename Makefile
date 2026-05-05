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

VENV := venv
PYTHON := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip
SCANNER_MAIN := scanner/main.py
SCANNER_PKG := scanner
REQUIREMENTS := requirements.txt

# ─────────────────────────────────────────────
# Phony targets
# ─────────────────────────────────────────────

.PHONY: help install dev test run run-sudo clean lint fmt check all


# ─────────────────────────────────────────────
# Default target
# ─────────────────────────────────────────────

help:
	@echo "$(BRIGHT)$(BLUE)╔════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BRIGHT)$(BLUE)║ Network Security Scanner — Makefile Commands               ║$(RESET)"
	@echo "$(BRIGHT)$(BLUE)╚════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(GREEN)Development:$(RESET)"
	@echo "  make install       — Install dependencies from requirements.txt"
	@echo "  make dev           — Install development dependencies (including test tools)"
	@echo ""
	@echo "$(CYAN)Usage:$(RESET)"
	@echo "  make run           — Run the scanner (auto-detects network)"
	@echo "  make run-sudo      — Run with sudo (required for ARP/raw sockets)"
	@echo "  make run NETWORK=192.168.1.0/24 — Scan specific network"
	@echo ""
	@echo "$(YELLOW)Quality & Testing:$(RESET)"
	@echo "  make lint          — Run flake8 and mypy checks"
	@echo "  make fmt           — Format code with black (auto-fix)"
	@echo "  make check         — Full checks: lint + type checking"
	@echo "  make test          — Run pytest (if available)"
	@echo ""
	@echo "$(RED)Cleanup:$(RESET)"
	@echo "  make clean         — Remove cache, compiled files, databases"
	@echo "  make clean-hard    — Clean + remove venv and .pyc files"
	@echo ""
	@echo "$(BRIGHT)All:$(RESET)"
	@echo "  make all           — Install + check + run"
	@echo ""


# ─────────────────────────────────────────────
# Installation
# ─────────────────────────────────────────────

install:
	@echo "$(GREEN)📦 Installing dependencies...$(RESET)"
	@$(PIP) install -r $(REQUIREMENTS)
	@echo "$(GREEN)✓ Dependencies installed!$(RESET)"

dev: install
	@echo "$(BLUE)🔧 Installing development dependencies...$(RESET)"
	@$(PIP) install pytest pytest-cov black isort
	@echo "$(BLUE)✓ Development tools installed!$(RESET)"


# ─────────────────────────────────────────────
# Running the scanner
# ─────────────────────────────────────────────

run:
	@echo "$(CYAN)🚀 Starting Network Security Scanner...$(RESET)"
	@$(PYTHON) -m $(SCANNER_PKG).main $(ARGS)

run-sudo:
	@echo "$(CYAN)🚀 Starting Network Security Scanner (with sudo for raw sockets)...$(RESET)"
	@sudo $(PYTHON) -m $(SCANNER_PKG).main $(ARGS)

run-list:
	@echo "$(CYAN)📜 Listing previous scans...$(RESET)"
	@$(PYTHON) -m $(SCANNER_PKG).main --list


# ─────────────────────────────────────────────
# Code quality & linting
# ─────────────────────────────────────────────

lint:
	@echo "$(YELLOW)🔍 Running flake8...$(RESET)"
	@flake8 $(SCANNER_PKG) --max-line-length=120 --ignore=E501,W503
	@echo "$(GREEN)✓ Flake8 passed!$(RESET)"
	@echo ""
	@echo "$(YELLOW)🔍 Running mypy...$(RESET)"
	@mypy $(SCANNER_PKG) --ignore-missing-imports --warn-return-any --warn-unused-ignores 2>/dev/null || true
	@echo "$(GREEN)✓ MyPy checks complete!$(RESET)"

fmt:
	@echo "$(CYAN)✨ Formatting code with black...$(RESET)"
	@black $(SCANNER_PKG) --line-length=120 2>/dev/null || $(PYTHON) -m black $(SCANNER_PKG) --line-length=120
	@echo "$(CYAN)✨ Sorting imports with isort...$(RESET)"
	@isort $(SCANNER_PKG) 2>/dev/null || $(PYTHON) -m isort $(SCANNER_PKG)
	@echo "$(GREEN)✓ Code formatted!$(RESET)"

check: lint
	@echo "$(GREEN)✓ All checks passed!$(RESET)"

test:
	@echo "$(YELLOW)🧪 Running tests...$(RESET)"
	@$(PYTHON) -m pytest . -v 2>/dev/null || echo "$(YELLOW)ℹ pytest not installed. Run 'make dev' first.$(RESET)"


# ─────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────

clean:
	@echo "$(RED)🧹 Cleaning cache files...$(RESET)"
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name ".DS_Store" -delete
	@rm -f scanner/data/scans.db scanner/data/scans.db-wal scanner/data/scans.db-shm 2>/dev/null || true
	@echo "$(GREEN)✓ Cleaned!$(RESET)"

clean-hard: clean
	@echo "$(RED)🧹 Removing virtual environment and compiled files...$(RESET)"
	@rm -rf $(VENV) build dist *.egg-info .coverage .coverage.* htmlcov 2>/dev/null || true
	@echo "$(GREEN)✓ Hard clean complete!$(RESET)"


# ─────────────────────────────────────────────
# Meta targets
# ─────────────────────────────────────────────

all: install check
	@echo ""
	@echo "$(BRIGHT)$(GREEN)🎉 Setup complete! Run 'make run' to start scanning.$(RESET)"
