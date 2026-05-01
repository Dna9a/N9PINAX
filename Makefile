# Colors
RED = \033[31m
GREEN = \033[32m
YELLOW = \033[33m
BLUE = \033[34m
CYAN = \033[36m
RESET = \033[0m

# Variables
PYTHON = python3
PIP	= pip3
MAIN = ft_scanner.py
CONFIG = config.txt

.PHONY: run install debug clean lint lint-strict


run:
	@echo "$(GREEN)Cooking🍳😛.............. </>$(RESET)"
	@$(PYTHON) $(MAIN) $(CONFIG)

install:
	@echo "$(BLUE)Installing...... </>$(RESET)"
	@sleep 1
	@echo "$(CYAN)Still going..............$(RESET)"
	@sleep 1
	@echo "$(CYAN)One second a jmi..............$(RESET)"
# 	$(PIP) install -r requirements.txt # neeed to be uncommented
	@echo "$(YELLOW)  installing flake8..............$(RESET)"
	@echo "$(BLUE)    installing mypy..............$(RESET)"
	@echo "$(YELLOW)      installing scapy..............$(RESET)"
	@echo "$(GREEN)\tBuild complete ALL DONEE :) ! 🐪$(RESET)"

# not nessary but just for fun :D
debug:
	@sleep 1
	@$(PYTHON) -m pdb $(MAIN) $(CONFIG)

clean:
	@echo "$(RED)CLEANINNG........$(RESET)"
	@sleep 1
	@rm -rf __pycache__ */__pycache__ .mypy_cache

# not nessary but just for fun :D
lint:
	@echo "$(YELLOW)CHECKKINNG YOO FLAKE8 && MYPY..........."
	flake8 .
	mypy . --warn-return-any --warn-unused-ignores --ignore-missing-imports --disallow-untyped-defs --check-untyped-defs

# not nessary but just for fun :D
lint-strict:
	@echo "$(YELLOW)CHECKKINNG YOO FLAKE8 && MYPY STRICT..........."
	flake8 .
	mypy . --strict
