# FIN//GUARD Automation Makefile
# Cross-platform: works on Linux, macOS, and Windows (PowerShell or Git Bash).

# Detect python: prefer .venv, fall back to system python3/python
ifeq ($(OS),Windows_NT)
  PYTHON  ?= $(or $(wildcard .venv/Scripts/python.exe),python)
else
  PYTHON  ?= $(or $(wildcard .venv/bin/python),.venv/bin/python3,python3,python)
endif

PYTEST  = $(PYTHON) -m pytest
RUFF    = $(PYTHON) -m ruff

.PHONY: help watch t0 t1 t2 t3 attack attack-loop bench migrate-dry migrate-money docs invariants

help:
	@echo "FIN//GUARD Development Commands:"
	@echo "  make watch        - Continuous fast T0 test watcher"
	@echo "  make t0           - Lint + fast unit tests (seconds)"
	@echo "  make t1           - Pre-commit gate: lint + unit + regression"
	@echo "  make t2           - Pre-PR gate: lint + full suite + branch coverage >= 71%"
	@echo "  make t3           - Nightly gate: full suite + Hypothesis ci profile"
	@echo "  make attack       - Red-team attack catalog"
	@echo "  make attack-loop  - Continuous randomized attack loop"
	@echo "  make bench        - Performance baseline"
	@echo "  make migrate-dry  - Dry-run legacy money migration"
	@echo "  make migrate-money DATABASE=... BACKUP=... - Apply migration after backup"
	@echo "  make docs         - Verify documentation invariants (fails on stale claims)"
	@echo "  make invariants   - Check INVARIANTS.md cites only existing tests"

watch:
	$(PYTEST) -q -f tests/unit/

t0:
	$(RUFF) check .
	$(PYTEST) -q -m "not slow" tests/unit/

t1:
	$(RUFF) check .
	$(PYTEST) -v tests/unit/ tests/regression/

t2:
	$(RUFF) check .
	$(PYTEST) -v --cov=finguard --cov-branch --cov-report=term-missing --cov-fail-under=71 tests/

t3:
	$(RUFF) check .
	$(PYTEST) -v --cov=finguard --cov-branch --hypothesis-profile=ci tests/

attack:
	$(PYTEST) -v tests/security/ tests/regression/

attack-loop:
	$(PYTHON) -c "import time, subprocess, sys; [subprocess.run([sys.executable, '-m', 'pytest', '-q', 'tests/regression/']) or time.sleep(2) for _ in iter(int, 1)]"

bench:
	$(PYTHON) scripts/bench.py

migrate-dry:
	$(PYTHON) scripts/migrate_legacy_money.py --database .finguard/finguard.db

migrate-money:
	$(PYTHON) scripts/migrate_legacy_money.py --database "$(DATABASE)" --apply --backup "$(BACKUP)"

invariants: ## Fail if INVARIANTS.md cites a test that does not exist
	$(PYTHON) scripts/check_invariants.py

docs: invariants
	@echo "Documentation check passed."
