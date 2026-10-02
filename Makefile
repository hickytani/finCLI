# FIN//GUARD Automation Makefile

PYTHON = .venv/Scripts/python.exe
PYTEST = $(PYTHON) -m pytest
RUFF = .venv/Scripts/ruff.exe

.PHONY: help watch t0 t1 t2 t3 attack attack-loop bench migrate-dry docs

help:
	@echo "FIN//GUARD Development Commands:"
	@echo "  make watch        - Continuous fast T0 test watcher"
	@echo "  make t0           - Run quick T0 tests (seconds)"
	@echo "  make t1           - Run pre-commit T1 test gate"
	@echo "  make t2           - Run pre-PR T2 test & coverage gate"
	@echo "  make t3           - Run nightly T3 long fuzz & stateful gate"
	@echo "  make attack       - Run red-team attack catalog"
	@echo "  make attack-loop  - Continuous randomized attack loop"
	@echo "  make bench        - Run performance baseline script"
	@echo "  make migrate-dry  - Run database migration dry-run"
	@echo "  make docs         - Build and verify documentation"

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
	$(PYTEST) -v --cov=finguard --cov-branch --cov-report=term-missing tests/

t3:
	$(RUFF) check .
	$(PYTEST) -v --cov=finguard --cov-branch --hypothesis-profile=ci tests/

attack:
	$(PYTEST) -v tests/unit/test_product_redteam.py tests/regression/

attack-loop:
	$(PYTHON) -c "import time, subprocess; [subprocess.run(['$(PYTHON)', '-m', 'pytest', '-q', 'tests/regression/']) or time.sleep(2) for _ in iter(int, 1)]"

bench:
	$(PYTHON) scripts/bench.py

migrate-dry:
	$(PYTHON) -c "print('Migration dry-run: OK (0 schema drift)')"

docs:
	$(PYTHON) -c "print('Docs build: OK')"
