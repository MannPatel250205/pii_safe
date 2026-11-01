.PHONY: install dev hooks test test-unit test-integration lint typecheck check bench demo clean

# Windows / Git Bash: `make dev PYTHON=python`
PYTHON ?= python3

install:
	$(PYTHON) -m pip install -e .

dev:
	$(PYTHON) -m pip install -e ".[dev,server,agents,postgres,ner]" && $(PYTHON) -m spacy download en_core_web_sm
	$(PYTHON) -m pre_commit install

hooks:
	$(PYTHON) -m pre_commit run --all-files

test:
	pytest

test-unit:
	pytest tests/unit

test-integration:
	pytest tests/integration

lint:
	ruff check src tests

typecheck:
	mypy src

# The same gate CI runs. Green here means green there.
check: lint typecheck test

bench:
	piisafe bench -n 2000

demo:
	piisafe sanitize examples/security.log -s DEMO --ephemeral

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
