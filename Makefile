.PHONY: install dev test test-unit test-integration lint bench demo clean

install:
	python3 -m pip install -e .

dev:
	python3 -m pip install -e ".[dev,server,agents,postgres,ner]" && python3 -m spacy download en_core_web_sm

test:
	pytest

test-unit:
	pytest tests/unit

test-integration:
	pytest tests/integration

lint:
	ruff check src tests

bench:
	piisafe bench -n 2000

demo:
	piisafe sanitize examples/security.log -s DEMO --ephemeral

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
