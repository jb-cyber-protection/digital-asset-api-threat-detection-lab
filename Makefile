PYTHON ?= python3

.PHONY: install-dev lint test smoke format

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check src tests scripts

test:
	$(PYTHON) -m pytest

smoke:
	$(PYTHON) scripts/generate_activity.py --events 25 --output data/generated/smoke_events.jsonl
	$(PYTHON) scripts/run_detections.py --events data/generated/smoke_events.jsonl --alerts data/generated/smoke_alerts.jsonl

format:
	$(PYTHON) -m ruff format src tests scripts
