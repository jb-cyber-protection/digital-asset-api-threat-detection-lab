PYTHON ?= python3

.PHONY: install-dev lint test smoke format

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check src tests scripts

test:
	$(PYTHON) -m unittest discover -s tests

smoke:
	$(PYTHON) scripts/generate_activity.py --events 250 --output data/generated/smoke_events.jsonl --summary data/generated/smoke_summary.json
	$(PYTHON) scripts/run_detections.py --events data/generated/smoke_events.jsonl --alerts data/generated/smoke_alerts.jsonl
	$(PYTHON) scripts/enrich_alerts.py --events data/generated/smoke_events.jsonl --alerts data/generated/smoke_alerts.jsonl --output reports/tickets/smoke_triage.jsonl --markdown-dir reports/tickets/smoke_markdown

format:
	$(PYTHON) -m ruff format src tests scripts
