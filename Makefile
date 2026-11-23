# Week 1 commands. Data lands in data/, which is gitignored.

# Operator credentials. `.env` is gitignored; `-include` keeps the file optional so a
# fresh checkout can run everything that does not need a key.
-include .env
export ABUSECH_AUTH_KEY

.PHONY: install lint test collect-kev collect-threatfox silver ingest

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

lint:
	.venv/bin/ruff check .

test:
	.venv/bin/pytest -q

collect-kev:
	.venv/bin/python -m threatintel.collectors.kev --out data/bronze

# One batch per day, 7-day window: the API rejects `days` above 7, and pulling the
# maximum window every run keeps the fair-use volume predictable.
collect-threatfox:
	.venv/bin/python -m threatintel.collectors.threatfox --out data/bronze --days 7

silver:
	.venv/bin/python -m threatintel.normalize.pipeline \
		--bronze data/bronze --silver data/silver/indicators.parquet

ingest: collect-kev collect-threatfox silver
