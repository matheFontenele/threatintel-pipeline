# Week 1 commands. Data lands in data/, which is gitignored.

.PHONY: install lint test collect-kev silver ingest

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

lint:
	.venv/bin/ruff check .

test:
	.venv/bin/pytest -q

collect-kev:
	.venv/bin/python -m threatintel.collectors.kev --out data/bronze

silver:
	.venv/bin/python -m threatintel.normalize.pipeline \
		--bronze data/bronze --silver data/silver/indicators.parquet

ingest: collect-kev silver
