# Week 1 commands. Data lands in data/, which is gitignored.

# Operator credentials. `.env` is gitignored; `-include` keeps the file optional so a
# fresh checkout can run everything that does not need a key.
-include .env
export ABUSECH_AUTH_KEY

.PHONY: install lint test collect-kev collect-feodo collect-threatfox collect-urlhaus silver rules ingest

install:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

lint:
	.venv/bin/ruff check .

test:
	.venv/bin/pytest -q

collect-kev:
	.venv/bin/python -m threatintel.collectors.kev --out data/bronze

# No credential: the blocklist is public. The local guard allows one fetch per hour.
collect-feodo:
	.venv/bin/python -m threatintel.collectors.feodo --out data/bronze

# One batch per day, 7-day window: the API rejects `days` above 7, and pulling the
# maximum window every run keeps the fair-use volume predictable.
collect-threatfox:
	.venv/bin/python -m threatintel.collectors.threatfox --out data/bronze --days 7

# The export comments out its own header line; the parser locates it by shape.
# The body is ~27 MB and 10^5 rows, so silver takes noticeably longer with it. Needs
# ABUSECH_AUTH_KEY.
collect-urlhaus:
	.venv/bin/python -m threatintel.collectors.urlhaus --out data/bronze

silver:
	.venv/bin/python -m threatintel.normalize.pipeline \
		--bronze data/bronze --silver data/silver/indicators.parquet

# FP-04/FP-05 over silver. The output is reproducible only with an explicit --as-of;
# without it the report uses the current clock, which is convenient but not publishable.
rules:
	.venv/bin/python -m threatintel.fp_rules --silver data/silver/indicators.parquet

ingest: collect-kev collect-feodo collect-threatfox collect-urlhaus silver
