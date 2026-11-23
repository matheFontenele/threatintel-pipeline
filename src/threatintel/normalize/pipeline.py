"""Bronze -> silver for the sources implemented so far.

Re-running is safe: the write is an upsert keyed by the deterministic indicator id, so a
second run for the same collection date changes nothing and a second source enriches the
existing row instead of duplicating it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from threatintel.normalize.feodo import indicators_from_feodo
from threatintel.normalize.kev import indicators_from_kev
from threatintel.normalize.silver import read_indicators, upsert_indicators
from threatintel.normalize.threatfox import indicators_from_threatfox

KEV_SOURCE_DIR = "cisa_kev"
THREATFOX_SOURCE_DIR = "threatfox"
FEODO_SOURCE_DIR = "feodo"


def _iter_bronze(bronze_root: Path, source_dir: str) -> list[tuple[str, Any]]:
    source_root = bronze_root / source_dir
    if not source_root.is_dir():
        return []
    batches: list[tuple[str, Any]] = []
    for payload_path in sorted(source_root.glob("collection_date=*/payload.json")):
        payload = json.loads(payload_path.read_text())
        bronze_ref = payload_path.parent.relative_to(bronze_root).as_posix()
        batches.append((bronze_ref, payload))
    return batches


def iter_kev_bronze(bronze_root: Path) -> list[tuple[str, Any]]:
    """Yield (bronze_ref, payload) for every KEV collection, oldest first."""
    return _iter_bronze(bronze_root, KEV_SOURCE_DIR)


def iter_threatfox_bronze(bronze_root: Path) -> list[tuple[str, Any]]:
    return _iter_bronze(bronze_root, THREATFOX_SOURCE_DIR)


def iter_feodo_bronze(bronze_root: Path) -> list[tuple[str, Any]]:
    return _iter_bronze(bronze_root, FEODO_SOURCE_DIR)


def build_silver(bronze_root: Path, silver_path: Path) -> dict[str, int]:
    """Map every bronze batch into silver, merging across collection dates and sources.

    Reports two counts on purpose: `source_rows` is what the normalizers emitted per batch
    (after within-batch cleanup, before cross-batch dedupe), `indicators` is what survives
    in the table. A single number would hide the whole point of the merge. Feodo is where
    they diverge first: four C2 entries with two ports become three IP indicators.
    """
    stats = {"batches": 0, "rejected": 0, "source_rows": 0, "indicators": 0}
    all_indicators = []

    for bronze_ref, payload in iter_kev_bronze(bronze_root):
        result = indicators_from_kev(payload, bronze_ref=bronze_ref)
        stats["batches"] += 1
        stats["rejected"] += len(result.rejected)
        stats["source_rows"] += len(result.indicators)
        all_indicators.extend(result.indicators)

    for bronze_ref, payload in iter_threatfox_bronze(bronze_root):
        result = indicators_from_threatfox(payload, bronze_ref=bronze_ref)
        stats["batches"] += 1
        stats["rejected"] += len(result.rejected)
        stats["source_rows"] += len(result.indicators)
        all_indicators.extend(result.indicators)

    for bronze_ref, payload in iter_feodo_bronze(bronze_root):
        result = indicators_from_feodo(payload, bronze_ref=bronze_ref)
        stats["batches"] += 1
        stats["rejected"] += len(result.rejected)
        stats["source_rows"] += len(result.indicators)
        all_indicators.extend(result.indicators)

    if stats["batches"] == 0:
        return stats

    upsert_indicators(silver_path, all_indicators, silver_path)
    stats["indicators"] = len(read_indicators(silver_path))
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build silver indicators from bronze.")
    parser.add_argument("--bronze", type=Path, default=Path("data/bronze"))
    parser.add_argument("--silver", type=Path, default=Path("data/silver/indicators.parquet"))
    args = parser.parse_args(argv)

    stats = build_silver(args.bronze, args.silver)
    if stats["batches"] == 0:
        print(f"no bronze batches under {args.bronze}", file=sys.stderr)
        return 1
    print(
        f"mapped {stats['source_rows']} source rows from {stats['batches']} batch(es) "
        f"into {stats['indicators']} indicators, {stats['rejected']} rejected "
        f"-> {args.silver}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
