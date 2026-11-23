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

from threatintel.normalize.kev import indicators_from_kev
from threatintel.normalize.silver import upsert_indicators

KEV_SOURCE_DIR = "cisa_kev"


def iter_kev_bronze(bronze_root: Path) -> list[tuple[str, dict[str, Any]]]:
    """Yield (bronze_ref, payload) for every KEV collection, oldest first."""
    source_root = bronze_root / KEV_SOURCE_DIR
    if not source_root.is_dir():
        return []
    batches: list[tuple[str, dict[str, Any]]] = []
    for payload_path in sorted(source_root.glob("collection_date=*/payload.json")):
        payload = json.loads(payload_path.read_text())
        bronze_ref = payload_path.parent.relative_to(bronze_root).as_posix()
        batches.append((bronze_ref, payload))
    return batches


def build_silver(bronze_root: Path, silver_path: Path) -> dict[str, int]:
    """Map every bronze batch into silver, merging across collection dates."""
    batches = iter_kev_bronze(bronze_root)
    stats = {"batches": len(batches), "rejected": 0, "indicators": 0}
    if not batches:
        return stats

    all_indicators = []
    for bronze_ref, payload in batches:
        result = indicators_from_kev(payload, bronze_ref=bronze_ref)
        stats["rejected"] += len(result.rejected)
        all_indicators.extend(result.indicators)

    upsert_indicators(silver_path, all_indicators, silver_path)
    stats["indicators"] = len(all_indicators)
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
        f"mapped {stats['indicators']} indicators from {stats['batches']} batch(es), "
        f"{stats['rejected']} rejected -> {args.silver}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
