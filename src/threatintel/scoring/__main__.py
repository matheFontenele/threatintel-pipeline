"""CLI: score silver into gold, with a reproducible report on stdout."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from threatintel.normalize.silver import read_indicators
from threatintel.scoring.engine import ScoringReport, evaluate_and_score
from threatintel.scoring.gold import write_gold


def _as_of_arg(value: str):
    from threatintel.scoring.engine import parse_as_of

    try:
        return parse_as_of(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _summary(report: ScoringReport, out: Path) -> dict[str, object]:
    payload = report.summary()
    payload["output"] = str(out)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score the silver indicator table and write the gold table."
    )
    parser.add_argument("--silver", type=Path, default=Path("data/silver/indicators.parquet"))
    parser.add_argument(
        "--out", type=Path, default=Path("data/gold/indicators.parquet"), help="gold Parquet path"
    )
    parser.add_argument(
        "--as-of",
        type=_as_of_arg,
        default=None,
        help="evaluation clock (ISO 8601); defaults to now, which is not reproducible",
    )
    parser.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = parser.parse_args(argv)

    if not args.silver.exists():
        print(f"silver table not found: {args.silver}", file=sys.stderr)
        return 1

    try:
        report = evaluate_and_score(read_indicators(args.silver), as_of=args.as_of)
    except ValueError as exc:
        print(f"scoring failed: {exc}", file=sys.stderr)
        return 2

    write_gold(report, args.out)

    if args.json:
        print(json.dumps(_summary(report, args.out), indent=2, sort_keys=True))
        return 0

    print(
        f"{len(report.scored)} indicators scored at {report.as_of.isoformat()} "
        f"(policy {report.policy_version}/{report.policy_config_hash[:12]}, "
        f"rules {report.rules_config_hash[:12]})"
    )
    bands = " ".join(f"{band}={count}" for band, count in report.band_counts().items())
    print(f"  {bands} needs_review={sum(1 for item in report.scored if item.score.needs_review)}")
    print(
        "  reasons: "
        + " ".join(f"{code}={count}" for code, count in report.reason_counts().items())
    )
    print(f"gold -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
