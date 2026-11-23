"""CLI: score silver into two surfaces, with a reproducible report on stdout.

One run writes both files from one `as_of`, because a catalogue stamped with a different
clock than the scores would make a report cite two snapshots without saying so.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from threatintel.normalize.silver import read_indicators
from threatintel.scoring.engine import ScoringReport, VulnRow, build_tracks
from threatintel.scoring.gold import write_gold, write_vulnerabilities


def _as_of_arg(value: str):
    from threatintel.scoring.engine import parse_as_of

    try:
        return parse_as_of(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _distinct_scores(report: ScoringReport) -> int:
    return len({item.score.score for item in report.scored})


def _summary(
    report: ScoringReport,
    vulnerabilities: tuple[VulnRow, ...],
    out: Path,
    out_vulnerabilities: Path,
) -> dict[str, object]:
    payload = report.summary()
    payload["distinct_scores"] = _distinct_scores(report)
    payload["output"] = str(out)
    payload["vulnerabilities"] = {
        "count": len(vulnerabilities),
        "ransomware": sum(1 for item in vulnerabilities if item.ransomware),
        "output": str(out_vulnerabilities),
    }
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Score the silver indicator table into gold and publish the vulnerability "
            "catalogue as facts."
        )
    )
    parser.add_argument("--silver", type=Path, default=Path("data/silver/indicators.parquet"))
    parser.add_argument(
        "--out", type=Path, default=Path("data/gold/indicators.parquet"), help="gold Parquet path"
    )
    parser.add_argument(
        "--out-vulnerabilities",
        type=Path,
        default=Path("data/gold/vulnerabilities.parquet"),
        help="vulnerability catalogue path",
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
        tracks = build_tracks(read_indicators(args.silver), as_of=args.as_of)
    except ValueError as exc:
        print(f"scoring failed: {exc}", file=sys.stderr)
        return 2

    report = tracks.indicators
    write_gold(report, args.out)
    write_vulnerabilities(tracks.vulnerabilities, args.out_vulnerabilities, as_of=report.as_of)

    if args.json:
        print(
            json.dumps(
                _summary(report, tracks.vulnerabilities, args.out, args.out_vulnerabilities),
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    print(
        f"{len(report.scored)} indicators scored at {report.as_of.isoformat()} "
        f"(policy {report.policy_version}/{report.policy_config_hash[:12]}, "
        f"rules {report.rules_config_hash[:12]})"
    )
    bands = " ".join(f"{band}={count}" for band, count in report.band_counts().items())
    print(
        f"  {bands} distinct_scores={_distinct_scores(report)} "
        f"needs_review={sum(1 for item in report.scored if item.score.needs_review)}"
    )
    print(
        "  reasons: "
        + " ".join(f"{code}={count}" for code, count in report.reason_counts().items())
    )
    print(
        f"  {len(tracks.vulnerabilities)} vulnerabilities, no score "
        f"(ransomware={sum(1 for item in tracks.vulnerabilities if item.ransomware)})"
    )
    print(f"gold -> {args.out}")
    print(f"vulnerabilities -> {args.out_vulnerabilities}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
