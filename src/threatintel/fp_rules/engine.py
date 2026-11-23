"""Run the rule set over silver and produce a reproducible report.

Two properties are load-bearing:

- **The report is reproducible from `(snapshot, as_of, config_hash)`.** `as_of` is explicit
  and never `datetime.now()` inside a rule; the config hash covers every rule parameter that
  can change a verdict. Re-running the same three inputs must give the same report, or the
  published metrics cannot be tied to a snapshot.
- **The report never carries an indicator value.** Findings are keyed by id; the summary is
  counts and rates. That is what lets the artifact be published even when the underlying
  rows come from a feed whose terms forbid redistribution (`decisions/0007`).

`fp_reasons` is recomputed, not appended to. A code this run owns but no longer fires is
dropped, so a rule fix actually clears its stale annotations. Codes owned by rules that were
not part of this run are left untouched: a partial run must not clobber another rule's work.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threatintel.fp_rules.aging import AgingRule
from threatintel.fp_rules.base import Finding, Rule, RuleStatus
from threatintel.fp_rules.corroboration import CorroborationRule
from threatintel.normalize.schema import Indicator
from threatintel.normalize.silver import read_indicators, write_indicators

DEFAULT_RULES: tuple[Rule, ...] = (AgingRule(), CorroborationRule())


def config_fingerprint(rules: Sequence[Rule]) -> str:
    """sha256 over the sorted rule descriptions.

    Sorted by code so the hash depends on the rule set, not on import or iteration order.
    Any parameter that reaches `describe()` therefore changes the hash, which is the point:
    a TTL edit is a new configuration, not a silent reinterpretation of old results.
    """
    described = sorted((rule.describe() for rule in rules), key=lambda item: item.get("code", ""))
    payload = json.dumps(described, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _annotate(
    indicator: Indicator, findings: Sequence[Finding], owned_codes: frozenset[str]
) -> Indicator:
    """Recompute `fp_reasons`: keep foreign codes, replace the ones this run owns."""
    fired = {finding.code for finding in findings if finding.status is RuleStatus.FIRED}
    foreign = [code for code in indicator.fp_reasons if code not in owned_codes]
    reasons = sorted(set(foreign) | fired)
    if reasons == indicator.fp_reasons:
        return indicator
    # model_copy skips validation on purpose: only `fp_reasons` changes, and the identity
    # fields that the validator guards are unchanged.
    return indicator.model_copy(update={"fp_reasons": reasons})


@dataclass(frozen=True)
class RulesReport:
    """Findings plus the annotated indicators and the metadata needed to reproduce them."""

    as_of: datetime
    config_hash: str
    rules: tuple[dict[str, Any], ...]
    findings: tuple[Finding, ...]
    annotated: tuple[Indicator, ...]
    indicator_types: dict[str, str] = field(default_factory=dict)

    def counts(self) -> dict[str, dict[str, int]]:
        """Per code, how many findings landed in each status."""
        tally: dict[str, dict[str, int]] = {}
        for finding in self.findings:
            bucket = tally.setdefault(finding.code, {})
            bucket[finding.status.value] = bucket.get(finding.status.value, 0) + 1
        return tally

    def type_rates(self) -> dict[str, dict[str, dict[str, float | int]]]:
        """Per indicator type and code: how often the rule fired, and at what rate."""
        totals: dict[tuple[str, str], int] = {}
        fired: dict[tuple[str, str], int] = {}
        for finding in self.findings:
            indicator_type = self.indicator_types.get(finding.indicator_id, "unknown")
            key = (indicator_type, finding.code)
            totals[key] = totals.get(key, 0) + 1
            if finding.status is RuleStatus.FIRED:
                fired[key] = fired.get(key, 0) + 1

        nested: dict[str, dict[str, dict[str, float | int]]] = {}
        for (indicator_type, code), total in sorted(totals.items()):
            hit = fired.get((indicator_type, code), 0)
            nested.setdefault(indicator_type, {})[code] = {
                "fired": hit,
                "total": total,
                "rate": round(hit / total, 4) if total else 0.0,
            }
        return nested

    def summary(self) -> dict[str, Any]:
        """JSON-ready report. Counts and rates only — never an indicator value."""
        return {
            "as_of": self.as_of.isoformat(),
            "config_hash": self.config_hash,
            "rules": list(self.rules),
            "indicators": len(self.annotated),
            "counts": self.counts(),
            "type_rates": self.type_rates(),
        }


def evaluate(
    indicators: Iterable[Indicator],
    *,
    as_of: datetime | None = None,
    rules: Sequence[Rule] | None = None,
) -> RulesReport:
    """Evaluate every indicator with every rule at a fixed `as_of`.

    `as_of` defaults to now for convenience, but callers that publish a number should pass
    it explicitly; the value is echoed in the report precisely so that a reader can tell
    which clock produced the result.
    """
    moment = as_of if as_of is not None else datetime.now(UTC)
    if moment.tzinfo is None:
        raise ValueError(f"as_of must be timezone-aware, got naive {moment!r}")

    active = tuple(rules) if rules is not None else DEFAULT_RULES
    owned = frozenset(rule.code for rule in active)

    ordered = sorted(indicators, key=lambda item: (item.type.value, item.value))
    findings: list[Finding] = []
    annotated: list[Indicator] = []
    for indicator in ordered:
        local: list[Finding] = []
        for rule in active:
            local.extend(rule.evaluate(indicator, as_of=moment))
        findings.extend(local)
        annotated.append(_annotate(indicator, local, owned))

    return RulesReport(
        as_of=moment,
        config_hash=config_fingerprint(active),
        rules=tuple(rule.describe() for rule in active),
        findings=tuple(findings),
        annotated=tuple(annotated),
        indicator_types={item.id: item.type.value for item in ordered},
    )


def _parse_as_of(value: str) -> datetime:
    try:
        moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not an ISO 8601 date or datetime: {value!r}") from exc
    # A bare date means midnight UTC: a declared convention beats a local-time guess.
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the false-positive rules over the silver indicator table."
    )
    parser.add_argument("--silver", type=Path, default=Path("data/silver/indicators.parquet"))
    parser.add_argument(
        "--as-of",
        type=_parse_as_of,
        default=None,
        help="evaluation clock (ISO 8601); defaults to now",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument(
        "--write-annotated",
        type=Path,
        default=None,
        help="write the indicators with recomputed fp_reasons to this Parquet path",
    )
    args = parser.parse_args(argv)

    if not args.silver.exists():
        print(f"silver table not found: {args.silver}", file=sys.stderr)
        return 1

    try:
        report = evaluate(read_indicators(args.silver), as_of=args.as_of)
    except ValueError as exc:
        print(f"evaluation failed: {exc}", file=sys.stderr)
        return 2

    if args.write_annotated is not None:
        write_indicators(report.annotated, args.write_annotated)

    if args.json:
        print(json.dumps(report.summary(), indent=2, sort_keys=True))
    else:
        print(
            f"{len(report.annotated)} indicators at {report.as_of.isoformat()} "
            f"(config {report.config_hash[:12]})"
        )
        for code, statuses in report.counts().items():
            parts = " ".join(f"{status}={count}" for status, count in sorted(statuses.items()))
            print(f"  {code:<22} {parts}")
        if args.write_annotated is not None:
            print(f"annotated indicators -> {args.write_annotated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
