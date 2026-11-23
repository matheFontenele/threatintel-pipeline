"""Turn rule findings into a score that can be read without trusting a black box.

The scorer consumes two things: the indicator (for its sources and type) and the findings
the rules just produced. It never re-derives a rule's verdict, so a score can always be
traced back to the exact findings that shaped it.

Every term appears in the output as `(code, weight, detail)`. The score is the sum of those
weights plus the base term, then clamped by the policy's caps, which are reported separately
because a cap is a *guarantee* rather than a contribution. An indicator that hits a cap is
not "slightly worse than the arithmetic"; it is structurally barred from the top band.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from threatintel.fp_rules.base import Finding, RuleStatus
from threatintel.fp_rules.corroboration import AUTHORITATIVE_SOURCES, COMMUNITY_SOURCES
from threatintel.fp_rules.engine import RulesReport, evaluate
from threatintel.normalize.schema import Indicator, IndicatorType
from threatintel.scoring.policy import (
    BAND_HIGH,
    BAND_LOW,
    BAND_MEDIUM,
    DEFAULT_POLICY,
    ScorePolicy,
    config_fingerprint,
)

SCORE_FLOOR = 0
SCORE_CEILING = 100


@dataclass(frozen=True)
class Reason:
    """One signed contribution. `detail` is for humans, `code` is for machines."""

    code: str
    weight: int
    detail: str


@dataclass(frozen=True)
class Score:
    """A score with everything needed to challenge it."""

    indicator_id: str
    score: int
    band: str
    needs_review: bool
    reasons: tuple[Reason, ...]
    caps: tuple[str, ...]
    policy_version: str
    policy_config_hash: str = ""


@dataclass(frozen=True)
class ScoredIndicator:
    indicator: Indicator
    score: Score


@dataclass(frozen=True)
class ScoringReport:
    """Scores plus the two hashes that make the run reproducible."""

    as_of: datetime
    policy_version: str
    policy_config_hash: str
    rules_config_hash: str
    scored: tuple[ScoredIndicator, ...]

    def band_counts(self) -> dict[str, int]:
        counts = Counter(item.score.band for item in self.scored)
        return {band: counts.get(band, 0) for band in (BAND_LOW, BAND_MEDIUM, BAND_HIGH)}

    def reason_counts(self) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for item in self.scored:
            counts.update(reason.code for reason in item.score.reasons)
        return dict(sorted(counts.items()))

    def summary(self) -> dict[str, Any]:
        """JSON-ready summary. Counts only — never an indicator value."""
        return {
            "as_of": self.as_of.isoformat(),
            "policy_version": self.policy_version,
            "policy_config_hash": self.policy_config_hash,
            "rules_config_hash": self.rules_config_hash,
            "indicators": len(self.scored),
            "bands": self.band_counts(),
            "needs_review": sum(1 for item in self.scored if item.score.needs_review),
            "reasons": self.reason_counts(),
        }


_KEV_ATTRIBUTE_KEYS = (
    "vendorProject",
    "product",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "cwes",
    "notes",
)


@dataclass(frozen=True)
class VulnRow:
    """One catalogue entry: facts, and deliberately no score.

    A vulnerability's importance is a function of an asset inventory this project does not
    have. Ranking it anyway would produce a number that looks like priority and is really
    the catalogue's publication order plus a source-trust constant, so this track stops at
    the facts and leaves the judgement to a consumer that owns an estate.
    """

    indicator: Indicator

    @property
    def cve_id(self) -> str:
        return self.indicator.value

    def fact(self, key: str) -> Any:
        return (self.indicator.attributes.get("cisa_kev") or {}).get(key)

    @property
    def ransomware(self) -> bool:
        """The catalogue's own flag, normalised. A fact about the CVE, not about a reader."""
        return "ransomware_campaign_use" in self.indicator.tags or (
            str(self.fact("knownRansomwareCampaignUse") or "").strip().lower() == "known"
        )


@dataclass(frozen=True)
class Tracks:
    """Both surfaces from one clock: a scatter of claims, and a catalogue."""

    indicators: ScoringReport
    vulnerabilities: tuple[VulnRow, ...]


def split_tracks(
    indicators: Iterable[Indicator],
) -> tuple[list[Indicator], list[VulnRow]]:
    """Partition one silver read into the two tracks, preserving input order."""
    iocs: list[Indicator] = []
    vulns: list[VulnRow] = []
    for indicator in indicators:
        if indicator.type is IndicatorType.CVE:
            vulns.append(VulnRow(indicator=indicator))
        else:
            iocs.append(indicator)
    return iocs, vulns


def build_tracks(
    indicators: Iterable[Indicator],
    *,
    as_of: datetime | None = None,
    policy: ScorePolicy = DEFAULT_POLICY,
) -> Tracks:
    """Score the IOC track and collect the catalogue at one clock.

    One function so a run cannot stamp its two outputs with two different `as_of` values.
    """
    iocs, vulns = split_tracks(indicators)
    return Tracks(
        indicators=evaluate_and_score(iocs, as_of=as_of, policy=policy),
        vulnerabilities=tuple(vulns),
    )


def _source_class(names: set[str]) -> str:
    if names & AUTHORITATIVE_SOURCES:
        return "SRC_AUTHORITATIVE"
    if names & COMMUNITY_SOURCES:
        return "SRC_COMMUNITY"
    return "SRC_UNCLASSIFIED"


def score_indicator(
    indicator: Indicator,
    findings: Mapping[str, Finding],
    *,
    policy: ScorePolicy = DEFAULT_POLICY,
    policy_hash: str | None = None,
) -> Score:
    """Score one indicator from its findings.

    A missing rule code means the rule did not run; it contributes nothing and imposes no
    cap. That keeps a partial rule set scorable without pretending the missing rule passed.
    """
    names = {ref.name for ref in indicator.sources}
    source_code = _source_class(names)
    base = policy.weights[source_code]
    reasons: list[Reason] = [
        Reason(source_code, base, ", ".join(sorted(names)) or "no source references")
    ]

    def add(code: str, detail: str) -> None:
        reasons.append(Reason(code, policy.weights[code], detail))

    aging = findings.get("FP-04_STALE")
    if aging is not None and aging.status is RuleStatus.FIRED:
        add("STALE_EVIDENCE", aging.detail)
    elif aging is not None and aging.status is RuleStatus.INSUFFICIENT_DATA:
        add("UNKNOWN_AGE", aging.detail)
    elif (
        aging is not None
        and aging.status is RuleStatus.NOT_FIRED
        and source_code == "SRC_AUTHORITATIVE"
    ):
        add("FRESH_AUTHORITATIVE", "inside TTL and curated")

    corroboration = findings.get("FP-05_SINGLE_SOURCE")
    if corroboration is not None and corroboration.status is RuleStatus.FIRED:
        add("SINGLE_COMMUNITY_SOURCE", corroboration.detail)
    elif corroboration is not None and corroboration.status is RuleStatus.NOT_FIRED:
        add("CORROBORATED", corroboration.detail)
    elif corroboration is not None and corroboration.status is RuleStatus.INSUFFICIENT_DATA:
        add("UNCLASSIFIED_SOURCE", corroboration.detail)

    raw = sum(reason.weight for reason in reasons)
    score = max(SCORE_FLOOR, min(SCORE_CEILING, raw))

    caps: list[str] = []
    cap_values: list[tuple[str, int]] = []
    if aging is not None and aging.status is RuleStatus.FIRED:
        cap_values.append(("CAP_STALE", policy.caps["stale"]))
    if aging is not None and aging.status is RuleStatus.INSUFFICIENT_DATA:
        cap_values.append(("CAP_UNKNOWN_AGE", policy.caps["unknown_age"]))
    if corroboration is not None and corroboration.status is RuleStatus.FIRED:
        cap_values.append(("CAP_SINGLE_SOURCE", policy.caps["single_source"]))
    if corroboration is not None and corroboration.status is RuleStatus.INSUFFICIENT_DATA:
        cap_values.append(("CAP_UNCLASSIFIED", policy.caps["unclassified_source"]))
    for code, ceiling in sorted(cap_values, key=lambda item: item[1]):
        if score > ceiling:
            score = ceiling
            caps.append(code)

    needs_review = any(
        finding.status is RuleStatus.INSUFFICIENT_DATA
        for finding in (aging, corroboration)
        if finding is not None
    )

    return Score(
        indicator_id=indicator.id,
        score=score,
        band=policy.band_for(score),
        needs_review=needs_review,
        reasons=tuple(reasons),
        caps=tuple(caps),
        policy_version=policy.version,
        policy_config_hash=policy_hash if policy_hash is not None else config_fingerprint(policy),
    )


def score_all(
    report: RulesReport,
    *,
    policy: ScorePolicy = DEFAULT_POLICY,
) -> ScoringReport:
    """Score every indicator in a rules report."""
    by_indicator: dict[str, dict[str, Finding]] = {}
    for finding in report.findings:
        by_indicator.setdefault(finding.indicator_id, {})[finding.code] = finding

    policy_hash = config_fingerprint(policy)
    scored = tuple(
        ScoredIndicator(
            indicator=indicator,
            score=score_indicator(
                indicator,
                by_indicator.get(indicator.id, {}),
                policy=policy,
                policy_hash=policy_hash,
            ),
        )
        for indicator in report.annotated
    )
    return ScoringReport(
        as_of=report.as_of,
        policy_version=policy.version,
        policy_config_hash=policy_hash,
        rules_config_hash=report.config_hash,
        scored=scored,
    )


def evaluate_and_score(
    indicators: Iterable[Indicator],
    *,
    as_of: datetime | None = None,
    policy: ScorePolicy = DEFAULT_POLICY,
) -> ScoringReport:
    """Run the rules and the scorer at one clock. The supported entry point.

    Refuses CVE input. A catalogue entry has no maliciousness to score, and silently
    dropping it here would hide the caller that skipped the track split.
    """
    items = list(indicators)
    cves = sum(1 for item in items if item.type is IndicatorType.CVE)
    if cves:
        raise ValueError(
            f"{cves} CVE indicators reached the IOC scorer; use build_tracks() instead"
        )
    report = evaluate(items, as_of=as_of)
    return score_all(report, policy=policy)


def parse_as_of(value: str) -> datetime:
    """Reuse the rules engine convention: ISO 8601, bare date means midnight UTC."""
    try:
        moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"not an ISO 8601 date or datetime: {value!r}") from exc
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
