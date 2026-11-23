"""FP-04: an indicator older than its type's TTL is stale evidence.

A public feed says "this was malicious", present tense, forever. An IP reported in March is
often a residential address by June. The TTLs here are judgement calls and are versioned as
a policy, not scattered as constants: changing one changes every score, so it must show up
in the config fingerprint.

CVE is deliberately exempt. KEV is a catalogue of *exploitation*, not a time-decaying
indicator, and aging it would silently drop the only non-IP type the pipeline has.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from threatintel.fp_rules.base import Finding, RuleStatus, Strength
from threatintel.normalize.schema import Indicator, IndicatorType

# Days per type. Justification per entry, because a TTL without a reason is a guess:
#   ip     30  — reassignment is routine; Feodo itself prunes inactive C2s continuously.
#   domain 180 — matches the six-month window ThreatFox still serves, so aging inside the
#                feed's own retention is the only range where "stale" is measurable.
#   url    30  — a path stops resolving or starts serving something else quickly.
#   hash   365 — a file hash never becomes benign, it becomes irrelevant; one year is the
#                most generous defensible bound.
#   cve    None — see module docstring.
DEFAULT_TTL_DAYS: dict[IndicatorType, int | None] = {
    IndicatorType.IP: 30,
    IndicatorType.DOMAIN: 180,
    IndicatorType.URL: 30,
    IndicatorType.HASH: 365,
    IndicatorType.CVE: None,
}
POLICY_VERSION = "2026-11-23"


@dataclass(frozen=True)
class AgingRule:
    code: str = "FP-04_STALE"
    ttl_days: dict[IndicatorType, int | None] = field(
        default_factory=lambda: dict(DEFAULT_TTL_DAYS)
    )
    policy_version: str = POLICY_VERSION

    def describe(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "policy_version": self.policy_version,
            "ttl_days": {key.value: value for key, value in sorted(self.ttl_days.items())},
        }

    def evaluate(self, indicator: Indicator, *, as_of: datetime) -> list[Finding]:
        if as_of.tzinfo is None:
            raise ValueError(f"as_of must be timezone-aware, got naive {as_of!r}")

        ttl_days = self.ttl_days.get(indicator.type)
        if ttl_days is None:
            return [
                Finding(
                    code=self.code,
                    indicator_id=indicator.id,
                    status=RuleStatus.NOT_APPLICABLE,
                    detail=f"no TTL defined for type {indicator.type.value}",
                )
            ]

        if indicator.last_seen is not None:
            reference_field, reference = "last_seen", indicator.last_seen
        elif indicator.first_seen is not None:
            reference_field, reference = "first_seen", indicator.first_seen
        else:
            return [
                Finding(
                    code=self.code,
                    indicator_id=indicator.id,
                    status=RuleStatus.INSUFFICIENT_DATA,
                    detail="no first_seen or last_seen to age against",
                )
            ]

        age = as_of - reference
        if age < timedelta(0):
            # A timestamp in the future is bad data, not a fresh indicator. Do not fire, but
            # say why, so the anomaly is visible in the report instead of silently ignored.
            return [
                Finding(
                    code=self.code,
                    indicator_id=indicator.id,
                    status=RuleStatus.NOT_FIRED,
                    detail=f"{reference_field} is in the future; age treated as zero",
                    evidence={"reference": reference_field, "age_seconds": age.total_seconds()},
                )
            ]

        ttl = timedelta(days=ttl_days)
        evidence = {
            "type": indicator.type.value,
            "reference": reference_field,
            "age_days": round(age.total_seconds() / 86_400, 2),
            "ttl_days": ttl_days,
        }
        if age > ttl:
            return [
                Finding(
                    code=self.code,
                    indicator_id=indicator.id,
                    status=RuleStatus.FIRED,
                    strength=Strength.MODERATE,
                    detail=f"{reference_field} is older than the {ttl_days}-day TTL",
                    evidence=evidence,
                )
            ]
        return [
            Finding(
                code=self.code,
                indicator_id=indicator.id,
                status=RuleStatus.NOT_FIRED,
                detail=f"{reference_field} is inside the {ttl_days}-day TTL",
                evidence=evidence,
            )
        ]
