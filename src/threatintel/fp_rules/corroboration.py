"""FP-05: an indicator only one community feed reports is weakly corroborated.

The echo problem: a single submission gets relayed into several "sources", and a scorer that
counts feed rows reads that as agreement. Counting *independent feeds* is the fix, and this
rule is what makes the count operational.

Two deliberate limits keep the rule honest:

- **An authoritative single source is not a weak source.** Feodo publishes a curated C2
  blocklist; KEV publishes exploitation observed by a government catalogue. Being
  alone there is not evidence of a false positive, so the rule reports `not_applicable`
  instead of firing.
- **Unknown feeds are not assumed independent.** A source that has not been classified
  produces `insufficient_data`, so adding a feed forces the classification decision to be
  made explicitly rather than silently benefiting from the default.

Known limitation, recorded so it is not discovered later: with the current source mix this
rule is close to "the indicator came from ThreatFox". It stays `weak` on that basis, and
`docs/methodology.md` §8 ablation is what must justify it once the source mix widens.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from threatintel.fp_rules.base import Finding, RuleStatus, Strength
from threatintel.normalize.schema import Indicator, IndicatorType

# Curated: alone is not suspicious for these.
AUTHORITATIVE_SOURCES = frozenset({"cisa_kev", "feodo"})
# Community-submitted: alone is worth flagging.
COMMUNITY_SOURCES = frozenset({"threatfox", "urlhaus"})
# CVE corroboration is a different question (advisories, not feeds); this rule stays out.
SUPPORTED_TYPES = frozenset(
    {IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.HASH}
)


@dataclass(frozen=True)
class CorroborationRule:
    code: str = "FP-05_SINGLE_SOURCE"

    def describe(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "authoritative_sources": sorted(AUTHORITATIVE_SOURCES),
            "community_sources": sorted(COMMUNITY_SOURCES),
            "supported_types": sorted(item.value for item in SUPPORTED_TYPES),
        }

    def evaluate(self, indicator: Indicator, *, as_of: datetime) -> list[Finding]:
        if indicator.type not in SUPPORTED_TYPES:
            return [
                Finding(
                    code=self.code,
                    indicator_id=indicator.id,
                    status=RuleStatus.NOT_APPLICABLE,
                    detail=f"corroboration is not defined for type {indicator.type.value}",
                )
            ]

        names = sorted({ref.name for ref in indicator.sources})
        if not names:
            return [
                Finding(
                    code=self.code,
                    indicator_id=indicator.id,
                    status=RuleStatus.INSUFFICIENT_DATA,
                    detail="indicator has no source references",
                )
            ]

        unclassified = sorted(set(names) - AUTHORITATIVE_SOURCES - COMMUNITY_SOURCES)
        if unclassified:
            return [
                Finding(
                    code=self.code,
                    indicator_id=indicator.id,
                    status=RuleStatus.INSUFFICIENT_DATA,
                    detail="source has no independence classification",
                    evidence={"unclassified_sources": unclassified},
                )
            ]

        if len(names) >= 2:
            return [
                Finding(
                    code=self.code,
                    indicator_id=indicator.id,
                    status=RuleStatus.NOT_FIRED,
                    detail=f"reported by {len(names)} independent feeds",
                    evidence={"sources": names},
                )
            ]

        if names[0] in AUTHORITATIVE_SOURCES:
            return [
                Finding(
                    code=self.code,
                    indicator_id=indicator.id,
                    status=RuleStatus.NOT_APPLICABLE,
                    detail=f"{names[0]} is authoritative on its own",
                    evidence={"sources": names},
                )
            ]

        return [
            Finding(
                code=self.code,
                indicator_id=indicator.id,
                status=RuleStatus.FIRED,
                strength=Strength.WEAK,
                detail=f"only one community feed ({names[0]}) reports it",
                evidence={
                    "sources": names,
                    "distinct_reporters": len(names),
                },
            )
        ]
