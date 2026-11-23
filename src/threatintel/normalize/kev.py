"""Map the CISA KEV payload onto silver indicators.

The mapping refuses to guess: a row that does not parse is recorded as rejected with a
reason, not silently dropped and not allowed to abort the whole run. One malformed entry
should cost one indicator, not the collection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from threatintel import __version__
from threatintel.normalize.schema import (
    Indicator,
    IndicatorType,
    InvalidIndicator,
    SourceRef,
    merge_indicators,
)

SOURCE = "cisa_kev"


@dataclass(frozen=True)
class KeVResult:
    """Indicators plus the rows that could not be mapped, with their reasons."""

    indicators: list[Indicator]
    rejected: list[dict[str, str]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.indicators)


def _parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return None


def _attributes(entry: dict[str, Any]) -> dict[str, Any]:
    """Source-specific fields, verbatim, under the source key so merges cannot clash."""
    keys = (
        "vendorProject",
        "product",
        "shortDescription",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse",
        "cwes",
        "notes",
    )
    return {key: entry[key] for key in keys if entry.get(key) not in (None, "", [])}


def _indicator_from_entry(
    entry: dict[str, Any], bronze_ref: str, ingest_version: str
) -> Indicator:
    cve_id = entry.get("cveID")
    if not isinstance(cve_id, str):
        raise InvalidIndicator("missing cveID")
    added = _parse_date(entry.get("dateAdded"))
    ransomware = str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known"
    tags = ["kev", "known_exploited"]
    if ransomware:
        tags.append("ransomware_campaign_use")
    return Indicator.build(
        type=IndicatorType.CVE,
        value=cve_id,
        sources=[SourceRef(name=SOURCE, external_id=cve_id, first_seen=added)],
        # Not a maliciousness score: KEV is authoritative that exploitation was observed,
        # not that this CVE matters to any particular estate.
        source_confidence={SOURCE: 1.0},
        tags=tags,
        first_seen=added,
        attributes={SOURCE: _attributes(entry)},
        ingest_version=ingest_version,
        bronze_refs=[bronze_ref],
    )


def indicators_from_kev(
    payload: dict[str, Any],
    *,
    bronze_ref: str,
    ingest_version: str = __version__,
) -> KeVResult:
    """Convert a validated KEV payload into indicators, merging duplicate CVE ids."""
    merged: dict[str, Indicator] = {}
    rejected: list[dict[str, str]] = []

    for entry in payload.get("vulnerabilities", []):
        if not isinstance(entry, dict):
            rejected.append({"cveID": "", "reason": "entry is not an object"})
            continue
        try:
            indicator = _indicator_from_entry(entry, bronze_ref, ingest_version)
        except (InvalidIndicator, ValueError) as exc:
            rejected.append({"cveID": str(entry.get("cveID", "")), "reason": str(exc)})
            continue
        previous = merged.get(indicator.id)
        merged[indicator.id] = (
            indicator if previous is None else merge_indicators(previous, indicator)
        )

    indicators = sorted(merged.values(), key=lambda item: item.value)
    return KeVResult(indicators=indicators, rejected=rejected)
