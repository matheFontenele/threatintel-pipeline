"""Map URLhaus CSV batches onto silver indicators.

URLhaus is a *URL* feed: every row is a malware distribution or C2 URL, so there is no
type classification to do and no `ip:port` splitting. The interesting part is provenance:
`dateadded` and `last_online` bound the sighting window, `url_status` says whether the URL
still answered when the feed was generated, and `reporter` is the submitter.

The parser is the collector's own `parse_export`, not a lookalike: the live export comments
out its header line, and two independent header-skipping routines would eventually disagree.

`distinct_reporters` stays 1. URLhaus is one feed; the `reporter` column names a submitter
inside it, and counting submitters as independent sources is the echo problem this project
exists to measure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from threatintel import __version__
from threatintel.collectors.urlhaus import parse_export
from threatintel.normalize.schema import (
    Indicator,
    IndicatorType,
    InvalidIndicator,
    SourceRef,
    merge_indicators,
)

SOURCE = "urlhaus"


@dataclass(frozen=True)
class UrlhausResult:
    indicators: list[Indicator]
    rejected: list[dict[str, str]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.indicators)


def _parse_timestamp(value: Any) -> datetime | None:
    """Both columns are `YYYY-MM-DD HH:MM:SS` today; a bare date is accepted as midnight.

    `last_online` is empty for URLs that never came back, and that is not an error: the URL
    is still an indicator, it simply has no last sighting.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _tags(row: dict[str, Any]) -> set[str]:
    tags = {part.strip() for part in (row.get("tags") or "").split(",") if part.strip()}
    threat = (row.get("threat") or "").strip()
    if threat:
        tags.add(threat)
    return tags


def _indicator_from_row(row: dict[str, Any], bronze_ref: str, ingest_version: str) -> Indicator:
    url = row.get("url")
    if not isinstance(url, str) or not url.strip():
        raise InvalidIndicator("missing url")
    # The status is recorded, not validated: a new value in the feed must not cost the
    # indicator, and rejecting the row would discard a real URL over a label.
    status = (row.get("url_status") or "").strip()

    first_seen = _parse_timestamp(row.get("dateadded"))
    last_seen = _parse_timestamp(row.get("last_online"))
    attributes: dict[str, Any] = {}
    if status:
        attributes["status"] = status
    for key in ("threat", "reporter", "urlhaus_link"):
        value = (row.get(key) or "").strip()
        if value:
            attributes[key] = value

    external_id = (row.get("id") or "").strip() or None
    return Indicator.build(
        type=IndicatorType.URL,
        value=url,
        sources=[
            SourceRef(
                name=SOURCE,
                external_id=external_id,
                first_seen=first_seen,
                last_seen=last_seen,
            )
        ],
        tags=sorted(_tags(row)),
        first_seen=first_seen,
        last_seen=last_seen,
        attributes={SOURCE: attributes},
        ingest_version=ingest_version,
        bronze_refs=[bronze_ref],
    )


def indicators_from_urlhaus(
    text: str,
    *,
    bronze_ref: str,
    ingest_version: str = __version__,
) -> UrlhausResult:
    """Map one export body. Invalid rows are rejected individually, never fatally."""
    rows, _columns = parse_export(text)
    merged: dict[str, Indicator] = {}
    rejected: list[dict[str, str]] = []

    for row in rows:
        try:
            indicator = _indicator_from_row(row, bronze_ref, ingest_version)
        except (InvalidIndicator, ValueError, TypeError) as exc:
            rejected.append({"url": (row.get("url") or "").strip(), "reason": str(exc)})
            continue
        previous = merged.get(indicator.id)
        merged[indicator.id] = (
            indicator if previous is None else merge_indicators(previous, indicator)
        )

    indicators = sorted(merged.values(), key=lambda item: item.value)
    return UrlhausResult(indicators=indicators, rejected=rejected)
