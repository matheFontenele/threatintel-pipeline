"""Map Feodo Tracker batches onto silver indicators.

Feodo is a list of *entries*, not of indicators: the same C2 IP appears once per open port.
The indicator is the IP; the ports are attributes. Collapsing them keeps
`distinct_reporters` and the id stable when a botnet opens one more port.

`status` is aggregated conservatively: an IP is `online` if **any** of its entries says so,
because a live C2 on one port is a live C2. The individual statuses stay in attributes so
the aggregation is auditable instead of lossy.

Confidence is 1.0 per source: Feodo publishes confirmed botnet C2s and prunes the rest. It
is a statement of what the feed means, not a claim that every entry is still live — that is
what `status` and `last_seen` are for.
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
    normalize_ip,
)

SOURCE = "feodo"


@dataclass(frozen=True)
class FeodoResult:
    indicators: list[Indicator]
    rejected: list[dict[str, str]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.indicators)


def _parse_timestamp(value: Any) -> datetime | None:
    """Feodo timestamps look like `2026-11-23 06:00:00`, served in UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def _malware_tags(value: Any) -> set[str]:
    if not isinstance(value, str):
        return set()
    return {part.strip() for part in value.replace(";", ",").split(",") if part.strip()}


def _sorted_unique(values: list[Any]) -> list[Any]:
    seen: dict[Any, None] = {}
    for value in values:
        if value not in (None, ""):
            seen[value] = None
    return sorted(seen)


def _indicator_from_entries(
    ip: str,
    entries: list[dict[str, Any]],
    bronze_ref: str,
    ingest_version: str,
) -> Indicator:
    ports: set[int] = set()
    statuses: set[str] = set()
    countries: list[Any] = []
    as_names: list[Any] = []
    as_numbers: list[Any] = []
    hostnames: list[Any] = []
    malware: set[str] = set()
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    for entry in entries:
        port = entry.get("port")
        if not isinstance(port, int) or not 0 <= port <= 65535:
            raise InvalidIndicator(f"invalid port: {port!r}")
        ports.add(port)
        status = entry.get("status")
        if status not in {"online", "offline"}:
            raise InvalidIndicator(f"invalid status: {status!r}")
        statuses.add(status)
        countries.append(entry.get("country"))
        as_names.append(entry.get("as_name"))
        as_numbers.append(entry.get("as_number"))
        hostnames.append(entry.get("hostname"))
        malware |= _malware_tags(entry.get("malware"))

        seen = _parse_timestamp(entry.get("first_seen"))
        if seen is not None:
            first_seen = seen if first_seen is None else min(first_seen, seen)
        online = _parse_timestamp(entry.get("last_online"))
        if online is not None:
            last_seen = online if last_seen is None else max(last_seen, online)

    status = "online" if "online" in statuses else "offline"
    attributes = {
        "ports": sorted(ports),
        "status": status,
        "statuses": sorted(statuses),
        "countries": _sorted_unique(countries),
        "as_names": _sorted_unique(as_names),
        "as_numbers": _sorted_unique(as_numbers),
        "hostnames": _sorted_unique(hostnames),
        "entries": len(entries),
    }

    return Indicator.build(
        type=IndicatorType.IP,
        value=ip,
        sources=[
            SourceRef(name=SOURCE, first_seen=first_seen, last_seen=last_seen),
        ],
        source_confidence={SOURCE: 1.0},
        tags=sorted(malware),
        first_seen=first_seen,
        last_seen=last_seen,
        attributes={SOURCE: attributes},
        ingest_version=ingest_version,
        bronze_refs=[bronze_ref],
    )


def indicators_from_feodo(
    payload: Any,
    *,
    bronze_ref: str,
    ingest_version: str = __version__,
) -> FeodoResult:
    rejected: list[dict[str, str]] = []
    if not isinstance(payload, list):
        return FeodoResult(
            indicators=[],
            rejected=[{"ip": "", "reason": "payload is not a JSON array"}],
        )

    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in payload:
        if not isinstance(entry, dict):
            rejected.append({"ip": "", "reason": "entry is not an object"})
            continue
        raw_ip = entry.get("ip_address")
        if not isinstance(raw_ip, str) or not raw_ip.strip():
            rejected.append({"ip": "", "reason": "missing ip_address"})
            continue
        try:
            normalized = normalize_ip(raw_ip)
        except InvalidIndicator as exc:
            rejected.append({"ip": raw_ip, "reason": str(exc)})
            continue
        grouped.setdefault(normalized, []).append(entry)

    merged: dict[str, Indicator] = {}
    for ip, entries in grouped.items():
        try:
            indicator = _indicator_from_entries(ip, entries, bronze_ref, ingest_version)
        except (InvalidIndicator, ValueError, TypeError) as exc:
            rejected.append({"ip": ip, "reason": str(exc)})
            continue
        previous = merged.get(indicator.id)
        merged[indicator.id] = (
            indicator if previous is None else merge_indicators(previous, indicator)
        )

    indicators = sorted(merged.values(), key=lambda item: (item.type.value, item.value))
    return FeodoResult(indicators=indicators, rejected=rejected)
