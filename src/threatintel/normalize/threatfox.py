"""Map ThreatFox batches onto silver indicators.

ThreatFox is where the project stops being CVE-only: domains, URLs, IPs and file hashes.
`ip:port` is the awkward case — the port identifies the service, the IP identifies the
host, and only the host is an indicator. The port is kept as an attribute so it is not
silently discarded.

`distinct_reporters` stays 1 here: that field counts *feeds* that report an indicator, and
ThreatFox is one feed. The upstream submitter (ThreatFox's own `reporter` field) is kept
in attributes, because counting it as an independent source would double-count a single
submission that happens to be re-published.
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

SOURCE = "threatfox"
HASH_KINDS = {"md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256"}
SIMPLE_TYPES = {"domain": IndicatorType.DOMAIN, "url": IndicatorType.URL}


@dataclass(frozen=True)
class ThreatFoxResult:
    indicators: list[Indicator]
    rejected: list[dict[str, str]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.indicators)


def _parse_timestamp(value: Any) -> datetime | None:
    """ThreatFox timestamps look like `2020-12-08 13:36:27 UTC`."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S %Z").replace(tzinfo=UTC)
    except ValueError:
        return None


def split_ip_port(ioc: str) -> tuple[str, int | None]:
    """`1.2.3.4:443` -> (ip, port); bare IPv6 addresses survive untouched."""
    if ioc.startswith("["):  # bracketed IPv6: [2001:db8::1]:443
        host, _, rest = ioc.partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        return host[1:], int(port) if port.isdigit() else None
    host, sep, port = ioc.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host, int(port)
    return ioc, None


def _classify(ioc: str, ioc_type: str) -> tuple[IndicatorType, str, dict[str, Any]]:
    if ioc_type in SIMPLE_TYPES:
        return SIMPLE_TYPES[ioc_type], ioc, {}
    if ioc_type == "ip:port":
        host, port = split_ip_port(ioc)
        extras: dict[str, Any] = {"port": port} if port is not None else {}
        return IndicatorType.IP, host, extras
    if ioc_type in HASH_KINDS:
        return IndicatorType.HASH, ioc, {"hash_kind": HASH_KINDS[ioc_type]}
    raise InvalidIndicator(f"unsupported ioc_type: {ioc_type!r}")


def _attributes(entry: dict[str, Any], extras: dict[str, Any]) -> dict[str, Any]:
    attributes = dict(extras)
    for key in (
        "threat_type",
        "threat_type_desc",
        "malware",
        "malware_printable",
        "malware_alias",
        "malware_malpedia",
        "reporter",
        "reference",
        "confidence_level",
    ):
        if entry.get(key) not in (None, "", []):
            attributes[key] = entry[key]
    return attributes


def _confidence(entry: dict[str, Any]) -> dict[str, float]:
    level = entry.get("confidence_level")
    if isinstance(level, int) and 0 <= level <= 100:
        return {SOURCE: level / 100}
    return {}


def _indicator_from_entry(
    entry: dict[str, Any], bronze_ref: str, ingest_version: str
) -> Indicator:
    ioc = entry.get("ioc")
    ioc_type = entry.get("ioc_type")
    if not isinstance(ioc, str) or not ioc.strip():
        raise InvalidIndicator("missing ioc")
    if not isinstance(ioc_type, str) or not ioc_type.strip():
        raise InvalidIndicator("missing ioc_type")

    indicator_type, value, extras = _classify(ioc.strip(), ioc_type.strip())
    first_seen = _parse_timestamp(entry.get("first_seen"))
    last_seen = _parse_timestamp(entry.get("last_seen"))
    feed_tags = entry.get("tags") if isinstance(entry.get("tags"), list) else []
    tags = {str(tag).strip() for tag in feed_tags if str(tag).strip()}
    threat_type = entry.get("threat_type")
    if isinstance(threat_type, str) and threat_type:
        tags.add(threat_type)

    external_id = entry.get("id")
    return Indicator.build(
        type=indicator_type,
        value=value,
        sources=[
            SourceRef(
                name=SOURCE,
                external_id=str(external_id) if external_id is not None else None,
                first_seen=first_seen,
                last_seen=last_seen,
            )
        ],
        source_confidence=_confidence(entry),
        tags=sorted(tags),
        first_seen=first_seen,
        last_seen=last_seen,
        attributes={SOURCE: _attributes(entry, extras)},
        ingest_version=ingest_version,
        bronze_refs=[bronze_ref],
    )


def indicators_from_threatfox(
    payload: dict[str, Any],
    *,
    bronze_ref: str,
    ingest_version: str = __version__,
) -> ThreatFoxResult:
    merged: dict[str, Indicator] = {}
    rejected: list[dict[str, str]] = []

    for entry in payload.get("data") or []:
        if not isinstance(entry, dict):
            rejected.append({"ioc": "", "reason": "entry is not an object"})
            continue
        try:
            indicator = _indicator_from_entry(entry, bronze_ref, ingest_version)
        except (InvalidIndicator, ValueError, TypeError) as exc:
            rejected.append({"ioc": str(entry.get("ioc", "")), "reason": str(exc)})
            continue
        previous = merged.get(indicator.id)
        merged[indicator.id] = (
            indicator if previous is None else merge_indicators(previous, indicator)
        )

    indicators = sorted(merged.values(), key=lambda item: (item.type.value, item.value))
    return ThreatFoxResult(indicators=indicators, rejected=rejected)
