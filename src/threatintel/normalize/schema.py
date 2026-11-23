"""The indicator contract: identity, normalization and merge.

Two rows are the *same* indicator when `(type, normalized value)` match, and the id is
derived from exactly that pair. Deterministic ids are not a detail: a random UUID would
create a second copy on every re-ingest, and would silently detach a manual review from
the indicator it was about.

Normalization is worth this much code because every downstream join depends on it.
`1.2.3.4`, `001.002.003.004` and `1.2.3.4 ` must be one indicator, or corroboration
counts and review history both break.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

# uuid5(NAMESPACE_DNS, "threatintel-pipeline") — fixed forever; changing it silently
# renumbers every indicator, so it is a breaking change, not a refactor.
ID_NAMESPACE = uuid.UUID("ed12ad7d-ac31-5a93-aa0b-0b0002597a58")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DOMAIN_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
HASH_LENGTHS = {32, 40, 64}
MAX_DOMAIN_LENGTH = 253
DEFAULT_PORTS = {("http", 80), ("https", 443)}


class InvalidIndicator(ValueError):
    """The value cannot be normalized to the declared type."""


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CVE = "cve"


def normalize_ip(value: str) -> str:
    raw = value.strip()
    if "/" in raw:
        raise InvalidIndicator(f"CIDR range is not an indicator: {value!r}")
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise InvalidIndicator(f"not an IP address: {value!r}") from exc
    # Fold IPv4-mapped IPv6 onto its IPv4 form, otherwise the same host counts twice.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def normalize_domain(value: str) -> str:
    raw = value.strip().rstrip(".").lower()
    if raw.startswith("*."):
        raw = raw[2:]
    if not raw or len(raw) > MAX_DOMAIN_LENGTH:
        raise InvalidIndicator(f"invalid domain length: {value!r}")
    if any(ch in raw for ch in "/@:? \\"):
        raise InvalidIndicator(f"invalid character in domain: {value!r}")
    try:
        ascii_domain = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidIndicator(f"domain is not IDNA-encodable: {value!r}") from exc
    labels = ascii_domain.split(".")
    if len(labels) < 2:
        raise InvalidIndicator(f"single-label domain is not a public indicator: {value!r}")
    if any(not DOMAIN_LABEL_RE.match(label) for label in labels):
        raise InvalidIndicator(f"invalid domain label: {value!r}")
    return ascii_domain


def normalize_url(value: str) -> str:
    raw = value.strip()
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InvalidIndicator(f"unsupported URL scheme: {value!r}")
    if not parts.hostname:
        raise InvalidIndicator(f"URL without host: {value!r}")
    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise InvalidIndicator(f"invalid URL port: {value!r}") from exc
    try:
        host = normalize_ip(hostname)
    except InvalidIndicator:
        host = normalize_domain(hostname)
    netloc = host if port is None or (scheme, port) in DEFAULT_PORTS else f"{host}:{port}"
    # Rebuild from parts: this drops userinfo (credentials do not belong in an indicator)
    # and the fragment (client-side only, never sent to the server).
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def normalize_hash(value: str) -> str:
    raw = value.strip().lower()
    if len(raw) not in HASH_LENGTHS or not all(c in "0123456789abcdef" for c in raw):
        raise InvalidIndicator(f"not an md5/sha1/sha256 hex digest: {value!r}")
    return raw


def normalize_cve(value: str) -> str:
    raw = value.strip().upper()
    if not CVE_RE.match(raw):
        raise InvalidIndicator(f"not a CVE identifier: {value!r}")
    return raw


_NORMALIZERS = {
    IndicatorType.IP: normalize_ip,
    IndicatorType.DOMAIN: normalize_domain,
    IndicatorType.URL: normalize_url,
    IndicatorType.HASH: normalize_hash,
    IndicatorType.CVE: normalize_cve,
}


def normalize_value(indicator_type: IndicatorType, value: str) -> str:
    """Normalize `value` for `indicator_type`, raising InvalidIndicator on garbage."""
    try:
        normalizer = _NORMALIZERS[indicator_type]
    except KeyError as exc:
        raise InvalidIndicator(f"unsupported indicator type: {indicator_type!r}") from exc
    return normalizer(value)


def indicator_id(indicator_type: IndicatorType, normalized_value: str) -> str:
    """Stable id from the normalized pair. Same input, same id, on any machine."""
    return str(uuid.uuid5(ID_NAMESPACE, f"{indicator_type.value}|{normalized_value}"))


def _require_aware(moment: datetime, field: str) -> datetime:
    if moment.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware, got naive {moment!r}")
    return moment


class SourceRef(BaseModel):
    """One provider's claim about one indicator."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    external_id: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @model_validator(mode="after")
    def _check(self) -> SourceRef:
        if not self.name.strip():
            raise ValueError("source name cannot be empty")
        if self.first_seen:
            _require_aware(self.first_seen, "source.first_seen")
        if self.last_seen:
            _require_aware(self.last_seen, "source.last_seen")
        return self


class Indicator(BaseModel):
    """A normalized indicator as stored in silver.

    `attributes` is keyed by source name so that merging two sources can never make one
    provider's fields overwrite another's. Source-specific facts stay source-specific.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    type: IndicatorType
    value: str
    sources: list[SourceRef] = Field(default_factory=list)
    source_confidence: dict[str, float] = Field(default_factory=dict)
    distinct_reporters: int = 0
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    usage_type: str | None = None
    fp_reasons: list[str] = Field(default_factory=list)
    attributes: dict[str, dict[str, Any]] = Field(default_factory=dict)
    ingest_version: str
    bronze_refs: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_identity(self) -> Indicator:
        expected_value = normalize_value(self.type, self.value)
        if self.value != expected_value:
            raise ValueError(f"value is not normalized: {self.value!r} != {expected_value!r}")
        if self.id != indicator_id(self.type, self.value):
            raise ValueError(f"id does not match (type, value): {self.id!r}")
        if self.first_seen:
            _require_aware(self.first_seen, "first_seen")
        if self.last_seen:
            _require_aware(self.last_seen, "last_seen")
        return self

    @classmethod
    def build(
        cls,
        *,
        type: IndicatorType,
        value: str,
        sources: list[SourceRef],
        ingest_version: str,
        source_confidence: dict[str, float] | None = None,
        distinct_reporters: int | None = None,
        tags: list[str] | None = None,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
        usage_type: str | None = None,
        fp_reasons: list[str] | None = None,
        attributes: dict[str, dict[str, Any]] | None = None,
        bronze_refs: list[str] | None = None,
    ) -> Indicator:
        normalized = normalize_value(type, value)
        # The indicator's window is the widest window its sources claim, unless a
        # caller sets it explicitly. Deriving it here keeps the two representations
        # from disagreeing after a merge.
        if first_seen is None:
            first_seen = min(
                (ref.first_seen for ref in sources if ref.first_seen is not None), default=None
            )
        if last_seen is None:
            last_seen = max(
                (ref.last_seen for ref in sources if ref.last_seen is not None), default=None
            )
        return cls(
            id=indicator_id(type, normalized),
            type=type,
            value=normalized,
            sources=sources,
            source_confidence=source_confidence or {},
            distinct_reporters=(
                len({ref.name for ref in sources})
                if distinct_reporters is None
                else distinct_reporters
            ),
            tags=tags or [],
            first_seen=first_seen,
            last_seen=last_seen,
            usage_type=usage_type,
            fp_reasons=fp_reasons or [],
            attributes=attributes or {},
            ingest_version=ingest_version,
            bronze_refs=bronze_refs or [],
        )


def _merge_source(existing: SourceRef, incoming: SourceRef) -> SourceRef:
    """Combine two claims from the same provider: earliest sighting, latest sighting."""
    first = min(
        (d for d in (existing.first_seen, incoming.first_seen) if d is not None),
        default=None,
    )
    last = max(
        (d for d in (existing.last_seen, incoming.last_seen) if d is not None),
        default=None,
    )
    return SourceRef(
        name=existing.name,
        external_id=existing.external_id or incoming.external_id,
        first_seen=first,
        last_seen=last,
    )


def merge_indicators(existing: Indicator, incoming: Indicator) -> Indicator:
    """Union two views of the same indicator. Never picks a winner arbitrarily.

    Sources are merged per provider (not appended); dates take the widest window;
    per-source attributes stay under their own source key.
    """
    if existing.id != incoming.id:
        raise ValueError("cannot merge indicators with different ids")

    by_provider: dict[str, SourceRef] = {}
    for ref in (*existing.sources, *incoming.sources):
        by_provider[ref.name] = (
            ref if ref.name not in by_provider else _merge_source(by_provider[ref.name], ref)
        )
    sources = sorted(by_provider.values(), key=lambda ref: ref.name)

    first_seen = min(
        (d for d in (existing.first_seen, incoming.first_seen) if d is not None), default=None
    )
    last_seen = max(
        (d for d in (existing.last_seen, incoming.last_seen) if d is not None), default=None
    )

    confidence = {**existing.source_confidence}
    for name, score in incoming.source_confidence.items():
        confidence[name] = max(score, confidence.get(name, score))

    return Indicator(
        id=existing.id,
        type=existing.type,
        value=existing.value,
        sources=sources,
        source_confidence=confidence,
        distinct_reporters=len(by_provider),
        tags=sorted(set(existing.tags) | set(incoming.tags)),
        first_seen=first_seen,
        last_seen=last_seen,
        usage_type=existing.usage_type or incoming.usage_type,
        fp_reasons=sorted(set(existing.fp_reasons) | set(incoming.fp_reasons)),
        attributes={**existing.attributes, **incoming.attributes},
        ingest_version=incoming.ingest_version,
        bronze_refs=sorted(set(existing.bronze_refs) | set(incoming.bronze_refs)),
    )
