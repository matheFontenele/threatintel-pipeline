"""Response models for the read API.

They are deliberately explicit rather than returning raw rows. Three reasons:

- the OpenAPI contract is the product (`decisions/0009`), so every field is documented;
- a row from gold is never forwarded blindly: `attributes` and `sources` are source-specific
  JSON, and an explicit model is where that shape is confirmed rather than assumed;
- changing a field is a visible edit in this file, which is the reviewable place for a
  compatibility decision.

`value` is returned as data. The API never renders it into HTML or CSV; escaping on output
is the consumer's job (threat model B4), and the security headers say the response is JSON,
not a document.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class SourceRefOut(BaseModel):
    name: str
    external_id: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class ReasonOut(BaseModel):
    code: str
    weight: int
    detail: str


class IndicatorSummary(BaseModel):
    """What a list row carries: the score, its reasons, and how to fetch the rest."""

    id: str
    type: str
    value: str
    score: int
    band: str
    needs_review: bool
    reasons: list[ReasonOut]
    caps: list[str]
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sources: list[SourceRefOut]


class IndicatorDetail(IndicatorSummary):
    """The list row plus the fields that are too large or too specific for a page."""

    tags: list[str]
    usage_type: str | None = None
    fp_reasons: list[str]
    attributes: dict[str, dict[str, Any]]
    ingest_version: str
    bronze_refs: list[str]
    policy_version: str
    policy_config_hash: str


class RunMeta(BaseModel):
    """The clock and both hashes. A result without these cannot be reproduced."""

    as_of: datetime | None
    policy_version: str | None
    policy_config_hash: str | None
    rules_config_hash: str | None
    indicators: int


class Page(BaseModel):
    run: RunMeta
    items: list[IndicatorSummary]
    next_cursor: str | None
    limit: int


class Detail(BaseModel):
    run: RunMeta
    indicator: IndicatorDetail


class BandCounts(BaseModel):
    high: int
    medium: int
    low: int


class VulnerabilitySummary(BaseModel):
    """One catalogue entry. No score, no band: this track publishes facts only."""

    id: str
    cve_id: str
    date_added: datetime | None = None
    due_date: datetime | None = None
    ransomware: bool
    vendor_project: str | None = None
    product: str | None = None
    required_action: str | None = None
    short_description: str | None = None
    cwes: list[str]
    notes: str | None = None
    tags: list[str]
    sources: list[SourceRefOut]
    bronze_refs: list[str]
    ingest_version: str


class VulnRunMeta(BaseModel):
    """The clock and the row count. A catalogue has no policy to hash."""

    as_of: datetime | None
    vulnerabilities: int


class VulnPage(BaseModel):
    run: VulnRunMeta
    items: list[VulnerabilitySummary]
    next_cursor: str | None
    limit: int


class VulnerabilityStats(BaseModel):
    count: int
    ransomware: int
    earliest_date_added: datetime | None = None
    latest_date_added: datetime | None = None


class Stats(BaseModel):
    run: RunMeta
    bands: BandCounts
    distinct_scores: int
    needs_review: int
    reasons: dict[str, int]
    vulnerabilities: VulnerabilityStats


class Health(BaseModel):
    status: str
    indicators: int
    vulnerabilities: int


class ErrorBody(BaseModel):
    code: str
    message: str
    fields: list[dict[str, str]] | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody
