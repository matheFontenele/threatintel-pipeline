"""The gold table: silver rows plus the score and the reasons behind it.

One flat Parquet file, same reasoning as silver (`docs/decisions/0003`). The score columns
are stored as ordinary columns, and the reasons as JSON, so DuckDB can read the table
without the project's models and the API can serve it without recomputing rules.

The file is derived output and lives under `data/`, which is gitignored. `write_gold` is
atomic for the same reason silver is: a half-written gold table is worse than a stale one,
because the API would serve it with no sign that it is truncated.

The run metadata (`as_of`, both config hashes) is stored per row rather than in a sidecar.
A sidecar is two files that can be separated or half-replaced; a repeated string costs
almost nothing after Parquet dictionary encoding, and a row copied out of the table can
still name the run that produced it. A table that mixes rows from two runs is rejected on
read, because that is the failure a per-row design would otherwise permit.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from threatintel.normalize.schema import IndicatorType
from threatintel.normalize.silver import indicator_from_row, indicator_row
from threatintel.scoring.engine import (
    Reason,
    Score,
    ScoredIndicator,
    ScoringReport,
    VulnRow,
)

GOLD_SCHEMA = pa.schema(
    [
        pa.field("id", pa.string(), nullable=False),
        pa.field("type", pa.string(), nullable=False),
        pa.field("value", pa.string(), nullable=False),
        pa.field("score", pa.int32(), nullable=False),
        pa.field("band", pa.string(), nullable=False),
        pa.field("needs_review", pa.bool_(), nullable=False),
        pa.field("score_reasons_json", pa.string(), nullable=False),
        pa.field("score_caps", pa.list_(pa.string())),
        pa.field("policy_version", pa.string(), nullable=False),
        pa.field("policy_config_hash", pa.string(), nullable=False),
        pa.field("fp_reasons", pa.list_(pa.string())),
        pa.field("sources_json", pa.string(), nullable=False),
        pa.field("source_confidence_json", pa.string(), nullable=False),
        pa.field("distinct_reporters", pa.int32(), nullable=False),
        pa.field("tags", pa.list_(pa.string())),
        pa.field("first_seen", pa.timestamp("us", tz="UTC")),
        pa.field("last_seen", pa.timestamp("us", tz="UTC")),
        pa.field("usage_type", pa.string()),
        pa.field("attributes_json", pa.string(), nullable=False),
        pa.field("ingest_version", pa.string(), nullable=False),
        pa.field("bronze_refs", pa.list_(pa.string())),
        pa.field("as_of", pa.timestamp("us", tz="UTC"), nullable=False),
        pa.field("rules_config_hash", pa.string(), nullable=False),
    ]
)


@dataclass(frozen=True)
class GoldTable:
    """One scored run: the rows plus the metadata that makes them reproducible."""

    as_of: datetime | None
    policy_config_hash: str | None
    rules_config_hash: str | None
    items: tuple[ScoredIndicator, ...]


def _gold_row(
    item: ScoredIndicator, *, as_of: datetime, rules_config_hash: str
) -> dict[str, object]:
    row = indicator_row(item.indicator)
    score = item.score
    row.update(
        {
            "score": score.score,
            "band": score.band,
            "needs_review": score.needs_review,
            "score_reasons_json": json.dumps(
                [
                    {"code": reason.code, "weight": reason.weight, "detail": reason.detail}
                    for reason in score.reasons
                ],
                sort_keys=True,
            ),
            "score_caps": list(score.caps),
            "policy_version": score.policy_version,
            "policy_config_hash": score.policy_config_hash,
            "as_of": as_of,
            "rules_config_hash": rules_config_hash,
        }
    )
    return row


def write_gold(report: ScoringReport, path: Path) -> Path:
    """Write the scored table, highest score first."""
    if any(item.indicator.type is IndicatorType.CVE for item in report.scored):
        raise ValueError(
            "the gold indicator table must not contain CVE rows; "
            "write them with write_vulnerabilities"
        )
    rows = [
        _gold_row(item, as_of=report.as_of, rules_config_hash=report.rules_config_hash)
        for item in sorted(
            report.scored,
            key=lambda entry: (
                -entry.score.score,
                entry.indicator.type.value,
                entry.indicator.value,
            ),
        )
    ]
    table = pa.Table.from_pylist(rows, schema=GOLD_SCHEMA)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    pq.write_table(table, tmp)
    os.replace(tmp, path)
    return path


def read_gold(path: Path) -> GoldTable:
    """Load gold back into models so tests and the API exercise the same contract."""
    rows = pq.read_table(path).to_pylist()
    if not rows:
        return GoldTable(as_of=None, policy_config_hash=None, rules_config_hash=None, items=())

    runs = {(row["as_of"], row["policy_config_hash"], row["rules_config_hash"]) for row in rows}
    if len(runs) > 1:
        raise ValueError(f"gold table mixes {len(runs)} runs; rewrite it with one scoring run")

    scored: list[ScoredIndicator] = []
    for row in rows:
        reasons = tuple(
            Reason(code=item["code"], weight=item["weight"], detail=item["detail"])
            for item in json.loads(row["score_reasons_json"])
        )
        score = Score(
            indicator_id=row["id"],
            score=row["score"],
            band=row["band"],
            needs_review=row["needs_review"],
            reasons=reasons,
            caps=tuple(row["score_caps"] or []),
            policy_version=row["policy_version"],
            policy_config_hash=row["policy_config_hash"],
        )
        scored.append(ScoredIndicator(indicator=indicator_from_row(row), score=score))

    first = rows[0]
    return GoldTable(
        as_of=first["as_of"],
        policy_config_hash=first["policy_config_hash"],
        rules_config_hash=first["rules_config_hash"],
        items=tuple(scored),
    )


# --- vulnerability track --------------------------------------------------------------
#
# A separate file, not a column. Merging the two would recreate the defect this change
# removes: one ranking over two units, where the top of the list is "the catalogue said so"
# and the bottom is "a feed said so", and neither answers "does this matter to me".

VULN_SCHEMA = pa.schema(
    [
        pa.field("id", pa.string(), nullable=False),
        pa.field("cve_id", pa.string(), nullable=False),
        pa.field("date_added", pa.timestamp("us", tz="UTC")),
        pa.field("due_date", pa.timestamp("us", tz="UTC")),
        pa.field("ransomware", pa.bool_(), nullable=False),
        pa.field("vendor_project", pa.string()),
        pa.field("product", pa.string()),
        pa.field("required_action", pa.string()),
        pa.field("short_description", pa.string()),
        pa.field("cwes", pa.list_(pa.string())),
        pa.field("notes", pa.string()),
        pa.field("tags", pa.list_(pa.string())),
        pa.field("sources_json", pa.string(), nullable=False),
        pa.field("bronze_refs", pa.list_(pa.string())),
        pa.field("ingest_version", pa.string(), nullable=False),
        pa.field("as_of", pa.timestamp("us", tz="UTC"), nullable=False),
    ]
)


@dataclass(frozen=True)
class VulnTable:
    """The catalogue as stored: one clock, no score. Mixed runs are rejected on read."""

    as_of: datetime | None
    rows: tuple[dict[str, object], ...]


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _text_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return []


def _date(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return None


def _vuln_row(item: VulnRow, *, as_of: datetime) -> dict[str, object]:
    indicator = item.indicator
    ransomware = item.ransomware
    return {
        "id": indicator.id,
        "cve_id": item.cve_id,
        # The normalizer sets `first_seen` from the catalogue's own `dateAdded`, so this is
        # the publication date, not the date this pipeline first fetched the row.
        "date_added": indicator.first_seen,
        "due_date": _date(item.fact("dueDate")),
        "ransomware": ransomware,
        "vendor_project": _text(item.fact("vendorProject")),
        "product": _text(item.fact("product")),
        "required_action": _text(item.fact("requiredAction")),
        "short_description": _text(item.fact("shortDescription")),
        "cwes": _text_list(item.fact("cwes")),
        "notes": _text(item.fact("notes")),
        "tags": list(indicator.tags),
        "sources_json": json.dumps(
            [ref.model_dump(mode="json") for ref in indicator.sources], sort_keys=True
        ),
        "bronze_refs": list(indicator.bronze_refs),
        "ingest_version": indicator.ingest_version,
        "as_of": as_of,
    }


def _vuln_sort_key(row: dict[str, object]) -> tuple[bool, float, str]:
    added = row["date_added"]
    if isinstance(added, datetime):
        return (False, -added.timestamp(), str(row["cve_id"]))
    return (True, 0.0, str(row["cve_id"]))


def write_vulnerabilities(rows: Iterable[VulnRow], path: Path, *, as_of: datetime) -> Path:
    """Write the catalogue in `date_added DESC, cve_id ASC` order.

    Chronology, not priority. Sorting by ransomware flag or remediation deadline would
    smuggle a ranking into the one track that exists because the ranking was not honest.
    """
    payload = [_vuln_row(item, as_of=as_of) for item in rows]
    payload.sort(key=_vuln_sort_key)
    table = pa.Table.from_pylist(payload, schema=VULN_SCHEMA)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    pq.write_table(table, tmp)
    os.replace(tmp, path)
    return path


def read_vulnerabilities(path: Path) -> VulnTable:
    """Load the catalogue back, rejecting a table assembled from more than one run."""
    rows = pq.read_table(path).to_pylist()
    if not rows:
        return VulnTable(as_of=None, rows=())
    clocks = {row["as_of"] for row in rows}
    if len(clocks) > 1:
        raise ValueError(
            f"vulnerability table mixes {len(clocks)} runs; rewrite it with one scoring run"
        )
    return VulnTable(as_of=rows[0]["as_of"], rows=tuple(rows))


__all__ = [
    "GOLD_SCHEMA",
    "GoldTable",
    "VULN_SCHEMA",
    "VulnTable",
    "read_gold",
    "read_vulnerabilities",
    "write_gold",
    "write_vulnerabilities",
]
