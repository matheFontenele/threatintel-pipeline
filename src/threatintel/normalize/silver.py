"""Read and write the silver indicator table as Parquet.

One flat file rather than a partition tree: at tens of thousands of rows a single
Parquet file scans faster than any partitioning scheme and eliminates a class of
"file exists but is the wrong version" bugs. Partitioning is a scale decision, deferred
with the storage one (docs/decisions/0003).

Nested values are stored as JSON strings (`sources_json`, `attributes_json`). Parquet
would represent them as structs, but the field sets differ per source, and a column
union that grows with every feed is worse than a string DuckDB can `json_extract` from.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from threatintel.normalize.schema import Indicator, IndicatorType, SourceRef, merge_indicators

SILVER_SCHEMA = pa.schema(
    [
        pa.field("id", pa.string(), nullable=False),
        pa.field("type", pa.string(), nullable=False),
        pa.field("value", pa.string(), nullable=False),
        pa.field("sources_json", pa.string(), nullable=False),
        pa.field("source_confidence_json", pa.string(), nullable=False),
        pa.field("distinct_reporters", pa.int32(), nullable=False),
        pa.field("tags", pa.list_(pa.string())),
        pa.field("first_seen", pa.timestamp("us", tz="UTC")),
        pa.field("last_seen", pa.timestamp("us", tz="UTC")),
        pa.field("usage_type", pa.string()),
        pa.field("fp_reasons", pa.list_(pa.string())),
        pa.field("attributes_json", pa.string(), nullable=False),
        pa.field("ingest_version", pa.string(), nullable=False),
        pa.field("bronze_refs", pa.list_(pa.string())),
    ]
)


def indicator_row(indicator: Indicator) -> dict[str, object]:
    return {
        "id": indicator.id,
        "type": indicator.type.value,
        "value": indicator.value,
        "sources_json": json.dumps(
            [ref.model_dump(mode="json") for ref in indicator.sources], sort_keys=True
        ),
        "source_confidence_json": json.dumps(indicator.source_confidence, sort_keys=True),
        "distinct_reporters": indicator.distinct_reporters,
        "tags": indicator.tags,
        "first_seen": indicator.first_seen,
        "last_seen": indicator.last_seen,
        "usage_type": indicator.usage_type,
        "fp_reasons": indicator.fp_reasons,
        "attributes_json": json.dumps(indicator.attributes, sort_keys=True),
        "ingest_version": indicator.ingest_version,
        "bronze_refs": indicator.bronze_refs,
    }


def write_indicators(indicators: Iterable[Indicator], path: Path) -> Path:
    """Write sorted, deterministic Parquet via temp file + replace.

    Atomic because a partially written silver file is worse than a stale one: the API
    would serve a truncated dataset with no indication that it is truncated.
    """
    rows = [
        indicator_row(item) for item in sorted(indicators, key=lambda i: (i.type.value, i.value))
    ]
    table = pa.Table.from_pylist(rows, schema=SILVER_SCHEMA)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    pq.write_table(table, tmp)
    os.replace(tmp, path)
    return path


def indicator_from_row(row: dict[str, object]) -> Indicator:
    """Rebuild one indicator from a stored row. Shared with the gold table reader."""
    return Indicator(
        id=row["id"],
        type=IndicatorType(row["type"]),
        value=row["value"],
        sources=[SourceRef(**ref) for ref in json.loads(row["sources_json"])],
        source_confidence=json.loads(row["source_confidence_json"]),
        distinct_reporters=row["distinct_reporters"],
        tags=row["tags"] or [],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        usage_type=row["usage_type"],
        fp_reasons=row["fp_reasons"] or [],
        attributes=json.loads(row["attributes_json"]),
        ingest_version=row["ingest_version"],
        bronze_refs=row["bronze_refs"] or [],
    )


def read_indicators(path: Path) -> list[Indicator]:
    """Load silver back into models. Validators run on read, so a corrupt file fails loudly."""
    return [indicator_from_row(row) for row in pq.read_table(path).to_pylist()]


def upsert_indicators(existing_path: Path, incoming: Iterable[Indicator], out_path: Path) -> Path:
    """Merge new indicators into the existing table, keyed by the deterministic id.

    Re-running a collection is therefore additive and idempotent: the same source cannot
    inflate `distinct_reporters`, and a new source enriches the existing row instead of
    duplicating it.
    """
    merged: dict[str, Indicator] = {}
    if existing_path.exists():
        for indicator in read_indicators(existing_path):
            merged[indicator.id] = indicator
    for indicator in incoming:
        previous = merged.get(indicator.id)
        merged[indicator.id] = (
            indicator if previous is None else merge_indicators(previous, indicator)
        )
    return write_indicators(merged.values(), out_path)


__all__ = [
    "SILVER_SCHEMA",
    "indicator_from_row",
    "indicator_row",
    "read_indicators",
    "upsert_indicators",
    "write_indicators",
]