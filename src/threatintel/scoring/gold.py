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
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from threatintel.normalize.silver import indicator_from_row, indicator_row
from threatintel.scoring.engine import Reason, Score, ScoredIndicator, ScoringReport

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


__all__ = ["GOLD_SCHEMA", "GoldTable", "read_gold", "write_gold"]
