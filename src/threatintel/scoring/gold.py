"""The gold table: silver rows plus the score and the reasons behind it.

One flat Parquet file, same reasoning as silver (`docs/decisions/0003`). The score columns
are stored as ordinary columns, and the reasons as JSON, so DuckDB can read the table
without the project's models and the API can serve it without recomputing rules.

The file is derived output and lives under `data/`, which is gitignored. `write_gold` is
atomic for the same reason silver is: a half-written gold table is worse than a stale one,
because the API would serve it with no sign that it is truncated.
"""

from __future__ import annotations

import json
import os
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
    ]
)


def _gold_row(item: ScoredIndicator) -> dict[str, object]:
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
        }
    )
    return row


def write_gold(report: ScoringReport, path: Path) -> Path:
    """Write the scored table, highest score first."""
    rows = [
        _gold_row(item)
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


def read_gold(path: Path) -> list[ScoredIndicator]:
    """Load gold back into models so tests and the API exercise the same contract."""
    scored: list[ScoredIndicator] = []
    for row in pq.read_table(path).to_pylist():
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
    return scored


__all__ = ["GOLD_SCHEMA", "read_gold", "write_gold"]
