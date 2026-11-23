"""Read-only access to the gold table for the HTTP API.

The API is the only reader of the store (threat model B3, `decisions/0009`). It opens the
Parquet file through an in-memory DuckDB view, so the analytical engine is the same one the
project already documents, and no process holds a writable handle.

Three properties matter more than throughput at this scale:

- **Every user value is a bound parameter.** Filters build SQL fragments from a fixed set of
  column names; the values themselves never reach the string.
- **Pagination is keyset, not offset.** A gold table is replaced atomically, so an offset page
  can skip or repeat rows between requests. The cursor is `(score, id)`; `id` is unique and
  stable, which is why it is the tiebreaker and not the indicator value.
- **One run per process.** The Parquet file is copied into an in-memory DuckDB table at
  startup. A long-lived view over `read_parquet` would resolve the path per query, so a
  `make gold` landing between two queries could serve rows from one run with metadata from
  another. Pinning the table makes the run a property of the process: a new score set is
  published by restarting the API, which is a deliberate, visible event. A table whose rows
  disagree about the run is rejected at startup, the same way `read_gold` rejects it.
"""

from __future__ import annotations

import base64
import binascii
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb


class GoldStoreError(RuntimeError):
    """The gold table exists but can no longer be read. Mapped to 503 by the API."""


class InvalidCursor(ValueError):
    """The cursor did not decode to `(score, id)`. Mapped to 400 by the API."""


@dataclass(frozen=True)
class Cursor:
    score: int
    indicator_id: str

    def encode(self) -> str:
        raw = json.dumps(
            {"score": self.score, "id": self.indicator_id}, separators=(",", ":")
        ).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @classmethod
    def decode(cls, token: str) -> Cursor:
        try:
            padded = token + "=" * (-len(token) % 4)
            payload = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
            data = json.loads(payload)
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise InvalidCursor("cursor is not base64url-encoded JSON") from exc

        if not isinstance(data, dict):
            raise InvalidCursor("cursor payload is not an object")
        score = data.get("score")
        indicator_id = data.get("id")
        if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
            raise InvalidCursor("cursor score must be an integer in 0..100")
        if not isinstance(indicator_id, str) or not 1 <= len(indicator_id) <= 64:
            raise InvalidCursor("cursor id is missing or too long")
        return cls(score=score, indicator_id=indicator_id)


_LIST_COLUMNS = """
    id, type, value, score, band, needs_review, score_reasons_json, score_caps,
    first_seen, last_seen, sources_json
"""


def _summary_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "type": row["type"],
        "value": row["value"],
        "score": row["score"],
        "band": row["band"],
        "needs_review": row["needs_review"],
        "reasons": json.loads(row["score_reasons_json"]),
        "caps": row["score_caps"] or [],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "sources": json.loads(row["sources_json"]),
    }


class GoldStore:
    """One in-memory snapshot of one scored run, queried under one lock."""

    def __init__(self, path: Path):
        if not path.is_file():
            raise FileNotFoundError(f"gold table not found: {path}")
        self.path = path
        # A single connection keeps the process from opening a writable handle; the lock is
        # duckdb's requirement, not a claim that the workload is contended.
        self._lock = threading.Lock()
        self._connection = duckdb.connect(":memory:")
        literal = str(path).replace("'", "''")
        self._connection.execute(
            f"CREATE TABLE gold AS SELECT * FROM read_parquet('{literal}')"
        )
        runs = self._rows(
            """
            SELECT
                count(DISTINCT as_of) AS clocks,
                count(DISTINCT policy_config_hash) AS policies,
                count(DISTINCT rules_config_hash) AS rule_sets
            FROM gold
            """
        )[0]
        if max(runs.values()) > 1:
            self._connection.close()
            raise GoldStoreError(
                "gold table mixes runs; rewrite it with one scoring run"
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _rows(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        try:
            with self._lock:
                cursor = self._connection.execute(sql, params or [])
                columns = [description[0] for description in cursor.description]
                return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]
        except duckdb.Error as exc:
            raise GoldStoreError("gold table is not readable") from exc

    # --- metadata ---------------------------------------------------------------------

    def run_meta(self) -> dict[str, Any]:
        rows = self._rows(
            """
            SELECT
                min(as_of) AS as_of,
                min(policy_version) AS policy_version,
                min(policy_config_hash) AS policy_config_hash,
                min(rules_config_hash) AS rules_config_hash,
                count(*) AS indicators
            FROM gold
            """
        )
        return rows[0]

    def health(self) -> dict[str, Any]:
        rows = self._rows("SELECT count(*) AS indicators FROM gold")
        return {"status": "ok", "indicators": rows[0]["indicators"]}

    # --- indicators -------------------------------------------------------------------

    def list_indicators(
        self,
        *,
        indicator_type: str | None = None,
        band: str | None = None,
        min_score: int | None = None,
        max_score: int | None = None,
        reason: str | None = None,
        source: str | None = None,
        needs_review: bool | None = None,
        limit: int = 50,
        cursor: Cursor | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """One page, highest score first. Returns `(items, next_cursor)`."""
        conditions: list[str] = []
        params: list[Any] = []

        if indicator_type is not None:
            conditions.append("type = ?")
            params.append(indicator_type)
        if band is not None:
            conditions.append("band = ?")
            params.append(band)
        if min_score is not None:
            conditions.append("score >= ?")
            params.append(min_score)
        if max_score is not None:
            conditions.append("score <= ?")
            params.append(max_score)
        if needs_review is not None:
            conditions.append("needs_review = ?")
            params.append(needs_review)
        if reason is not None:
            conditions.append(
                "EXISTS (SELECT 1 FROM json_each(score_reasons_json::JSON) AS r"
                " WHERE json_extract_string(r.value, '$.code') = ?)"
            )
            params.append(reason)
        if source is not None:
            conditions.append(
                "EXISTS (SELECT 1 FROM json_each(sources_json::JSON) AS s"
                " WHERE json_extract_string(s.value, '$.name') = ?)"
            )
            params.append(source)
        if cursor is not None:
            conditions.append("(score < ? OR (score = ? AND id > ?))")
            params.extend([cursor.score, cursor.score, cursor.indicator_id])

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT {_LIST_COLUMNS} FROM gold{where}"
            " ORDER BY score DESC, id ASC LIMIT ?"
        )
        params.append(limit + 1)

        rows = self._rows(sql, params)
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            next_cursor = Cursor(score=last["score"], indicator_id=last["id"]).encode()
        return [_summary_row(row) for row in rows], next_cursor

    def get_indicator(self, indicator_id: str) -> dict[str, Any] | None:
        rows = self._rows("SELECT * FROM gold WHERE id = ? LIMIT 1", [indicator_id])
        if not rows:
            return None
        row = rows[0]
        detail = _summary_row(row)
        detail.update(
            {
                "tags": row["tags"] or [],
                "usage_type": row["usage_type"],
                "fp_reasons": row["fp_reasons"] or [],
                "attributes": json.loads(row["attributes_json"]),
                "ingest_version": row["ingest_version"],
                "bronze_refs": row["bronze_refs"] or [],
                "policy_version": row["policy_version"],
                "policy_config_hash": row["policy_config_hash"],
            }
        )
        return detail

    # --- aggregates -------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        band_rows = self._rows("SELECT band, count(*) AS n FROM gold GROUP BY band")
        counts = {row["band"]: row["n"] for row in band_rows}
        review = self._rows("SELECT count(*) AS n FROM gold WHERE needs_review")
        distinct = self._rows("SELECT count(DISTINCT score) AS n FROM gold")[0]["n"]
        reason_rows = self._rows(
            """
            SELECT json_extract_string(reason.value, '$.code') AS code, count(*) AS n
            FROM gold, json_each(gold.score_reasons_json::JSON) AS reason
            GROUP BY code
            ORDER BY code
            """
        )
        return {
            "bands": {band: counts.get(band, 0) for band in ("high", "medium", "low")},
            "distinct_scores": distinct,
            "needs_review": review[0]["n"],
            "reasons": {row["code"]: row["n"] for row in reason_rows},
        }


__all__ = ["Cursor", "GoldStore", "GoldStoreError", "InvalidCursor"]
