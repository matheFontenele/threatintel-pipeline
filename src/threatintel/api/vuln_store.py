"""Read-only access to the vulnerability catalogue for the HTTP API.

Same three properties as `GoldStore` — bound parameters, keyset pagination, one run per
process — with one difference that matters: there is no score column. Reusing the
`(score, id)` cursor would let a token from `/v1/indicators` decode as valid here, and the
two endpoints would paginate different tables with the same token. `VulnCursor` is a
distinct payload with its own version tag, so cross-endpoint use fails loudly.

Ordering is `date_added DESC, cve_id ASC` — chronology, not priority. A row without a
publication date sorts last (`NULL_ORDER_KEY`) rather than being invented or dropped.
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

from threatintel.api.store import GoldStoreError, InvalidCursor

# -1: smaller than any real epoch-microsecond value, so undated rows sort last under DESC.
NULL_ORDER_KEY = -1
_ORDER_KEY_SQL = f"coalesce(epoch_us(date_added), {NULL_ORDER_KEY})"


@dataclass(frozen=True)
class VulnCursor:
    order_key: int
    cve_id: str

    def encode(self) -> str:
        raw = json.dumps(
            {"v": 1, "k": self.order_key, "cve": self.cve_id}, separators=(",", ":")
        ).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @classmethod
    def decode(cls, token: str) -> VulnCursor:
        try:
            padded = token + "=" * (-len(token) % 4)
            payload = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
            data = json.loads(payload)
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise InvalidCursor("cursor is not base64url-encoded JSON") from exc

        if not isinstance(data, dict) or data.get("v") != 1:
            raise InvalidCursor("not a vulnerability cursor")
        order_key = data.get("k")
        cve_id = data.get("cve")
        if not isinstance(order_key, int) or isinstance(order_key, bool):
            raise InvalidCursor("cursor order key must be an integer")
        if not isinstance(cve_id, str) or not 1 <= len(cve_id) <= 64:
            raise InvalidCursor("cursor cve id is missing or too long")
        return cls(order_key=order_key, cve_id=cve_id)


def _row_to_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "cve_id": row["cve_id"],
        "date_added": row["date_added"],
        "due_date": row["due_date"],
        "ransomware": row["ransomware"],
        "vendor_project": row["vendor_project"],
        "product": row["product"],
        "required_action": row["required_action"],
        "short_description": row["short_description"],
        "cwes": row["cwes"] or [],
        "notes": row["notes"],
        "tags": row["tags"] or [],
        "sources": json.loads(row["sources_json"]),
        "bronze_refs": row["bronze_refs"] or [],
        "ingest_version": row["ingest_version"],
    }


class VulnStore:
    """One in-memory snapshot of one catalogue run, queried under one lock."""

    def __init__(self, path: Path):
        if not path.is_file():
            raise FileNotFoundError(f"vulnerability table not found: {path}")
        self.path = path
        self._lock = threading.Lock()
        self._connection = duckdb.connect(":memory:")
        literal = str(path).replace("'", "''")
        self._connection.execute(
            f"CREATE TABLE vulns AS SELECT * FROM read_parquet('{literal}')"
        )
        clocks = self._rows("SELECT count(DISTINCT as_of) AS clocks FROM vulns")[0]["clocks"]
        if clocks > 1:
            self._connection.close()
            raise GoldStoreError(
                "vulnerability table mixes runs; rewrite it with one scoring run"
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
            raise GoldStoreError("vulnerability table is not readable") from exc

    def run_meta(self) -> dict[str, Any]:
        rows = self._rows(
            "SELECT min(as_of) AS as_of, count(*) AS vulnerabilities FROM vulns"
        )
        return rows[0]

    def health(self) -> dict[str, Any]:
        return {"vulnerabilities": self._rows("SELECT count(*) AS n FROM vulns")[0]["n"]}

    def list_vulnerabilities(
        self,
        *,
        ransomware: bool | None = None,
        limit: int = 50,
        cursor: VulnCursor | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """One page in catalogue order. Returns `(items, next_cursor)`."""
        conditions: list[str] = []
        params: list[Any] = []

        if ransomware is not None:
            conditions.append("ransomware = ?")
            params.append(ransomware)
        if cursor is not None:
            conditions.append("(order_key < ? OR (order_key = ? AND cve_id > ?))")
            params.extend([cursor.order_key, cursor.order_key, cursor.cve_id])

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = (
            f"SELECT * FROM (SELECT *, {_ORDER_KEY_SQL} AS order_key FROM vulns) t{where}"
            " ORDER BY order_key DESC, cve_id ASC LIMIT ?"
        )
        params.append(limit + 1)

        rows = self._rows(sql, params)
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            next_cursor = VulnCursor(
                order_key=last["order_key"], cve_id=last["cve_id"]
            ).encode()
        items = [_row_to_item(row) for row in rows]
        return items, next_cursor

    def stats(self) -> dict[str, Any]:
        rows = self._rows(
            """
            SELECT
                count(*) AS n,
                count(*) FILTER (WHERE ransomware) AS ransomware,
                min(date_added) AS earliest_date_added,
                max(date_added) AS latest_date_added
            FROM vulns
            """
        )[0]
        return {
            "count": rows["n"],
            "ransomware": rows["ransomware"],
            "earliest_date_added": rows["earliest_date_added"],
            "latest_date_added": rows["latest_date_added"],
        }


__all__ = ["NULL_ORDER_KEY", "VulnCursor", "VulnStore"]
