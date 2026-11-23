"""URLhaus collector: the recent-URL export into immutable bronze.

URLhaus is the one abuse.ch platform whose export endpoint carries the Auth-Key **in the
URL path** (`/v2/files/exports/<KEY>/recent.csv`). That single fact dictates this module's
shape:

- no exception, log line or metadata file may contain the request URL;
- redirects are refused outright rather than followed;
- transport errors are re-raised with `from None`, so the chained httpx exception — which
  carries the URL — is dropped instead of surfacing in a traceback.

`_meta.json` records the endpoint with `<KEY>` in place of the credential, and the write is
refused if the key somehow appears in the serialized metadata. The bronze payload itself is
the CSV body, which never contains the key.

This collector is **bronze only**: the CSV column set is asserted at collection time but the
mapping to silver waits for a live export to confirm it, so the repository does not claim a
normalizer it has never run against real columns.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from threatintel import __version__
from threatintel.collectors.throttle import (
    DEFAULT_MIN_INTERVAL_SECONDS,
    record_fetch,
    seconds_until_allowed,
)

SOURCE = "urlhaus"
KEY_PLACEHOLDER = "<KEY>"
SAFE_URL = f"https://urlhaus-api.abuse.ch/v2/files/exports/{KEY_PLACEHOLDER}/recent.csv"
EXPORT_TEMPLATE = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
ALLOWED_HOSTS = frozenset({"urlhaus-api.abuse.ch"})
DEFAULT_MAX_BYTES = 100 * 1024 * 1024
DEFAULT_TIMEOUT = 120.0
# A key is a URL path segment here, so it is validated to contain no path syntax at all.
KEY_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
REQUIRED_COLUMNS = frozenset({"id", "dateadded", "url"})
# A column name in the header line. Deliberately strict: a data row must never be mistaken
# for the header, so tokens with a URL scheme, a colon or a timestamp cannot match.
COLUMN_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_ .\-]*$")
MAX_PREAMBLE_LINES = 200


class CollectorError(RuntimeError):
    """The collection could not produce a valid bronze artifact."""


@dataclass(frozen=True)
class CollectionResult:
    path: Path
    sha256: str
    bytes: int
    count: int
    skipped: bool


def _ensure_allowed(url: str) -> None:
    """Host allowlist. Only the hostname is ever quoted, never the full URL."""
    host = urlsplit(url).hostname
    if host not in ALLOWED_HOSTS:
        raise CollectorError(f"host not allowlisted: {host!r}")


def auth_key_from_env() -> str:
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        raise CollectorError(
            "ABUSECH_AUTH_KEY is not set. Create a free key at https://auth.abuse.ch/ "
            "and add it to .env (see .env.example)."
        )
    return key


def build_export_url(key: str) -> str:
    """Interpolate the key into the path after rejecting anything path-like.

    A key containing `/`, `..` or `?` could move the request to another path on the same
    host or truncate it, so the format is enforced rather than trusted.
    """
    if not KEY_RE.match(key):
        raise CollectorError(
            "ABUSECH_AUTH_KEY is not in the expected format "
            "(16-128 chars of letters, digits, hyphen or underscore); refusing to build a URL"
        )
    return EXPORT_TEMPLATE.format(key=key)


def fetch_payload(
    *,
    auth_key: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.Client | None = None,
) -> tuple[bytes, int, str]:
    """Fetch the export, returning (raw bytes, http status, content type).

    Every failure path raises text that is safe to print: the URL is never interpolated.
    """
    url = build_export_url(auth_key)
    _ensure_allowed(url)

    own_client = client is None
    if client is None:
        client = httpx.Client(timeout=timeout, follow_redirects=False)
    try:
        with client.stream("GET", url) as response:
            if 300 <= response.status_code < 400:
                raise CollectorError(
                    f"refusing redirect from the URLhaus export (HTTP {response.status_code})"
                )
            if response.status_code in (401, 403):
                raise CollectorError(
                    f"authentication rejected (HTTP {response.status_code}); "
                    "check ABUSECH_AUTH_KEY"
                )
            if response.status_code != 200:
                raise CollectorError(
                    f"unexpected HTTP {response.status_code} from the URLhaus export"
                )
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise CollectorError(f"payload exceeds {max_bytes} bytes; refusing to buffer")
                chunks.append(chunk)
            return b"".join(chunks), response.status_code, response.headers.get("content-type", "")
    except (httpx.HTTPError, httpx.InvalidURL):
        # `from None` drops the chained exception, whose message contains the URL and thus
        # the credential. This is the whole reason URLhaus was deferred until now.
        raise CollectorError(
            "URLhaus export request failed; the request URL is not reported because it "
            "contains the Auth-Key"
        ) from None
    finally:
        if own_client:
            client.close()


def _split_header(text: str) -> tuple[list[str], str]:
    """Find the header line and return (column names, remaining CSV text).

    The live export opens with a `#`-prefixed comment banner and a blank line, and the
    header itself is commented out (`#id,dateadded,...`). A plain `csv.DictReader` therefore
    takes the banner as a one-column header and never sees the real columns. The header is
    located by shape: a line whose comma-separated tokens all look like column names and
    that carries at least two required columns. Data rows cannot match — their `id` is
    numeric and their `dateadded`/`url` hold a timestamp and a scheme.
    """
    lines = text.splitlines()
    for index, line in enumerate(lines[:MAX_PREAMBLE_LINES]):
        stripped = line.strip()
        if not stripped:
            continue
        candidate = stripped[1:].strip() if stripped.startswith("#") else stripped
        if not candidate:
            continue
        fields = [field.strip().strip('"').strip() for field in next(csv.reader([candidate]))]
        if len(fields) < 2 or not all(COLUMN_NAME_RE.match(field) for field in fields):
            continue
        # Two required columns are enough to call it a header; a partial column set is then
        # reported precisely by the caller instead of as "no header".
        if len(REQUIRED_COLUMNS & set(fields)) >= 2:
            return fields, "\n".join(lines[index + 1 :])
    raise CollectorError(
        "URLhaus export has no recognisable CSV header "
        f"(looked for {', '.join(sorted(REQUIRED_COLUMNS))} in the first "
        f"{MAX_PREAMBLE_LINES} lines)"
    )


def parse_export(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse the export body into (rows, column names), tolerating the comment banner.

    Public because the silver normalizer must read exactly the same bytes the collector
    validated; a second, subtly different header-skipping routine is how a pipeline starts
    disagreeing with its own ingest gate.
    """
    columns, body = _split_header(text)
    missing = sorted(REQUIRED_COLUMNS - set(columns))
    if missing:
        raise CollectorError(f"URLhaus export is missing required column(s): {', '.join(missing)}")
    reader = csv.DictReader(io.StringIO(body), fieldnames=columns)
    rows = []
    for row in reader:
        values = [value if isinstance(value, str) else "" for value in row.values()]
        if not any(value.strip() for value in values):
            continue
        rows.append(row)
    for index, row in enumerate(rows):
        if not (row.get("url") or "").strip():
            raise CollectorError(f"row[{index}] has no url")
    return rows, columns


def validate_payload(raw: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    """Reject HTML and confirm the expected columns; return (rows, column names).

    An HTML body is the realistic failure mode: the CDN or an error page answers 200 with a
    document, and a CSV parser would happily read one garbage row from it.
    """
    if not raw.strip():
        raise CollectorError("URLhaus export is empty")
    if raw[:512].lstrip().startswith(b"<"):
        raise CollectorError(
            "URLhaus export returned HTML instead of CSV; the key may be rejected or the "
            "endpoint changed"
        )
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CollectorError("URLhaus export is not valid UTF-8") from exc
    return parse_export(text)


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def collect(
    *,
    out_dir: Path,
    collection_date: date | None = None,
    force: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    throttle_state: Path | None = None,
    min_interval: float = DEFAULT_MIN_INTERVAL_SECONDS,
    now: float | None = None,
    auth_key: str | None = None,
    client: httpx.Client | None = None,
) -> CollectionResult:
    key = auth_key or auth_key_from_env()
    day = collection_date or datetime.now(UTC).date()
    target = out_dir / SOURCE / f"collection_date={day.isoformat()}"
    payload_path = target / "payload.csv"
    meta_path = target / "_meta.json"

    if payload_path.exists() and not force:
        existing = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        return CollectionResult(
            path=target,
            sha256=existing.get("sha256", ""),
            bytes=existing.get("bytes", payload_path.stat().st_size),
            count=existing.get("count", 0),
            skipped=True,
        )

    if throttle_state is not None:
        wait = seconds_until_allowed(
            SOURCE, state_path=throttle_state, min_interval=min_interval, now=now
        )
        if wait > 0:
            raise CollectorError(
                f"fair-use interval not elapsed for {SOURCE}: wait {wait:.0f}s "
                f"(min interval {min_interval:.0f}s, state {throttle_state})"
            )

    raw, status, content_type = fetch_payload(
        auth_key=key, max_bytes=max_bytes, timeout=timeout, client=client
    )
    rows, columns = validate_payload(raw)
    digest = hashlib.sha256(raw).hexdigest()
    meta = {
        "source": SOURCE,
        "url": SAFE_URL,
        "fetched_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "http_status": status,
        "content_type": content_type,
        "sha256": digest,
        "bytes": len(raw),
        "ingest_version": __version__,
        "count": len(rows),
        "columns": columns,
    }
    serialized = json.dumps(meta, indent=2, sort_keys=True)
    if key and key in serialized:
        raise CollectorError("refusing to write metadata that contains the credential")

    target.mkdir(parents=True, exist_ok=True)
    _write_atomic(payload_path, raw)
    _write_atomic(meta_path, serialized.encode())

    if throttle_state is not None:
        record_fetch(SOURCE, state_path=throttle_state, now=now)

    return CollectionResult(
        path=target,
        sha256=digest,
        bytes=len(raw),
        count=len(rows),
        skipped=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect the URLhaus recent-URL export.")
    parser.add_argument("--out", type=Path, default=Path("data/bronze"))
    parser.add_argument("--date", type=date.fromisoformat, default=None)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--state",
        type=Path,
        default=Path("data/state/last_fetch.json"),
        help="fair-use state file; empty string disables the guard",
    )
    parser.add_argument(
        "--min-interval",
        type=float,
        default=DEFAULT_MIN_INTERVAL_SECONDS,
        help="seconds between fetches of this source (0 disables the guard)",
    )
    args = parser.parse_args(argv)
    throttle_state = args.state if str(args.state) else None

    try:
        result = collect(
            out_dir=args.out,
            collection_date=args.date,
            force=args.force,
            max_bytes=args.max_bytes,
            timeout=args.timeout,
            throttle_state=throttle_state,
            min_interval=args.min_interval,
        )
    except CollectorError as exc:
        print(f"collection failed: {exc}", file=sys.stderr)
        return 2

    action = "skipped (already present)" if result.skipped else "collected"
    print(
        f"{action}: {result.count} rows, {result.bytes} bytes, "
        f"sha256={result.sha256[:12]}… -> {result.path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
