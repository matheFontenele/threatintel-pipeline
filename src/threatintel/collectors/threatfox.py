"""ThreatFox collector: IOC batches into immutable bronze.

Uploads go through the POST body, so the Auth-Key travels in a header rather than in the
URL. That matters: a key in a URL ends up in server logs, in exception messages and in any
proxy in between. Here the only place it exists is the request header, which is never
logged.

Fair-use throttling is deliberate: one batch per day, `days <= 7`, no retry storm.
"""

from __future__ import annotations

import argparse
import hashlib
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

SOURCE = "threatfox"
API_URL = "https://threatfox-api.abuse.ch/api/v1/"
ALLOWED_HOSTS = frozenset({"threatfox-api.abuse.ch"})
DEFAULT_DAYS = 7
MIN_DAYS = 1
MAX_DAYS = 7
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
DEFAULT_TIMEOUT = 60.0
ACCEPTED_STATUS = frozenset({"ok", "no_result"})

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
HASH_TYPES = frozenset({"md5_hash", "sha1_hash", "sha256_hash"})


class CollectorError(RuntimeError):
    """The collection could not produce a valid bronze artifact."""


@dataclass(frozen=True)
class CollectionResult:
    path: Path
    sha256: str
    bytes: int
    count: int
    days: int
    skipped: bool


def _ensure_allowed(url: str) -> None:
    if urlsplit(url).hostname not in ALLOWED_HOSTS:
        raise CollectorError(f"host not allowlisted: {urlsplit(url).hostname!r}")


def auth_key_from_env() -> str:
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        raise CollectorError(
            "ABUSECH_AUTH_KEY is not set. Create a free key at https://auth.abuse.ch/ "
            "and add it to .env (see .env.example)."
        )
    return key


def fetch_payload(
    days: int = DEFAULT_DAYS,
    *,
    auth_key: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.Client | None = None,
) -> tuple[bytes, int]:
    """POST the batch query and return (raw bytes, http status).

    Redirects are refused rather than followed: a POST redirected elsewhere is either a
    misconfiguration or an attempt to move the credential to another host.
    """
    if not MIN_DAYS <= days <= MAX_DAYS:
        raise CollectorError(f"days must be between {MIN_DAYS} and {MAX_DAYS}, got {days}")
    _ensure_allowed(API_URL)

    own_client = client is None
    if client is None:
        client = httpx.Client(timeout=timeout, follow_redirects=False)
    try:
        with client.stream(
            "POST",
            API_URL,
            json={"query": "get_iocs", "days": days},
            headers={"Auth-Key": auth_key},
        ) as response:
            if 300 <= response.status_code < 400:
                raise CollectorError(
                    f"refusing redirect from {API_URL} (HTTP {response.status_code})"
                )
            if response.status_code in (401, 403):
                raise CollectorError(
                    f"authentication rejected (HTTP {response.status_code}); "
                    "check ABUSECH_AUTH_KEY"
                )
            if response.status_code != 200:
                raise CollectorError(f"unexpected HTTP {response.status_code} from {API_URL}")
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise CollectorError(f"payload exceeds {max_bytes} bytes; refusing to buffer")
                chunks.append(chunk)
            return b"".join(chunks), response.status_code
    except httpx.HTTPError as exc:
        # `exc` may include the request URL but never the headers, so no key leaks here.
        raise CollectorError(f"request failed for {API_URL}: {exc}") from exc
    finally:
        if own_client:
            client.close()


def validate_payload(raw: bytes) -> dict[str, Any]:
    """Structural check on the batch response before it is written (feeds are untrusted)."""
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"payload is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CollectorError("payload is not a JSON object")
    status = payload.get("query_status")
    if status not in ACCEPTED_STATUS:
        raise CollectorError(f"query_status is not ok: {status!r}")
    data = payload.get("data")
    if data is None and status == "no_result":
        payload["data"] = []
        return payload
    if not isinstance(data, list):
        raise CollectorError("payload has no 'data' list")
    for index, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise CollectorError(f"data[{index}] is not an object")
        ioc = entry.get("ioc")
        ioc_type = entry.get("ioc_type")
        if not isinstance(ioc, str) or not ioc:
            raise CollectorError(f"data[{index}].ioc is empty or not a string")
        if not isinstance(ioc_type, str) or not ioc_type:
            raise CollectorError(f"data[{index}].ioc_type is empty or not a string")
    return payload


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def collect(
    *,
    out_dir: Path,
    days: int = DEFAULT_DAYS,
    collection_date: date | None = None,
    force: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    auth_key: str | None = None,
    client: httpx.Client | None = None,
) -> CollectionResult:
    key = auth_key or auth_key_from_env()
    day = collection_date or datetime.now(UTC).date()
    target = out_dir / SOURCE / f"collection_date={day.isoformat()}"
    payload_path = target / "payload.json"
    meta_path = target / "_meta.json"

    if payload_path.exists() and not force:
        existing = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        return CollectionResult(
            path=target,
            sha256=existing.get("sha256", ""),
            bytes=existing.get("bytes", payload_path.stat().st_size),
            count=existing.get("count", 0),
            days=int(existing.get("days", days)),
            skipped=True,
        )

    raw, status = fetch_payload(days, auth_key=key, max_bytes=max_bytes, timeout=timeout,
                                client=client)
    payload = validate_payload(raw)
    data = payload["data"]
    digest = hashlib.sha256(raw).hexdigest()
    meta = {
        "source": SOURCE,
        "url": API_URL,
        "fetched_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "http_status": status,
        "sha256": digest,
        "bytes": len(raw),
        "ingest_version": __version__,
        "days": days,
        "count": len(data),
        "query_status": payload.get("query_status"),
    }

    target.mkdir(parents=True, exist_ok=True)
    _write_atomic(payload_path, raw)
    _write_atomic(meta_path, json.dumps(meta, indent=2, sort_keys=True).encode())

    return CollectionResult(
        path=target,
        sha256=digest,
        bytes=len(raw),
        count=len(data),
        days=days,
        skipped=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect ThreatFox IOCs into bronze.")
    parser.add_argument("--out", type=Path, default=Path("data/bronze"))
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, choices=range(1, 8))
    parser.add_argument("--date", type=date.fromisoformat, default=None)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)

    try:
        result = collect(
            out_dir=args.out,
            days=args.days,
            collection_date=args.date,
            force=args.force,
            max_bytes=args.max_bytes,
            timeout=args.timeout,
        )
    except CollectorError as exc:
        print(f"collection failed: {exc}", file=sys.stderr)
        return 2

    action = "skipped (already present)" if result.skipped else "collected"
    print(
        f"{action}: {result.count} iocs over {result.days} day(s), {result.bytes} bytes, "
        f"sha256={result.sha256[:12]}… -> {result.path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
