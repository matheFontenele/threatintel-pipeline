"""Feodo Tracker collector: botnet C2 IPs into immutable bronze.

Feodo is the one abuse.ch platform whose terms exempt it from the redistribution ban
(`docs/sources.md` §3.4, CC0), so its data can appear in a public demo. It is also the only
one that needs no Auth-Key: the JSON blocklist is served openly.

Two shape differences from the other feeds matter downstream:

- the payload is a JSON **array**, not an object with a count;
- an empty array is legitimate. The list is pruned to currently active C2s and can be
  empty at any moment, which is a fact about the botnets, not a broken feed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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

SOURCE = "feodo"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
ALLOWED_HOSTS = frozenset({"feodotracker.abuse.ch"})
DEFAULT_MAX_BYTES = 25 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
MAX_REDIRECTS = 3
VALID_STATUS = frozenset({"online", "offline"})


class CollectorError(RuntimeError):
    """The collection could not produce a valid bronze artifact."""


@dataclass(frozen=True)
class CollectionResult:
    path: Path
    sha256: str
    bytes: int
    count: int
    online: int
    skipped: bool


def _ensure_allowed(url: str) -> None:
    """Host allowlist. A feed must not be able to steer us to another host (T2)."""
    host = urlsplit(url).hostname
    if host not in ALLOWED_HOSTS:
        raise CollectorError(f"host not allowlisted: {host!r}")


def fetch_payload(
    url: str = FEODO_URL,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.Client | None = None,
) -> tuple[bytes, int, str]:
    """Fetch with a size cap, a timeout, and a bounded redirect chain.

    Redirects are followed by hand so every hop is checked against the allowlist; an
    automatic follow would happily land elsewhere.
    """
    own_client = client is None
    if client is None:
        client = httpx.Client(timeout=timeout, follow_redirects=False)
    try:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            _ensure_allowed(current)
            with client.stream("GET", current) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise CollectorError(f"redirect without Location from {current}")
                    current = str(httpx.URL(current).join(location))
                    continue
                if response.status_code != 200:
                    raise CollectorError(f"unexpected HTTP {response.status_code} from {current}")
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise CollectorError(
                            f"payload exceeds {max_bytes} bytes; refusing to buffer it"
                        )
                    chunks.append(chunk)
                return b"".join(chunks), response.status_code, current
        raise CollectorError(f"more than {MAX_REDIRECTS} redirects from {url}")
    except httpx.HTTPError as exc:
        raise CollectorError(f"request failed for {url}: {exc}") from exc
    finally:
        if own_client:
            client.close()


def validate_payload(raw: bytes) -> list[dict[str, Any]]:
    """Structural check before anything is written (feeds are untrusted input).

    Returns `[]` for a legitimately empty list; raises on anything that is not a list of
    well-formed entries.
    """
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"payload is not JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise CollectorError("payload is not a JSON array")
    for index, entry in enumerate(payload):
        if not isinstance(entry, dict):
            raise CollectorError(f"entry[{index}] is not an object")
        ip = entry.get("ip_address")
        if not isinstance(ip, str) or not ip.strip():
            raise CollectorError(f"entry[{index}].ip_address is empty or not a string")
        port = entry.get("port")
        if not isinstance(port, int) or not 0 <= port <= 65535:
            raise CollectorError(f"entry[{index}].port is not a valid port: {port!r}")
        if entry.get("status") not in VALID_STATUS:
            raise CollectorError(
                f"entry[{index}].status is not online/offline: {entry.get('status')!r}"
            )
    return payload


def _write_atomic(path: Path, data: bytes) -> None:
    """Write via temp file + replace so a crash cannot leave a truncated payload."""
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
    client: httpx.Client | None = None,
) -> CollectionResult:
    """Collect one daily batch.

    Throttling is opt-in through `throttle_state`: the primitive does what it is told, and
    the CLI is what always passes the state path. That keeps unit tests from creating
    operational state files in the working tree while leaving no supported entry point
    unguarded.
    """
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
            online=existing.get("online", 0),
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

    raw, status, final_url = fetch_payload(
        FEODO_URL, max_bytes=max_bytes, timeout=timeout, client=client
    )
    entries = validate_payload(raw)
    digest = hashlib.sha256(raw).hexdigest()
    online = sum(1 for entry in entries if entry["status"] == "online")
    meta = {
        "source": SOURCE,
        "url": final_url,
        "fetched_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "http_status": status,
        "sha256": digest,
        "bytes": len(raw),
        "ingest_version": __version__,
        "count": len(entries),
        "online": online,
        "license": "CC0 (abuse.ch terms §3.4)",
    }

    target.mkdir(parents=True, exist_ok=True)
    _write_atomic(payload_path, raw)
    _write_atomic(meta_path, json.dumps(meta, indent=2, sort_keys=True).encode())

    if throttle_state is not None:
        record_fetch(SOURCE, state_path=throttle_state, now=now)

    return CollectionResult(
        path=target,
        sha256=digest,
        bytes=len(raw),
        count=len(entries),
        online=online,
        skipped=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect the Feodo Tracker C2 blocklist.")
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
        f"{action}: {result.count} entries ({result.online} online), {result.bytes} bytes, "
        f"sha256={result.sha256[:12]}… -> {result.path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
