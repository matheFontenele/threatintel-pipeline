"""CISA KEV collector: fetch the catalogue into immutable bronze.

Bronze is the provider's bytes plus provenance — no transformation. Anything we derive
lives in silver, so a normalizer bug is fixable by re-running the mapping instead of
re-downloading, and the raw evidence stays exactly as the provider served it.
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

SOURCE = "cisa_kev"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ALLOWED_HOSTS = frozenset({"www.cisa.gov", "cisa.gov"})
DEFAULT_MAX_BYTES = 25 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
MAX_REDIRECTS = 3
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class CollectorError(RuntimeError):
    """The collection could not produce a valid bronze artifact."""


@dataclass(frozen=True)
class CollectionResult:
    path: Path
    sha256: str
    bytes: int
    count: int | None
    skipped: bool


def _ensure_allowed(url: str) -> None:
    """Host allowlist. A feed must not be able to steer us to another host (T2)."""
    host = urlsplit(url).hostname
    if host not in ALLOWED_HOSTS:
        raise CollectorError(f"host not allowlisted: {host!r}")


def fetch_payload(
    url: str = KEV_URL,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.Client | None = None,
) -> tuple[bytes, int, str]:
    """Fetch the payload with a size cap, a timeout, and a bounded redirect chain.

    Redirects are followed manually because an automatic follow would happily land on a
    host that is not allowlisted.
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


def validate_payload(raw: bytes) -> dict[str, Any]:
    """Structural check before anything is written (B1: feeds are untrusted input)."""
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"payload is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CollectorError("payload is not a JSON object")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise CollectorError("payload has no 'vulnerabilities' list")
    for index, entry in enumerate(vulnerabilities):
        if not isinstance(entry, dict):
            raise CollectorError(f"vulnerabilities[{index}] is not an object")
        cve_id = entry.get("cveID")
        if not isinstance(cve_id, str) or not CVE_ID_RE.match(cve_id):
            raise CollectorError(f"vulnerabilities[{index}].cveID is not a CVE id: {cve_id!r}")
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
    client: httpx.Client | None = None,
) -> CollectionResult:
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
            count=existing.get("count"),
            skipped=True,
        )

    raw, status, final_url = fetch_payload(
        KEV_URL, max_bytes=max_bytes, timeout=timeout, client=client
    )
    payload = validate_payload(raw)
    digest = hashlib.sha256(raw).hexdigest()
    count = payload.get("count")
    meta = {
        "source": SOURCE,
        "url": final_url,
        "fetched_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "http_status": status,
        "sha256": digest,
        "bytes": len(raw),
        "ingest_version": __version__,
        "release_date": payload.get("dateReleased"),
        "count": count if isinstance(count, int) else len(payload["vulnerabilities"]),
    }

    target.mkdir(parents=True, exist_ok=True)
    _write_atomic(payload_path, raw)
    _write_atomic(meta_path, json.dumps(meta, indent=2, sort_keys=True).encode())

    return CollectionResult(
        path=target,
        sha256=digest,
        bytes=len(raw),
        count=meta["count"],
        skipped=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect the CISA KEV catalogue into bronze.")
    parser.add_argument("--out", type=Path, default=Path("data/bronze"), help="bronze root")
    parser.add_argument("--date", type=date.fromisoformat, default=None, help="collection date")
    parser.add_argument("--force", action="store_true", help="re-download even if present")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)

    try:
        result = collect(
            out_dir=args.out,
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
        f"{action}: {result.count} vulnerabilities, {result.bytes} bytes, "
        f"sha256={result.sha256[:12]}… -> {result.path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
