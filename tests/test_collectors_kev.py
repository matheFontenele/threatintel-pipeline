"""KEV collector: bronze contract, idempotency, and the guards around untrusted input."""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import httpx
import pytest

from threatintel import __version__
from threatintel.collectors import kev
from threatintel.collectors.kev import KEV_URL, CollectorError, collect, validate_payload

COLLECTION_DATE = date(2026, 11, 23)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def _serving(payload: bytes, calls: list[httpx.Request] | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        return httpx.Response(200, content=payload)

    return _client(handler)


def _target(tmp_path: Path) -> Path:
    return tmp_path / "cisa_kev" / f"collection_date={COLLECTION_DATE.isoformat()}"


def test_collect_writes_the_provider_bytes_unchanged(tmp_path, kev_payload_bytes):
    result = collect(
        out_dir=tmp_path,
        collection_date=COLLECTION_DATE,
        client=_serving(kev_payload_bytes),
    )

    assert result.skipped is False
    assert result.sha256 == hashlib.sha256(kev_payload_bytes).hexdigest()
    assert result.bytes == len(kev_payload_bytes)
    assert result.count == 5

    target = _target(tmp_path)
    assert (target / "payload.json").read_bytes() == kev_payload_bytes
    meta = json.loads((target / "_meta.json").read_text())
    assert meta["source"] == "cisa_kev"
    assert meta["url"] == KEV_URL
    assert meta["http_status"] == 200
    assert meta["sha256"] == result.sha256
    assert meta["bytes"] == len(kev_payload_bytes)
    assert meta["ingest_version"] == __version__
    assert meta["count"] == 5
    assert meta["release_date"] == "2026-11-20T12:00:00.000Z"
    assert meta["fetched_at"].endswith("Z")


def test_rerun_same_day_skips_without_touching_the_network(tmp_path, kev_payload_bytes):
    calls: list[httpx.Request] = []
    first = collect(
        out_dir=tmp_path,
        collection_date=COLLECTION_DATE,
        client=_serving(kev_payload_bytes, calls),
    )
    second = collect(
        out_dir=tmp_path,
        collection_date=COLLECTION_DATE,
        client=_serving(kev_payload_bytes, calls),
    )

    assert len(calls) == 1
    assert second.skipped is True
    assert second.sha256 == first.sha256
    assert second.count == 5
    assert list((tmp_path / "cisa_kev").iterdir()) == [_target(tmp_path)]


def test_force_downloads_again(tmp_path, kev_payload_bytes):
    calls: list[httpx.Request] = []
    client = _serving(kev_payload_bytes, calls)
    collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, client=client)
    refreshed = collect(
        out_dir=tmp_path, collection_date=COLLECTION_DATE, force=True, client=client
    )
    assert len(calls) == 2
    assert refreshed.skipped is False


def test_redirect_off_the_allowlist_is_refused(tmp_path, kev_payload_bytes):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/kev.json"})

    with pytest.raises(CollectorError, match="not allowlisted"):
        collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, client=_client(handler))
    assert not _target(tmp_path).exists()


def test_redirect_inside_the_allowlist_is_followed(tmp_path, kev_payload_bytes):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "www.cisa.gov":
            return httpx.Response(301, headers={"location": "https://cisa.gov/kev.json"})
        return httpx.Response(200, content=kev_payload_bytes)

    result = collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, client=_client(handler))
    assert result.skipped is False
    assert json.loads((_target(tmp_path) / "_meta.json").read_text())["url"] == (
        "https://cisa.gov/kev.json"
    )


def test_oversized_payload_is_refused_before_buffering(tmp_path, kev_payload_bytes):
    with pytest.raises(CollectorError, match="exceeds"):
        collect(
            out_dir=tmp_path,
            collection_date=COLLECTION_DATE,
            max_bytes=100,
            client=_serving(kev_payload_bytes),
        )
    assert not (_target(tmp_path) / "payload.json").exists()


def test_http_error_is_not_written(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="nope")

    with pytest.raises(CollectorError, match="HTTP 500"):
        collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, client=_client(handler))
    assert not _target(tmp_path).exists()


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"[]",
        b'{"vulnerabilities": []}',
        b'{"vulnerabilities": ["nope"]}',
        b'{"vulnerabilities": [{"cveID": "CVE-21-1"}]}',
        b'{"vulnerabilities": [{"vendorProject": "no cve"}]}',
    ],
)
def test_invalid_payloads_are_rejected(payload: bytes):
    with pytest.raises(CollectorError):
        validate_payload(payload)


def test_valid_payload_round_trips(kev_payload_bytes):
    payload = validate_payload(kev_payload_bytes)
    assert len(payload["vulnerabilities"]) == 5


def test_cli_reports_failure_with_exit_code_2(tmp_path, monkeypatch, capsys):
    def boom(**kwargs):
        raise CollectorError("simulated")

    monkeypatch.setattr(kev, "collect", boom)
    assert kev.main(["--out", str(tmp_path)]) == 2
    assert "simulated" in capsys.readouterr().err
