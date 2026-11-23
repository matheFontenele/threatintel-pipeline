"""ThreatFox collector: credential handling, throttling, and bronze contract."""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import httpx
import pytest

from threatintel.collectors import threatfox
from threatintel.collectors.threatfox import CollectorError, collect

COLLECTION_DATE = date(2026, 11, 23)
KEY = "test-auth-key-not-a-real-credential"


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def _serving(payload: bytes, seen: list[httpx.Request] | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(200, content=payload)

    return _client(handler)


def _target(tmp_path: Path) -> Path:
    return tmp_path / "threatfox" / f"collection_date={COLLECTION_DATE.isoformat()}"


def test_sends_the_key_in_a_header_not_in_the_url(tmp_path, threatfox_payload_bytes):
    seen: list[httpx.Request] = []
    collect(
        out_dir=tmp_path,
        collection_date=COLLECTION_DATE,
        auth_key=KEY,
        client=_serving(threatfox_payload_bytes, seen),
    )

    request = seen[0]
    assert request.headers["Auth-Key"] == KEY
    assert KEY not in str(request.url)
    assert json.loads(request.content) == {"query": "get_iocs", "days": 7}


def test_meta_never_contains_the_credential(tmp_path, threatfox_payload_bytes):
    collect(
        out_dir=tmp_path,
        collection_date=COLLECTION_DATE,
        auth_key=KEY,
        client=_serving(threatfox_payload_bytes),
    )
    meta = json.loads((_target(tmp_path) / "_meta.json").read_text())
    assert KEY not in json.dumps(meta)
    assert meta["source"] == "threatfox"
    assert meta["count"] == 4
    assert meta["days"] == 7
    assert meta["sha256"] == hashlib.sha256(threatfox_payload_bytes).hexdigest()


def test_missing_key_fails_before_any_request(monkeypatch, tmp_path):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    with pytest.raises(CollectorError, match="ABUSECH_AUTH_KEY"):
        collect(out_dir=tmp_path, collection_date=COLLECTION_DATE)
    assert not _target(tmp_path).exists()


def test_rejected_key_is_reported_without_echoing_it(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthorized")

    with pytest.raises(CollectorError) as excinfo:
        collect(
            out_dir=tmp_path,
            collection_date=COLLECTION_DATE,
            auth_key=KEY,
            client=_client(handler),
        )
    assert "ABUSECH_AUTH_KEY" in str(excinfo.value)
    assert KEY not in str(excinfo.value)


def test_redirect_is_refused(tmp_path, threatfox_payload_bytes):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"location": "https://evil.example/steal"})

    with pytest.raises(CollectorError, match="refusing redirect"):
        collect(
            out_dir=tmp_path,
            collection_date=COLLECTION_DATE,
            auth_key=KEY,
            client=_client(handler),
        )
    assert not _target(tmp_path).exists()


def test_days_outside_the_allowed_window_is_refused(tmp_path, threatfox_payload_bytes):
    with pytest.raises(CollectorError, match="days must be between"):
        collect(
            out_dir=tmp_path,
            collection_date=COLLECTION_DATE,
            days=30,
            auth_key=KEY,
            client=_serving(threatfox_payload_bytes),
        )


def test_size_cap_is_enforced(tmp_path, threatfox_payload_bytes):
    with pytest.raises(CollectorError, match="exceeds"):
        collect(
            out_dir=tmp_path,
            collection_date=COLLECTION_DATE,
            auth_key=KEY,
            max_bytes=200,
            client=_serving(threatfox_payload_bytes),
        )


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b'{"query_status": "illegal_query"}',
        b'{"query_status": "ok", "data": "nope"}',
        b'{"query_status": "ok", "data": [{"ioc": ""}]}',
        b'{"query_status": "ok", "data": [{"ioc": "x.test"}]}',
    ],
)
def test_invalid_payloads_are_rejected(payload: bytes):
    with pytest.raises(CollectorError):
        threatfox.validate_payload(payload)


def test_no_result_is_a_valid_empty_batch():
    payload = threatfox.validate_payload(b'{"query_status": "no_result"}')
    assert payload["data"] == []


def test_rerun_same_day_skips(tmp_path, threatfox_payload_bytes):
    seen: list[httpx.Request] = []
    client = _serving(threatfox_payload_bytes, seen)
    collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, auth_key=KEY, client=client)
    again = collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, auth_key=KEY, client=client)
    assert len(seen) == 1
    assert again.skipped is True
    assert again.count == 4


def test_cli_exits_2_on_missing_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    assert threatfox.main(["--out", str(tmp_path)]) == 2
    assert "ABUSECH_AUTH_KEY" in capsys.readouterr().err
