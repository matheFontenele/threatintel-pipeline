"""URLhaus collector: the credential rides in the URL path, so leaks are the test subject."""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import httpx
import pytest

from threatintel.collectors import urlhaus
from threatintel.collectors.urlhaus import CollectorError, collect

COLLECTION_DATE = date(2026, 11, 23)
KEY = "0123456789abcdef0123456789abcdef"


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def _serving(payload: bytes, seen: list[httpx.Request] | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(200, content=payload, headers={"content-type": "text/csv"})

    return _client(handler)


def _target(tmp_path: Path) -> Path:
    return tmp_path / "urlhaus" / f"collection_date={COLLECTION_DATE.isoformat()}"


def test_key_travels_in_the_path_and_meta_uses_a_placeholder(
    tmp_path, urlhaus_payload_bytes
):
    seen: list[httpx.Request] = []
    result = collect(
        out_dir=tmp_path,
        collection_date=COLLECTION_DATE,
        auth_key=KEY,
        client=_serving(urlhaus_payload_bytes, seen),
    )

    assert KEY in str(seen[0].url)
    meta_text = (_target(tmp_path) / "_meta.json").read_text()
    meta = json.loads(meta_text)
    assert KEY not in meta_text
    assert meta["url"] == urlhaus.SAFE_URL
    assert urlhaus.KEY_PLACEHOLDER in meta["url"]
    assert meta["count"] == 2
    assert "url" in meta["columns"]
    assert meta["sha256"] == hashlib.sha256(urlhaus_payload_bytes).hexdigest()
    assert result.count == 2


def test_missing_key_fails_before_any_request(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    with pytest.raises(CollectorError, match="ABUSECH_AUTH_KEY"):
        collect(out_dir=tmp_path, collection_date=COLLECTION_DATE)
    assert not _target(tmp_path).exists()


def test_path_syntax_in_the_key_is_refused_without_echoing_it():
    hostile = "abc/../../admin"
    with pytest.raises(CollectorError) as excinfo:
        urlhaus.build_export_url(hostile)
    assert "ABUSECH_AUTH_KEY" in str(excinfo.value)
    assert hostile not in str(excinfo.value)


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


def test_transport_error_drops_the_chained_exception_that_carries_the_url(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"failed to connect to {request.url}")

    with pytest.raises(CollectorError) as excinfo:
        collect(
            out_dir=tmp_path,
            collection_date=COLLECTION_DATE,
            auth_key=KEY,
            client=_client(handler),
        )

    message = str(excinfo.value)
    assert KEY not in message
    assert "Auth-Key" in message
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__ is True


def test_redirect_is_refused(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/x.csv"})

    with pytest.raises(CollectorError, match="refusing redirect"):
        collect(
            out_dir=tmp_path,
            collection_date=COLLECTION_DATE,
            auth_key=KEY,
            client=_client(handler),
        )


def test_html_is_rejected_even_with_http_200(tmp_path):
    with pytest.raises(CollectorError, match="HTML"):
        collect(
            out_dir=tmp_path,
            collection_date=COLLECTION_DATE,
            auth_key=KEY,
            client=_serving(b"<!doctype html><html>error</html>"),
        )
    assert not _target(tmp_path).exists()


def test_missing_required_columns_is_rejected():
    with pytest.raises(CollectorError, match="missing required column"):
        urlhaus.validate_payload(b"id,dateadded\n1,2026-11-23\n")


def test_empty_and_non_utf8_payloads_are_rejected():
    with pytest.raises(CollectorError):
        urlhaus.validate_payload(b"   \n")
    with pytest.raises(CollectorError):
        urlhaus.validate_payload(b"\xff\xfe\x00\x00")


def test_size_cap_is_enforced(tmp_path, urlhaus_payload_bytes):
    with pytest.raises(CollectorError, match="exceeds"):
        collect(
            out_dir=tmp_path,
            collection_date=COLLECTION_DATE,
            auth_key=KEY,
            max_bytes=100,
            client=_serving(urlhaus_payload_bytes),
        )


def test_rerun_same_day_skips(tmp_path, urlhaus_payload_bytes):
    seen: list[httpx.Request] = []
    client = _serving(urlhaus_payload_bytes, seen)
    collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, auth_key=KEY, client=client)
    again = collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, auth_key=KEY, client=client)

    assert len(seen) == 1
    assert again.skipped is True


def test_fair_use_guard_blocks_a_second_date(tmp_path, urlhaus_payload_bytes):
    state = tmp_path / "state.json"
    client = _serving(urlhaus_payload_bytes)
    collect(
        out_dir=tmp_path,
        collection_date=date(2026, 11, 23),
        auth_key=KEY,
        throttle_state=state,
        min_interval=3_600,
        now=1_000.0,
        client=client,
    )

    with pytest.raises(CollectorError, match="fair-use interval"):
        collect(
            out_dir=tmp_path,
            collection_date=date(2026, 11, 24),
            auth_key=KEY,
            throttle_state=state,
            min_interval=3_600,
            now=1_500.0,
            client=client,
        )
