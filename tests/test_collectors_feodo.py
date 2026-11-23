"""Feodo collector: open JSON, empty list, allowlist hops, and the fair-use guard."""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import httpx
import pytest

from threatintel.collectors import feodo
from threatintel.collectors.feodo import CollectorError, collect

COLLECTION_DATE = date(2026, 11, 23)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def _serving(payload: bytes, seen: list[httpx.Request] | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(200, content=payload)

    return _client(handler)


def _target(tmp_path: Path) -> Path:
    return tmp_path / "feodo" / f"collection_date={COLLECTION_DATE.isoformat()}"


def test_writes_payload_and_meta(tmp_path, feodo_payload_bytes):
    result = collect(
        out_dir=tmp_path,
        collection_date=COLLECTION_DATE,
        client=_serving(feodo_payload_bytes),
    )

    meta = json.loads((_target(tmp_path) / "_meta.json").read_text())
    assert result.skipped is False
    assert result.count == 4
    assert result.online == 3
    assert meta["source"] == "feodo"
    assert meta["count"] == 4
    assert meta["online"] == 3
    assert meta["license"].startswith("CC0")
    assert meta["sha256"] == hashlib.sha256(feodo_payload_bytes).hexdigest()
    assert (_target(tmp_path) / "payload.json").read_bytes() == feodo_payload_bytes


def test_an_empty_list_is_a_valid_collection(tmp_path):
    """The blocklist prunes to active C2s; zero entries is a fact, not a broken feed."""
    result = collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, client=_serving(b"[]"))

    assert result.count == 0
    assert result.online == 0
    assert (_target(tmp_path) / "payload.json").exists()


def test_rerun_same_day_skips(tmp_path, feodo_payload_bytes):
    seen: list[httpx.Request] = []
    client = _serving(feodo_payload_bytes, seen)
    collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, client=client)
    again = collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, client=client)

    assert len(seen) == 1
    assert again.skipped is True
    assert again.count == 4


def test_redirect_inside_the_allowlist_is_followed(tmp_path, feodo_payload_bytes):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(302, headers={"location": "/downloads/ipblocklist.json"})
        return httpx.Response(200, content=feodo_payload_bytes)

    result = collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, client=_client(handler))
    assert result.count == 4
    assert len(seen) == 2


def test_redirect_to_another_host_is_never_followed(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"location": "https://evil.example/blocklist.json"})

    with pytest.raises(CollectorError, match="host not allowlisted"):
        collect(out_dir=tmp_path, collection_date=COLLECTION_DATE, client=_client(handler))
    assert not _target(tmp_path).exists()


def test_size_cap_is_enforced(tmp_path, feodo_payload_bytes):
    with pytest.raises(CollectorError, match="exceeds"):
        collect(
            out_dir=tmp_path,
            collection_date=COLLECTION_DATE,
            max_bytes=200,
            client=_serving(feodo_payload_bytes),
        )


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"{}",
        b"[1]",
        b'[{"ip_address": ""}]',
        b'[{"ip_address": "203.0.113.10", "port": "443", "status": "online"}]',
        b'[{"ip_address": "203.0.113.10", "port": 443, "status": "maybe"}]',
    ],
)
def test_structurally_invalid_payloads_are_rejected(payload: bytes):
    with pytest.raises(CollectorError):
        feodo.validate_payload(payload)


def test_fair_use_guard_blocks_a_second_date_inside_the_interval(tmp_path, feodo_payload_bytes):
    state = tmp_path / "state.json"
    client = _serving(feodo_payload_bytes)
    collect(
        out_dir=tmp_path,
        collection_date=date(2026, 11, 23),
        throttle_state=state,
        min_interval=3_600,
        now=1_000.0,
        client=client,
    )

    with pytest.raises(CollectorError, match="fair-use interval"):
        collect(
            out_dir=tmp_path,
            collection_date=date(2026, 11, 24),
            throttle_state=state,
            min_interval=3_600,
            now=2_000.0,
            client=client,
        )

    allowed = collect(
        out_dir=tmp_path,
        collection_date=date(2026, 11, 24),
        throttle_state=state,
        min_interval=3_600,
        now=1_000.0 + 3_601,
        client=client,
    )
    assert allowed.skipped is False
    assert json.loads(state.read_text())["feodo"] == 1_000.0 + 3_601


def test_without_a_state_path_the_guard_is_not_written(tmp_path, feodo_payload_bytes):
    client = _serving(feodo_payload_bytes)
    collect(out_dir=tmp_path, collection_date=date(2026, 11, 23), client=client)
    collect(out_dir=tmp_path, collection_date=date(2026, 11, 24), client=client)

    assert not (tmp_path / "state.json").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["feodo"]


def test_cli_refuses_when_the_interval_has_not_elapsed(tmp_path, capsys):
    from threatintel.collectors.throttle import record_fetch

    state = tmp_path / "state.json"
    record_fetch("feodo", state_path=state)

    code = feodo.main(
        [
            "--out",
            str(tmp_path / "out"),
            "--date",
            "2026-11-23",
            "--state",
            str(state),
            "--min-interval",
            "3600",
        ]
    )

    assert code == 2
    assert "fair-use" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
