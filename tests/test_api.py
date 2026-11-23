"""The read API: filters, keyset pagination, the error envelope and the security posture.

The tests build their own gold table from documentation-range indicators, so the suite never
touches `data/` and never contains a real feed value. What they pin is the contract a
consumer would otherwise discover by accident: ordering, cursor semantics, which errors are
400 vs 422, and the promise that every response names the run it came from.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from fastapi.testclient import TestClient

from threatintel.api import create_app
from threatintel.api.store import GoldStoreError
from threatintel.normalize.schema import Indicator, IndicatorType, SourceRef
from threatintel.scoring import (
    DEFAULT_POLICY,
    config_fingerprint,
    evaluate_and_score,
    write_gold,
)

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


def _indicator(
    indicator_type: IndicatorType,
    value: str,
    sources: list[str],
    *,
    last_seen: datetime | None = None,
) -> Indicator:
    return Indicator.build(
        type=indicator_type,
        value=value,
        sources=[SourceRef(name=name, last_seen=last_seen) for name in sources],
        ingest_version="0.1.0",
        last_seen=last_seen,
    )


def _fixture_indicators() -> list[Indicator]:
    return [
        _indicator(IndicatorType.CVE, "CVE-2024-0001", ["cisa_kev"]),
        _indicator(
            IndicatorType.IP, "203.0.113.10", ["feodo"], last_seen=NOW - timedelta(days=1)
        ),
        _indicator(
            IndicatorType.URL,
            "http://example.com/a",
            ["threatfox", "urlhaus"],
            last_seen=NOW - timedelta(days=1),
        ),
        _indicator(
            IndicatorType.URL,
            "http://example.com/b",
            ["threatfox"],
            last_seen=NOW - timedelta(days=40),
        ),
        _indicator(
            IndicatorType.IP,
            "198.51.100.5",
            ["mystery_feed"],
            last_seen=NOW - timedelta(days=1),
        ),
        _indicator(
            IndicatorType.HASH, "a" * 64, ["threatfox"], last_seen=NOW - timedelta(days=1)
        ),
    ]


@pytest.fixture
def gold_path(tmp_path):
    report = evaluate_and_score(_fixture_indicators(), as_of=NOW)
    return write_gold(report, tmp_path / "gold.parquet")


@pytest.fixture
def client(gold_path):
    with TestClient(create_app(gold_path)) as test_client:
        yield test_client


# --- liveness and metadata ---------------------------------------------------------------


def test_health_reports_the_pinned_row_count(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "indicators": 6}


def test_root_points_at_the_documented_surfaces(client):
    body = client.get("/").json()
    assert body["health"] == "/health"
    assert body["openapi"] == "/openapi.json"


def test_openapi_is_served_with_the_versioned_paths(client):
    document = client.get("/openapi.json").json()
    assert "/v1/indicators" in document["paths"]
    assert "/v1/indicators/{indicator_id}" in document["paths"]
    assert "/v1/stats" in document["paths"]


def test_security_headers_mark_the_body_as_data(client):
    headers = client.get("/health").headers

    assert headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["cache-control"] == "no-store"


# --- listing and filters -----------------------------------------------------------------


def test_list_is_ordered_by_score_then_id(client):
    items = client.get("/v1/indicators").json()["items"]

    scores = [item["score"] for item in items]
    assert scores == [70, 70, 60, 35, 15, 5]
    assert scores == sorted(scores, reverse=True)
    assert len({item["id"] for item in items}) == 6


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("type=cve", 1),
        ("band=high", 2),
        ("band=low", 3),
        ("min_score=60", 3),
        ("max_score=35", 3),
        ("reason=STALE_EVIDENCE", 1),
        ("source=feodo", 1),
        ("needs_review=true", 1),
        ("type=url&band=low", 1),
        ("source=feodo&band=high", 1),
    ],
)
def test_filters_narrow_the_page(client, query, expected):
    body = client.get(f"/v1/indicators?{query}").json()
    assert len(body["items"]) == expected


def test_a_page_carries_the_run_metadata(client):
    body = client.get("/v1/indicators?limit=1").json()

    run = body["run"]
    assert datetime.fromisoformat(run["as_of"].replace("Z", "+00:00")) == NOW
    assert run["policy_version"] == DEFAULT_POLICY.version
    assert run["policy_config_hash"] == config_fingerprint(DEFAULT_POLICY)
    assert run["rules_config_hash"]
    assert run["indicators"] == 6
    assert body["limit"] == 1
    assert body["next_cursor"]


def test_cursor_pagination_covers_every_row_exactly_once(client):
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        url = "/v1/indicators?limit=2"
        if cursor:
            url += f"&cursor={cursor}"
        body = client.get(url).json()
        seen.extend(item["id"] for item in body["items"])
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert pages == 3
    assert len(seen) == len(set(seen)) == 6


def test_the_cursor_does_not_embed_an_indicator_value(client):
    cursor = client.get("/v1/indicators?limit=2").json()["next_cursor"]
    decoded = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()

    payload = json.loads(decoded)
    assert set(payload) == {"score", "id"}
    assert "example.com" not in decoded
    assert "CVE-2024-0001" not in decoded


# --- detail ------------------------------------------------------------------------------


def test_detail_returns_reasons_sources_and_provenance(client):
    items = client.get("/v1/indicators?type=cve").json()["items"]
    indicator_id = items[0]["id"]

    body = client.get(f"/v1/indicators/{indicator_id}").json()
    indicator = body["indicator"]

    assert indicator["value"] == "CVE-2024-0001"
    assert [reason["code"] for reason in indicator["reasons"]] == [
        "SRC_AUTHORITATIVE",
        "KEV_EXPLOITATION",
    ]
    assert indicator["attributes"] == {}
    assert indicator["sources"][0]["name"] == "cisa_kev"
    assert indicator["policy_config_hash"] == config_fingerprint(DEFAULT_POLICY)
    assert body["run"]["indicators"] == 6


def test_unknown_id_is_a_stable_404(client):
    response = client.get("/v1/indicators/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


# --- stats -------------------------------------------------------------------------------


def test_stats_match_the_fixture(client):
    body = client.get("/v1/stats").json()

    assert body["bands"] == {"high": 2, "medium": 1, "low": 3}
    assert body["needs_review"] == 1
    assert body["reasons"] == {
        "CORROBORATED": 1,
        "FRESH_AUTHORITATIVE": 1,
        "KEV_EXPLOITATION": 1,
        "SINGLE_COMMUNITY_SOURCE": 2,
        "SRC_AUTHORITATIVE": 2,
        "SRC_COMMUNITY": 3,
        "SRC_UNCLASSIFIED": 1,
        "STALE_EVIDENCE": 1,
        "UNCLASSIFIED_SOURCE": 1,
    }
    assert body["run"]["indicators"] == 6


# --- input validation --------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "band=urgent",
        "type=email",
        "limit=0",
        "limit=201",
        "min_score=101",
        "reason=lowercase",
        "cursor=" + "x" * 513,
    ],
)
def test_invalid_query_parameters_use_the_validation_envelope(client, query):
    response = client.get(f"/v1/indicators?{query}")

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["fields"]


def test_a_cursor_that_is_not_json_is_a_400(client):
    response = client.get("/v1/indicators?cursor=nope")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_cursor"


def test_a_cursor_with_a_score_outside_the_band_space_is_a_400(client):
    token = base64.urlsafe_b64encode(json.dumps({"score": 999, "id": "x"}).encode()).decode()

    response = client.get(f"/v1/indicators?cursor={token}")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_cursor"


# --- the pinned snapshot -----------------------------------------------------------------


def test_the_store_serves_the_run_it_started_with(gold_path):
    test_client = TestClient(create_app(gold_path))

    replaced = write_gold(evaluate_and_score([], as_of=NOW + timedelta(days=1)), gold_path)

    assert test_client.get("/health").json()["indicators"] == 6
    assert TestClient(create_app(replaced)).get("/health").json()["indicators"] == 0


def test_an_empty_gold_table_is_a_valid_snapshot(tmp_path):
    empty = write_gold(evaluate_and_score([], as_of=NOW), tmp_path / "empty.parquet")
    with TestClient(create_app(empty)) as client:
        assert client.get("/health").json() == {"status": "ok", "indicators": 0}

        page = client.get("/v1/indicators").json()
        assert page["items"] == []
        assert page["next_cursor"] is None
        assert page["run"]["indicators"] == 0
        assert page["run"]["as_of"] is None

        stats = client.get("/v1/stats").json()
        assert stats["bands"] == {"high": 0, "medium": 0, "low": 0}
        assert stats["reasons"] == {}


def test_a_missing_gold_table_fails_at_startup(tmp_path):
    with pytest.raises(FileNotFoundError, match="gold table not found"):
        create_app(tmp_path / "absent.parquet")


def test_a_gold_table_that_mixes_runs_fails_at_startup(gold_path, tmp_path):
    table = pq.read_table(gold_path)
    rows = table.to_pylist()
    rows[0]["as_of"] = NOW - timedelta(days=1)
    mixed = tmp_path / "mixed.parquet"
    pq.write_table(pa.Table.from_pylist(rows, schema=table.schema), mixed)

    with pytest.raises(GoldStoreError, match="mixes runs"):
        create_app(mixed)
