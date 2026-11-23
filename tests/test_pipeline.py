"""Bronze -> silver pipeline: idempotency, empty input, and merge across collections."""

from __future__ import annotations

import json
from pathlib import Path

from threatintel.normalize.pipeline import build_silver, main
from threatintel.normalize.silver import read_indicators


def _bronze_with_payload(tmp_path: Path, kev_payload_bytes: bytes) -> Path:
    target = tmp_path / "cisa_kev" / "collection_date=2026-11-23"
    target.mkdir(parents=True)
    (target / "payload.json").write_bytes(kev_payload_bytes)
    (target / "_meta.json").write_text(json.dumps({"sha256": "abc", "count": 5}))
    return tmp_path


def _bronze_with_threatfox(
    bronze: Path, threatfox_payload_bytes: bytes, day: str = "2026-11-23"
) -> None:
    target = bronze / "threatfox" / f"collection_date={day}"
    target.mkdir(parents=True)
    (target / "payload.json").write_bytes(threatfox_payload_bytes)
    (target / "_meta.json").write_text(json.dumps({"sha256": "tf", "count": 4}))


def _bronze_with_feodo(
    bronze: Path, feodo_payload_bytes: bytes, day: str = "2026-11-23"
) -> None:
    target = bronze / "feodo" / f"collection_date={day}"
    target.mkdir(parents=True)
    (target / "payload.json").write_bytes(feodo_payload_bytes)
    (target / "_meta.json").write_text(json.dumps({"sha256": "fd", "count": 4}))


def test_build_silver_maps_every_batch(tmp_path, kev_payload_bytes):
    bronze = _bronze_with_payload(tmp_path / "bronze", kev_payload_bytes)
    silver = tmp_path / "silver" / "indicators.parquet"

    stats = build_silver(bronze, silver)

    assert stats == {"batches": 1, "rejected": 0, "source_rows": 5, "indicators": 5}
    indicators = read_indicators(silver)
    assert len(indicators) == 5
    assert {item.bronze_refs[0] for item in indicators} == {"cisa_kev/collection_date=2026-11-23"}


def test_build_silver_twice_changes_nothing(tmp_path, kev_payload_bytes):
    bronze = _bronze_with_payload(tmp_path / "bronze", kev_payload_bytes)
    silver = tmp_path / "indicators.parquet"

    build_silver(bronze, silver)
    build_silver(bronze, silver)

    assert len(read_indicators(silver)) == 5
    assert all(item.distinct_reporters == 1 for item in read_indicators(silver))


def test_two_collection_dates_merge_into_one_row(tmp_path, kev_payload_bytes):
    bronze = _bronze_with_payload(tmp_path / "bronze", kev_payload_bytes)
    second = bronze / "cisa_kev" / "collection_date=2026-11-24"
    second.mkdir(parents=True)
    (second / "payload.json").write_bytes(kev_payload_bytes)
    (second / "_meta.json").write_text(json.dumps({"sha256": "def", "count": 5}))
    silver = tmp_path / "indicators.parquet"

    stats = build_silver(bronze, silver)
    indicators = read_indicators(silver)

    assert stats["batches"] == 2
    assert len(indicators) == 5
    log4j = next(item for item in indicators if item.value == "CVE-2021-44228")
    assert log4j.distinct_reporters == 1, "one source seen twice is still one reporter"
    assert len(log4j.bronze_refs) == 2


def test_both_sources_land_in_one_silver_file(
    tmp_path, kev_payload_bytes, threatfox_payload_bytes
):
    """KEV yields CVEs, ThreatFox yields ip/url/domain/hash: disjoint types, one table.

    They cannot share a row here, so this proves coexistence and provenance rather than
    a cross-source merge — that merge is proven at the contract level in
    `test_normalize.py::test_upsert_is_idempotent_and_additive`.
    """
    bronze = _bronze_with_payload(tmp_path / "bronze", kev_payload_bytes)
    _bronze_with_threatfox(bronze, threatfox_payload_bytes)
    silver = tmp_path / "indicators.parquet"

    stats = build_silver(bronze, silver)
    indicators = read_indicators(silver)

    assert stats == {"batches": 2, "rejected": 0, "source_rows": 9, "indicators": 9}
    by_type: dict[str, int] = {}
    for item in indicators:
        by_type[item.type.value] = by_type.get(item.type.value, 0) + 1
    assert by_type == {"cve": 5, "domain": 1, "hash": 1, "ip": 1, "url": 1}
    assert all(item.distinct_reporters == 1 for item in indicators)
    sources_seen = {ref.split("/")[0] for item in indicators for ref in item.bronze_refs}
    assert sources_seen == {"cisa_kev", "threatfox"}


def test_same_source_on_two_dates_merges_the_indicator(
    tmp_path, threatfox_payload_bytes
):
    bronze = tmp_path / "bronze"
    _bronze_with_threatfox(bronze, threatfox_payload_bytes, "2026-11-23")
    _bronze_with_threatfox(bronze, threatfox_payload_bytes, "2026-11-24")
    silver = tmp_path / "indicators.parquet"

    stats = build_silver(bronze, silver)
    indicators = read_indicators(silver)
    domain = next(item for item in indicators if item.value == "cdn-update-service.example")

    assert stats["batches"] == 2
    assert stats["source_rows"] == 8, "eight rows arrived"
    assert stats["indicators"] == 4, "four survive dedupe"
    assert len(indicators) == 4, "same indicators on two dates must not duplicate rows"
    assert domain.distinct_reporters == 1
    assert len(domain.bronze_refs) == 2


def test_feodo_merges_with_threatfox_on_the_same_ip(
    tmp_path, kev_payload_bytes, threatfox_payload_bytes, feodo_payload_bytes
):
    """The cross-source merge the contract promises, exercised on real mappings.

    ThreatFox and Feodo both flag 198.51.100.23 (ThreatFox with `ip:port`, Feodo with a
    C2 entry), so the two must collapse into one row with two reporters and attributes
    kept under their own source key.
    """
    bronze = _bronze_with_payload(tmp_path / "bronze", kev_payload_bytes)
    _bronze_with_threatfox(bronze, threatfox_payload_bytes)
    _bronze_with_feodo(bronze, feodo_payload_bytes)
    silver = tmp_path / "indicators.parquet"

    stats = build_silver(bronze, silver)
    indicators = read_indicators(silver)

    assert stats == {"batches": 3, "rejected": 0, "source_rows": 12, "indicators": 11}
    merged = next(item for item in indicators if item.value == "198.51.100.23")
    assert merged.distinct_reporters == 2
    assert set(merged.attributes) == {"threatfox", "feodo"}
    assert merged.attributes["threatfox"]["port"] == 443
    assert merged.attributes["feodo"]["ports"] == [443]
    assert set(merged.source_confidence) == {"threatfox", "feodo"}
    assert merged.tags == ["CobaltStrike", "Emotet", "QakBot", "botnet_cc"]


def _bronze_with_urlhaus(
    bronze: Path, csv_text: str, day: str = "2026-11-23"
) -> None:
    target = bronze / "urlhaus" / f"collection_date={day}"
    target.mkdir(parents=True)
    (target / "payload.csv").write_text(csv_text, encoding="utf-8")
    (target / "_meta.json").write_text(json.dumps({"sha256": "uh", "count": 1}))


URLHAUS_HEADER = (
    "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
)


def test_urlhaus_csv_batch_lands_in_silver(tmp_path, urlhaus_payload_bytes):
    bronze = tmp_path / "bronze"
    _bronze_with_urlhaus(bronze, urlhaus_payload_bytes.decode("utf-8-sig"))
    silver = tmp_path / "indicators.parquet"

    stats = build_silver(bronze, silver)

    assert stats == {"batches": 1, "rejected": 0, "source_rows": 2, "indicators": 2}
    indicators = read_indicators(silver)
    assert {item.type.value for item in indicators} == {"url"}
    assert {item.bronze_refs[0] for item in indicators} == {
        "urlhaus/collection_date=2026-11-23"
    }


def test_urlhaus_url_merges_with_threatfox_on_the_same_url(
    tmp_path, threatfox_payload_bytes
):
    """The second community source is what turns FP-05 from a universal verdict into a rule."""
    bronze = tmp_path / "bronze"
    _bronze_with_threatfox(bronze, threatfox_payload_bytes)
    _bronze_with_urlhaus(
        bronze,
        URLHAUS_HEADER
        + "3600009,2026-11-19 23:41:55,http://203.0.113.44:8080/gate.php,online,"
        + "2026-11-20 03:02:10,malware_download,\"qakbot\","
        + "https://urlhaus.abuse.ch/url/3600009/,reporter_x\n",
    )
    silver = tmp_path / "indicators.parquet"

    stats = build_silver(bronze, silver)
    indicators = read_indicators(silver)
    merged = next(
        item for item in indicators if item.value == "http://203.0.113.44:8080/gate.php"
    )

    assert stats == {"batches": 2, "rejected": 0, "source_rows": 5, "indicators": 4}
    assert merged.distinct_reporters == 2
    assert set(merged.attributes) == {"threatfox", "urlhaus"}
    assert merged.tags == ["malware_download", "payload_delivery", "qakbot"]
    assert merged.source_confidence == {"threatfox": 1.0}, "URLhaus publishes no score"


def test_empty_bronze_reports_nothing_written(tmp_path, capsys):
    stats = build_silver(tmp_path, tmp_path / "indicators.parquet")
    assert stats == {"batches": 0, "rejected": 0, "source_rows": 0, "indicators": 0}
    assert not (tmp_path / "indicators.parquet").exists()
    assert main(["--bronze", str(tmp_path), "--silver", str(tmp_path / "s.parquet")]) == 1
    assert "no bronze batches" in capsys.readouterr().err
