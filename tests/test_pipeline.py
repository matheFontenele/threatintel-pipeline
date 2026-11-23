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


def test_build_silver_maps_every_batch(tmp_path, kev_payload_bytes):
    bronze = _bronze_with_payload(tmp_path / "bronze", kev_payload_bytes)
    silver = tmp_path / "silver" / "indicators.parquet"

    stats = build_silver(bronze, silver)

    assert stats == {"batches": 1, "rejected": 0, "indicators": 5}
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


def test_empty_bronze_reports_nothing_written(tmp_path, capsys):
    stats = build_silver(tmp_path, tmp_path / "indicators.parquet")
    assert stats == {"batches": 0, "rejected": 0, "indicators": 0}
    assert not (tmp_path / "indicators.parquet").exists()
    assert main(["--bronze", str(tmp_path), "--silver", str(tmp_path / "s.parquet")]) == 1
    assert "no bronze batches" in capsys.readouterr().err
