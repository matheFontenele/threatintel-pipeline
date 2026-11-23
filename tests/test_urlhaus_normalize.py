"""URLhaus mapping: one row is one URL, and the comment banner must not eat the header."""

from __future__ import annotations

from threatintel.normalize.schema import IndicatorType
from threatintel.normalize.urlhaus import indicators_from_urlhaus

REF = "urlhaus/collection_date=2026-11-23"


def _text(fixture: bytes) -> str:
    return fixture.decode("utf-8-sig")


def _by_value(result) -> dict[str, object]:
    return {item.value: item for item in result.indicators}


def test_rows_become_url_indicators(urlhaus_payload_bytes):
    result = indicators_from_urlhaus(_text(urlhaus_payload_bytes), bronze_ref=REF)

    assert result.rejected == []
    assert len(result.indicators) == 2
    by_value = _by_value(result)
    assert set(by_value) == {
        "http://malware-download.example/payload.elf",
        "https://update-check.example/gate.php",
    }
    assert all(item.type is IndicatorType.URL for item in result.indicators)


def test_metadata_lands_in_attributes_and_tags(urlhaus_payload_bytes):
    indicator = _by_value(indicators_from_urlhaus(_text(urlhaus_payload_bytes), bronze_ref=REF))[
        "http://malware-download.example/payload.elf"
    ]

    urlhaus = indicator.attributes["urlhaus"]
    assert urlhaus["status"] == "online"
    assert urlhaus["threat"] == "malware_download"
    assert urlhaus["reporter"] == "reporter_x"
    assert indicator.tags == ["elf", "malware_download", "mozi"]


def test_window_uses_date_added_and_last_online(urlhaus_payload_bytes):
    indicator = _by_value(indicators_from_urlhaus(_text(urlhaus_payload_bytes), bronze_ref=REF))[
        "https://update-check.example/gate.php"
    ]

    assert indicator.first_seen.isoformat().startswith("2026-11-23T05:22")
    assert indicator.last_seen.isoformat().startswith("2026-11-21T09:30")
    assert indicator.first_seen.tzinfo is not None


def test_an_empty_last_online_costs_the_date_not_the_row(urlhaus_payload_bytes):
    text = _text(urlhaus_payload_bytes).replace("2026-11-21 09:30:00", "")

    result = indicators_from_urlhaus(text, bronze_ref=REF)

    indicator = _by_value(result)["https://update-check.example/gate.php"]
    assert indicator.last_seen is None
    assert len(result.indicators) == 2


def test_duplicate_urls_merge_into_one_indicator(urlhaus_payload_bytes):
    text = _text(urlhaus_payload_bytes)
    header, *rows = text.splitlines()
    earlier = rows[0].replace("2026-11-23 04:11:00", "2026-11-22 01:00:00")
    text = "\n".join([header, rows[0], earlier, rows[1]])

    result = indicators_from_urlhaus(text, bronze_ref=REF)

    assert len(result.indicators) == 2
    merged = _by_value(result)["http://malware-download.example/payload.elf"]
    assert merged.distinct_reporters == 1, "one feed seen twice is still one reporter"
    assert merged.first_seen.isoformat().startswith("2026-11-22T01:00")
    assert merged.last_seen.isoformat().startswith("2026-11-23T04:11")


def test_an_invalid_url_is_rejected_and_the_rest_survive(urlhaus_payload_bytes):
    text = _text(urlhaus_payload_bytes)
    text += "\n3600003,2026-11-23 06:00:00,not-a-url,online,,malware_download,x,,reporter_z\n"

    result = indicators_from_urlhaus(text, bronze_ref=REF)

    assert len(result.indicators) == 2
    assert len(result.rejected) == 1
    assert result.rejected[0]["reason"]


def test_provenance_is_the_batch_not_the_row(urlhaus_payload_bytes):
    result = indicators_from_urlhaus(_text(urlhaus_payload_bytes), bronze_ref=REF)

    assert all(item.bronze_refs == [REF] for item in result.indicators)
    assert all(item.distinct_reporters == 1 for item in result.indicators)
    assert all(item.sources[0].name == "urlhaus" for item in result.indicators)
