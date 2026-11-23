"""Normalization, identity and merge: the contract every other module depends on."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from threatintel.normalize.kev import indicators_from_kev
from threatintel.normalize.schema import (
    Indicator,
    IndicatorType,
    InvalidIndicator,
    SourceRef,
    indicator_id,
    merge_indicators,
    normalize_value,
)
from threatintel.normalize.silver import read_indicators, upsert_indicators, write_indicators

DAY = datetime(2021, 12, 10, tzinfo=UTC)


@pytest.mark.parametrize(
    ("indicator_type", "raw", "expected"),
    [
        (IndicatorType.IP, "  1.2.3.4 ", "1.2.3.4"),
        (IndicatorType.IP, "2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
        (IndicatorType.IP, "::ffff:1.2.3.4", "1.2.3.4"),
        (IndicatorType.DOMAIN, "Example.COM.", "example.com"),
        (IndicatorType.DOMAIN, "*.bad.example.com", "bad.example.com"),
        (IndicatorType.DOMAIN, "münchen.de", "xn--mnchen-3ya.de"),
        (IndicatorType.URL, "HTTPS://Example.com:443/a?b=1#frag", "https://example.com/a?b=1"),
        (IndicatorType.URL, "http://user:pass@example.com/x", "http://example.com/x"),
        (IndicatorType.URL, "http://example.com", "http://example.com/"),
        (IndicatorType.HASH, "A" * 64, "a" * 64),
        (IndicatorType.CVE, " cve-2021-44228 ", "CVE-2021-44228"),
    ],
)
def test_normalizes_to_one_canonical_form(indicator_type, raw, expected):
    assert normalize_value(indicator_type, raw) == expected


@pytest.mark.parametrize(
    ("indicator_type", "raw"),
    [
        (IndicatorType.IP, "1.2.3.0/24"),
        (IndicatorType.IP, "999.1.1.1"),
        (IndicatorType.DOMAIN, "localhost"),
        (IndicatorType.DOMAIN, "has space.com"),
        (IndicatorType.URL, "ftp://example.com/f"),
        (IndicatorType.URL, "http:///nohost"),
        (IndicatorType.HASH, "a" * 63),
        (IndicatorType.HASH, "z" * 64),
        (IndicatorType.CVE, "CVE-21-1"),
    ],
)
def test_rejects_values_that_cannot_be_normalized(indicator_type, raw):
    with pytest.raises(InvalidIndicator):
        normalize_value(indicator_type, raw)


def test_id_is_deterministic_and_versioned():
    first = indicator_id(IndicatorType.CVE, "CVE-2021-44228")
    assert first == indicator_id(IndicatorType.CVE, "CVE-2021-44228")
    assert first != indicator_id(IndicatorType.CVE, "CVE-2021-44229")
    assert first[14] == "5", "expected a uuid5, not a random id"


def test_id_does_not_depend_on_type_spelling():
    assert indicator_id(IndicatorType.IP, "1.2.3.4") == indicator_id(
        IndicatorType("ip"), "1.2.3.4"
    )


def test_indicator_rejects_un_normalized_value():
    with pytest.raises(ValidationError):
        Indicator(
            id=indicator_id(IndicatorType.CVE, "CVE-2021-44228"),
            type=IndicatorType.CVE,
            value="cve-2021-44228",
            ingest_version="0.1.0",
        )


def test_indicator_rejects_foreign_id():
    with pytest.raises(ValidationError):
        Indicator(
            id=indicator_id(IndicatorType.CVE, "CVE-2021-44229"),
            type=IndicatorType.CVE,
            value="CVE-2021-44228",
            ingest_version="0.1.0",
        )


def _indicator(**overrides) -> Indicator:
    kwargs = {
        "type": IndicatorType.IP,
        "value": "198.51.100.7",
        "sources": [SourceRef(name="alpha", external_id="a-1", first_seen=DAY)],
        "tags": ["scanner"],
        "attributes": {"alpha": {"score": 90}},
        "ingest_version": "0.1.0",
        "bronze_refs": ["alpha/2021-12-10"],
    }
    kwargs.update(overrides)
    return Indicator.build(**kwargs)


def test_merge_unions_sources_without_inflating_reporters():
    later = datetime(2021, 12, 12, tzinfo=UTC)
    merged = merge_indicators(
        _indicator(),
        _indicator(
            sources=[SourceRef(name="beta", external_id="b-9", first_seen=later)],
            tags=["bruteforce"],
            attributes={"beta": {"confidence": 75}},
            bronze_refs=["beta/2021-12-12"],
        ),
    )
    assert [ref.name for ref in merged.sources] == ["alpha", "beta"]
    assert merged.distinct_reporters == 2
    assert merged.tags == ["bruteforce", "scanner"]
    assert merged.attributes == {"alpha": {"score": 90}, "beta": {"confidence": 75}}
    assert merged.bronze_refs == ["alpha/2021-12-10", "beta/2021-12-12"]
    assert merged.first_seen == DAY


def test_merge_from_the_same_source_keeps_the_widest_window():
    merged = merge_indicators(
        _indicator(),
        _indicator(
            sources=[
                SourceRef(
                    name="alpha",
                    external_id="a-1",
                    first_seen=datetime(2021, 12, 9, tzinfo=UTC),
                    last_seen=datetime(2021, 12, 20, tzinfo=UTC),
                )
            ]
        ),
    )
    assert merged.distinct_reporters == 1
    assert merged.first_seen == datetime(2021, 12, 9, tzinfo=UTC)
    assert merged.last_seen == datetime(2021, 12, 20, tzinfo=UTC)


def test_merge_refuses_different_indicators():
    with pytest.raises(ValueError):
        merge_indicators(_indicator(), _indicator(value="198.51.100.8"))


def test_kev_mapping_produces_sorted_indicators(kev_payload):
    result = indicators_from_kev(kev_payload, bronze_ref="kev/2026-11-23")
    assert len(result) == 5
    assert result.rejected == []
    values = [item.value for item in result.indicators]
    assert values == sorted(values)

    log4j = next(item for item in result.indicators if item.value == "CVE-2021-44228")
    assert log4j.type is IndicatorType.CVE
    assert "ransomware_campaign_use" in log4j.tags
    assert log4j.first_seen == datetime(2021, 12, 10, tzinfo=UTC)
    assert log4j.attributes["cisa_kev"]["product"] == "Log4j2"
    assert log4j.bronze_refs == ["kev/2026-11-23"]
    assert log4j.distinct_reporters == 1


def test_kev_mapping_records_rejections_instead_of_aborting(kev_payload):
    payload = json.loads(json.dumps(kev_payload))
    payload["vulnerabilities"].append({"vendorProject": "NoCve"})
    payload["vulnerabilities"].append("not-an-object")
    result = indicators_from_kev(payload, bronze_ref="kev/2026-11-23")
    assert len(result) == 5
    assert len(result.rejected) == 2
    assert all(item["reason"] for item in result.rejected)


def test_kev_mapping_is_stable_across_runs(kev_payload):
    first = indicators_from_kev(kev_payload, bronze_ref="kev/2026-11-23")
    second = indicators_from_kev(kev_payload, bronze_ref="kev/2026-11-23")
    assert [item.id for item in first.indicators] == [item.id for item in second.indicators]


def test_silver_round_trip_preserves_the_contract(tmp_path, kev_payload):
    indicators = indicators_from_kev(kev_payload, bronze_ref="kev/2026-11-23").indicators
    path = write_indicators(indicators, tmp_path / "indicators.parquet")
    restored = read_indicators(path)

    assert [item.id for item in restored] == [item.id for item in indicators]
    original = indicators_from_kev(kev_payload, bronze_ref="kev/2026-11-23").indicators
    assert restored[0].sources == original[0].sources
    assert restored[0].attributes == original[0].attributes
    assert restored[0].first_seen == original[0].first_seen


def test_upsert_is_idempotent_and_additive(tmp_path, kev_payload):
    path = tmp_path / "indicators.parquet"
    first_pass = indicators_from_kev(kev_payload, bronze_ref="kev/2026-11-23").indicators
    upsert_indicators(path, first_pass, path)
    second_pass = indicators_from_kev(kev_payload, bronze_ref="kev/2026-11-23").indicators
    upsert_indicators(path, second_pass, path)

    after_repeat = read_indicators(path)
    assert len(after_repeat) == 5
    assert all(item.distinct_reporters == 1 for item in after_repeat)

    # A second, independent source must enrich the row, not duplicate it.
    corroborating = [
        _indicator(
            type=IndicatorType.CVE,
            value="CVE-2021-44228",
            sources=[SourceRef(name="other_feed", external_id="x-1")],
            attributes={"other_feed": {"seen": True}},
            ingest_version="0.1.0",
        )
    ]
    upsert_indicators(path, corroborating, path)

    merged = {item.value: item for item in read_indicators(path)}["CVE-2021-44228"]
    assert len(merged.sources) == 2
    assert merged.distinct_reporters == 2
    assert merged.attributes["other_feed"] == {"seen": True}
    assert merged.attributes["cisa_kev"]["vendorProject"] == "Apache"
