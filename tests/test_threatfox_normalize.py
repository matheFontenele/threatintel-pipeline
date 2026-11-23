"""ThreatFox mapping: four indicator types, the ip:port case, and rejections."""

from __future__ import annotations

import json

import pytest

from threatintel.normalize.schema import IndicatorType
from threatintel.normalize.threatfox import indicators_from_threatfox, split_ip_port

REF = "threatfox/collection_date=2026-11-23"


def _by_value(result) -> dict[str, object]:
    return {item.value: item for item in result.indicators}


@pytest.mark.parametrize(
    ("ioc", "expected"),
    [
        ("1.2.3.4:443", ("1.2.3.4", 443)),
        ("1.2.3.4", ("1.2.3.4", None)),
        ("2001:db8::1", ("2001:db8::1", None)),
        ("[2001:db8::1]:8080", ("2001:db8::1", 8080)),
    ],
)
def test_split_ip_port(ioc, expected):
    assert split_ip_port(ioc) == expected


def test_maps_every_supported_type(threatfox_payload):
    result = indicators_from_threatfox(threatfox_payload, bronze_ref=REF)
    assert result.rejected == []
    by_value = _by_value(result)

    assert by_value["cdn-update-service.example"].type is IndicatorType.DOMAIN
    assert by_value["http://203.0.113.44:8080/gate.php"].type is IndicatorType.URL
    assert by_value["198.51.100.23"].type is IndicatorType.IP
    assert by_value["5b7e82e051ade4b14d163eea2a17bf8b"].type is IndicatorType.HASH


def test_ip_port_keeps_the_port_as_an_attribute(threatfox_payload):
    indicator = _by_value(indicators_from_threatfox(threatfox_payload, bronze_ref=REF))[
        "198.51.100.23"
    ]
    assert indicator.attributes["threatfox"]["port"] == 443
    assert indicator.attributes["threatfox"]["malware_printable"] == "Cobalt Strike"
    assert "CobaltStrike" in indicator.tags


def test_confidence_is_normalized_and_reporter_is_kept_as_attribute(threatfox_payload):
    qakbot = _by_value(indicators_from_threatfox(threatfox_payload, bronze_ref=REF))[
        "http://203.0.113.44:8080/gate.php"
    ]
    assert qakbot.source_confidence == {"threatfox": 1.0}
    assert qakbot.attributes["threatfox"]["reporter"] == "researcher_x"
    assert qakbot.last_seen is not None
    assert "payload_delivery" in qakbot.tags


def test_distinct_reporters_stays_one_for_a_single_feed(threatfox_payload):
    result = indicators_from_threatfox(threatfox_payload, bronze_ref=REF)
    assert all(item.distinct_reporters == 1 for item in result.indicators)


def test_unsupported_and_garbage_entries_are_rejected_not_fatal(threatfox_payload):
    payload = json.loads(json.dumps(threatfox_payload))
    payload["data"].append({"ioc": "s3://bucket/key", "ioc_type": "s3_path"})
    payload["data"].append({"ioc": "has space.example", "ioc_type": "domain"})
    payload["data"].append("not-an-object")

    result = indicators_from_threatfox(payload, bronze_ref=REF)

    assert len(result) == 4
    assert len(result.rejected) == 3
    assert all(entry["reason"] for entry in result.rejected)


def test_duplicate_iocs_merge_into_one_indicator(threatfox_payload):
    payload = json.loads(json.dumps(threatfox_payload))
    payload["data"].append(
        {
            "id": "999",
            "ioc": "CDN-Update-Service.example",
            "ioc_type": "domain",
            "threat_type": "botnet_cc",
            "confidence_level": 25,
            "first_seen": "2026-11-01 00:00:00 UTC",
        }
    )

    result = indicators_from_threatfox(payload, bronze_ref=REF)

    assert len(result) == 4
    merged = _by_value(result)["cdn-update-service.example"]
    assert merged.first_seen.isoformat().startswith("2026-11-01")
    assert merged.source_confidence == {"threatfox": 0.75}, "max confidence wins"
