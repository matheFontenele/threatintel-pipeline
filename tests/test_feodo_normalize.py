"""Feodo mapping: ports collapse into one IP, status aggregates conservatively."""

from __future__ import annotations

import json

from threatintel.normalize.feodo import indicators_from_feodo
from threatintel.normalize.schema import IndicatorType

REF = "feodo/collection_date=2026-11-23"


def _by_value(result) -> dict[str, object]:
    return {item.value: item for item in result.indicators}


def test_one_indicator_per_ip_not_per_port(feodo_payload):
    result = indicators_from_feodo(feodo_payload, bronze_ref=REF)

    assert result.rejected == []
    assert len(result.indicators) == 3
    by_value = _by_value(result)
    assert set(by_value) == {"203.0.113.10", "198.51.100.23", "2001:db8::42"}
    assert by_value["198.51.100.23"].type is IndicatorType.IP


def test_ports_collapse_and_status_is_online_if_any_entry_is(feodo_payload):
    indicator = _by_value(indicators_from_feodo(feodo_payload, bronze_ref=REF))["203.0.113.10"]

    feodo_attrs = indicator.attributes["feodo"]
    assert feodo_attrs["ports"] == [443, 8080]
    assert feodo_attrs["status"] == "online", "one online port makes the host a live C2"
    assert feodo_attrs["statuses"] == ["offline", "online"], "the mix stays auditable"
    assert feodo_attrs["entries"] == 2
    assert feodo_attrs["countries"] == ["NL"]
    assert feodo_attrs["as_numbers"] == [64500]


def test_malware_families_become_tags_and_split_on_commas(feodo_payload):
    indicator = _by_value(indicators_from_feodo(feodo_payload, bronze_ref=REF))["198.51.100.23"]
    assert indicator.tags == ["Emotet", "QakBot"]
    assert indicator.attributes["feodo"]["hostnames"] == ["mail-gw.example"]


def test_ipv6_is_preserved_and_not_truncated(feodo_payload):
    indicator = _by_value(indicators_from_feodo(feodo_payload, bronze_ref=REF))["2001:db8::42"]
    assert indicator.value == "2001:db8::42"
    assert indicator.attributes["feodo"]["ports"] == [4443]


def test_window_is_min_first_seen_and_max_last_online(feodo_payload):
    indicator = _by_value(indicators_from_feodo(feodo_payload, bronze_ref=REF))["203.0.113.10"]
    assert indicator.first_seen.isoformat().startswith("2026-10-15")
    assert indicator.last_seen.isoformat().startswith("2026-11-23")
    assert indicator.first_seen.tzinfo is not None


def test_confidence_is_one_and_one_feed_counts_once(feodo_payload):
    result = indicators_from_feodo(feodo_payload, bronze_ref=REF)
    assert all(item.source_confidence == {"feodo": 1.0} for item in result.indicators)
    assert all(item.distinct_reporters == 1 for item in result.indicators)
    assert all(item.bronze_refs == [REF] for item in result.indicators)


def test_bad_entries_are_rejected_not_fatal(feodo_payload):
    payload = json.loads(json.dumps(feodo_payload))
    payload.append({"ip_address": "not-an-ip", "port": 443, "status": "online"})
    payload.append({"ip_address": "203.0.113.99", "port": "443", "status": "online"})
    payload.append({"ip_address": "203.0.113.98", "port": 443, "status": "maybe"})
    payload.append({"ip_address": "", "port": 443, "status": "online"})
    payload.append("not-an-object")

    result = indicators_from_feodo(payload, bronze_ref=REF)

    assert len(result) == 3
    assert len(result.rejected) == 5
    assert all(entry["reason"] for entry in result.rejected)


def test_a_payload_that_is_not_a_list_is_rejected_as_a_whole():
    result = indicators_from_feodo({"data": []}, bronze_ref=REF)
    assert result.indicators == []
    assert result.rejected[0]["reason"] == "payload is not a JSON array"
