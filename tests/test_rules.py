"""FP-04/FP-05 and the engine: the boundaries are where a rule lies to you.

Each test pins a decision that would be easy to get wrong silently — an indicator exactly
at its TTL, a future timestamp, a source nobody classified, a stale reason code that a rule
fix should have cleared.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from threatintel.fp_rules import (
    DEFAULT_RULES,
    AgingRule,
    CorroborationRule,
    RuleStatus,
    Strength,
    config_fingerprint,
    evaluate,
)
from threatintel.fp_rules.engine import main
from threatintel.normalize.schema import Indicator, IndicatorType, SourceRef

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


def _ip(**overrides) -> Indicator:
    fields = {
        "type": IndicatorType.IP,
        "value": "203.0.113.10",
        "sources": [SourceRef(name="feodo")],
        "ingest_version": "0.1.0",
        "last_seen": NOW - timedelta(days=1),
    }
    fields.update(overrides)
    return Indicator.build(**fields)


def _status(findings) -> RuleStatus:
    assert len(findings) == 1
    return findings[0].status


# --- FP-04: aging ------------------------------------------------------------------------


def test_exactly_at_the_ttl_does_not_fire():
    indicator = _ip(last_seen=NOW - timedelta(days=30))
    finding = AgingRule().evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.NOT_FIRED, "a boundary day is not yet stale"


def test_one_second_past_the_ttl_fires_moderate():
    indicator = _ip(last_seen=NOW - timedelta(days=30, seconds=1))
    finding = AgingRule().evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.FIRED
    assert finding.strength is Strength.MODERATE
    assert finding.evidence["ttl_days"] == 30
    assert finding.evidence["reference"] == "last_seen"


def test_last_seen_wins_over_first_seen():
    indicator = _ip(
        first_seen=NOW - timedelta(days=200),
        last_seen=NOW - timedelta(days=2),
    )
    finding = AgingRule().evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.NOT_FIRED
    assert finding.evidence["reference"] == "last_seen"


def test_first_seen_is_used_when_last_seen_is_missing():
    indicator = _ip(first_seen=NOW - timedelta(days=31), last_seen=None)
    finding = AgingRule().evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.FIRED
    assert finding.evidence["reference"] == "first_seen"


def test_a_future_timestamp_does_not_fire_but_is_reported():
    indicator = _ip(last_seen=NOW + timedelta(days=3))
    finding = AgingRule().evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.NOT_FIRED, "bad data is not fresh evidence, but not stale"
    assert "future" in finding.detail
    assert finding.evidence["age_seconds"] < 0


def test_no_dates_is_insufficient_data_not_fresh():
    indicator = _ip(last_seen=None, first_seen=None)
    finding = AgingRule().evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.INSUFFICIENT_DATA, "missing data must not read as clean"


def test_cve_is_not_aged():
    indicator = Indicator.build(
        type=IndicatorType.CVE,
        value="CVE-2024-1234",
        sources=[SourceRef(name="cisa_kev")],
        ingest_version="0.1.0",
        last_seen=NOW - timedelta(days=3_650),
    )
    finding = AgingRule().evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.NOT_APPLICABLE, (
        "KEV catalogues exploitation, it does not expire"
    )


def test_a_custom_ttl_changes_the_verdict():
    indicator = _ip(last_seen=NOW - timedelta(days=2))
    finding = AgingRule(ttl_days={IndicatorType.IP: 1}).evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.FIRED
    assert finding.evidence["ttl_days"] == 1


def test_naive_as_of_is_refused():
    with pytest.raises(ValueError, match="timezone-aware"):
        AgingRule().evaluate(_ip(), as_of=datetime(2026, 11, 23, 12, 0))


# --- FP-05: corroboration ----------------------------------------------------------------


def test_one_community_feed_fires_weak():
    indicator = _ip(sources=[SourceRef(name="threatfox")])
    finding = CorroborationRule().evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.FIRED
    assert finding.strength is Strength.WEAK
    assert finding.evidence["distinct_reporters"] == 1


def test_two_independent_feeds_do_not_fire():
    indicator = _ip(sources=[SourceRef(name="threatfox"), SourceRef(name="feodo")])
    finding = CorroborationRule().evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.NOT_FIRED
    assert finding.evidence["sources"] == ["feodo", "threatfox"]


def test_an_authoritative_feed_alone_is_not_suspicious():
    finding = CorroborationRule().evaluate(_ip(sources=[SourceRef(name="feodo")]), as_of=NOW)[0]
    assert finding.status is RuleStatus.NOT_APPLICABLE


def test_kev_as_a_source_on_a_supported_type_is_authoritative():
    indicator = _ip(sources=[SourceRef(name="cisa_kev")])
    finding = CorroborationRule().evaluate(indicator, as_of=NOW)[0]
    assert finding.status is RuleStatus.NOT_APPLICABLE


def test_an_unclassified_source_is_insufficient_data_not_a_benefit_of_the_doubt():
    indicator = _ip(sources=[SourceRef(name="mystery_feed")])
    finding = CorroborationRule().evaluate(indicator, as_of=NOW)[0]

    assert finding.status is RuleStatus.INSUFFICIENT_DATA
    assert finding.evidence["unclassified_sources"] == ["mystery_feed"]


def test_no_sources_is_insufficient_data():
    indicator = _ip(sources=[])
    finding = CorroborationRule().evaluate(indicator, as_of=NOW)[0]
    assert finding.status is RuleStatus.INSUFFICIENT_DATA


def test_cve_corroboration_is_out_of_scope():
    indicator = Indicator.build(
        type=IndicatorType.CVE,
        value="CVE-2024-1234",
        sources=[SourceRef(name="cisa_kev")],
        ingest_version="0.1.0",
    )
    finding = CorroborationRule().evaluate(indicator, as_of=NOW)[0]
    assert finding.status is RuleStatus.NOT_APPLICABLE


# --- the engine ---------------------------------------------------------------------------


def test_engine_annotates_fired_codes_in_order():
    report = evaluate(
        [_ip(last_seen=NOW - timedelta(days=40), sources=[SourceRef(name="threatfox")])],
        as_of=NOW,
    )
    assert report.annotated[0].fp_reasons == ["FP-04_STALE", "FP-05_SINGLE_SOURCE"]


def test_engine_is_idempotent():
    first = evaluate([_ip(last_seen=NOW - timedelta(days=40))], as_of=NOW)
    second = evaluate(first.annotated, as_of=NOW)
    assert second.annotated[0].fp_reasons == first.annotated[0].fp_reasons


def test_a_stale_owned_code_is_removed_once_the_rule_stops_firing():
    indicator = _ip(last_seen=NOW - timedelta(days=1), fp_reasons=["FP-04_STALE"])
    report = evaluate([indicator], as_of=NOW)
    assert report.annotated[0].fp_reasons == [], "a rule fix must clear its old annotation"


def test_a_foreign_code_is_preserved():
    indicator = _ip(last_seen=NOW - timedelta(days=1), fp_reasons=["FP-99_FOREIGN"])
    report = evaluate([indicator], as_of=NOW)
    assert report.annotated[0].fp_reasons == ["FP-99_FOREIGN"]


def test_a_partial_run_does_not_clobber_a_rule_that_was_not_run():
    indicator = _ip(
        last_seen=NOW - timedelta(days=1),
        fp_reasons=["FP-05_SINGLE_SOURCE"],
    )
    report = evaluate([indicator], as_of=NOW, rules=(AgingRule(),))
    assert report.annotated[0].fp_reasons == ["FP-05_SINGLE_SOURCE"]


def test_config_hash_is_stable_and_parameter_sensitive():
    assert config_fingerprint(DEFAULT_RULES) == config_fingerprint(tuple(reversed(DEFAULT_RULES)))
    assert config_fingerprint([AgingRule()]) != config_fingerprint(
        [AgingRule(ttl_days={IndicatorType.IP: 1})]
    )


def test_report_never_carries_an_indicator_value():
    report = evaluate([_ip(value="198.51.100.77")], as_of=NOW)
    serialized = json.dumps(report.summary())
    assert "198.51.100.77" not in serialized
    assert report.annotated[0].value == "198.51.100.77", "in-memory rows keep their value"


def test_counts_and_type_rates_shape():
    report = evaluate(
        [
            _ip(value="203.0.113.10", last_seen=NOW - timedelta(days=40),
                sources=[SourceRef(name="threatfox")]),
            _ip(value="203.0.113.11", last_seen=NOW - timedelta(days=1),
                sources=[SourceRef(name="feodo")]),
        ],
        as_of=NOW,
    )

    assert report.counts()["FP-04_STALE"] == {"fired": 1, "not_fired": 1}
    assert report.counts()["FP-05_SINGLE_SOURCE"] == {"fired": 1, "not_applicable": 1}
    rates = report.type_rates()["ip"]["FP-04_STALE"]
    assert rates == {"fired": 1, "total": 2, "rate": 0.5}


def test_default_as_of_is_timezone_aware():
    report = evaluate([_ip()])
    assert report.as_of.tzinfo is not None


def test_engine_rejects_a_naive_clock():
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate([_ip()], as_of=datetime(2026, 11, 23, 12, 0))


# --- CLI -----------------------------------------------------------------------------------


def test_cli_prints_json_without_values(tmp_path, capsys):
    from threatintel.normalize.silver import write_indicators

    silver = tmp_path / "indicators.parquet"
    write_indicators([_ip(value="198.51.100.99", last_seen=NOW - timedelta(days=40))], silver)

    code = main(["--silver", str(silver), "--as-of", "2026-11-23T12:00:00Z", "--json"])

    assert code == 0
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["config_hash"]
    assert payload["counts"]["FP-04_STALE"]["fired"] == 1
    assert "198.51.100.99" not in output


def test_cli_writes_the_annotated_table(tmp_path):
    from threatintel.normalize.silver import read_indicators, write_indicators

    silver = tmp_path / "indicators.parquet"
    annotated = tmp_path / "annotated.parquet"
    write_indicators([_ip(last_seen=NOW - timedelta(days=40))], silver)

    code = main(
        [
            "--silver",
            str(silver),
            "--as-of",
            "2026-11-23T12:00:00Z",
            "--write-annotated",
            str(annotated),
        ]
    )

    assert code == 0
    assert read_indicators(annotated)[0].fp_reasons == ["FP-04_STALE"]


def test_cli_reports_a_missing_silver_table(tmp_path, capsys):
    code = main(["--silver", str(tmp_path / "absent.parquet")])
    assert code == 1
    assert "not found" in capsys.readouterr().err
