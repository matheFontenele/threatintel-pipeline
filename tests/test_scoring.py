"""Scoring: the arithmetic, the caps, and the promise that the number is reproducible.

Each test pins a claim the documentation makes — a band boundary, a structural cap, the
difference between "no cap" and "cap not binding", and the rule that a summary never carries
an indicator value. A scorer that drifts from its published policy is worse than no scorer,
because the output looks authoritative.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from threatintel.fp_rules import AgingRule, evaluate
from threatintel.normalize.schema import Indicator, IndicatorType, SourceRef
from threatintel.normalize.silver import write_indicators
from threatintel.scoring import (
    DEFAULT_POLICY,
    DEFAULT_WEIGHTS,
    GOLD_SCHEMA,
    ScorePolicy,
    config_fingerprint,
    evaluate_and_score,
    parse_as_of,
    read_gold,
    score_all,
    write_gold,
)
from threatintel.scoring import __main__ as scoring_cli

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


def _indicator(
    *,
    indicator_type: IndicatorType = IndicatorType.IP,
    value: str = "203.0.113.10",
    sources: list[str] | None = None,
    last_seen: datetime | None = None,
    first_seen: datetime | None = None,
) -> Indicator:
    refs = [SourceRef(name=name, last_seen=last_seen) for name in sources or ["feodo"]]
    return Indicator.build(
        type=indicator_type,
        value=value,
        sources=refs,
        ingest_version="0.1.0",
        first_seen=first_seen,
        last_seen=last_seen,
    )


def _codes(score) -> list[str]:
    return [reason.code for reason in score.reasons]


# --- base weights and bands ---------------------------------------------------------------


def test_authoritative_kev_reaches_the_top_band():
    indicator = _indicator(
        indicator_type=IndicatorType.CVE, value="CVE-2024-1234", sources=["cisa_kev"]
    )
    report = evaluate_and_score([indicator], as_of=NOW)
    score = report.scored[0].score

    assert _codes(score) == ["SRC_AUTHORITATIVE", "KEV_EXPLOITATION"]
    assert score.score == 70, "60 + 10: the two documented terms, nothing implicit"
    assert score.band == "high"
    assert score.needs_review is False


def test_fresh_authoritative_ip_reaches_the_top_band():
    indicator = _indicator(last_seen=NOW - timedelta(days=1))
    score = evaluate_and_score([indicator], as_of=NOW).scored[0].score

    assert _codes(score) == ["SRC_AUTHORITATIVE", "FRESH_AUTHORITATIVE"]
    assert score.score == 70
    assert score.band == "high"


def test_stale_authoritative_evidence_is_low_regardless_of_source_quality():
    indicator = _indicator(last_seen=NOW - timedelta(days=40))
    score = evaluate_and_score([indicator], as_of=NOW).scored[0].score

    assert "STALE_EVIDENCE" in _codes(score)
    assert "FRESH_AUTHORITATIVE" not in _codes(score)
    assert score.score == 30, "60 - 30: curated but out of date"
    assert score.band == "low"


def test_a_single_community_feed_is_low():
    indicator = _indicator(
        indicator_type=IndicatorType.URL,
        value="http://example.com/dropper.bin",
        sources=["threatfox"],
        last_seen=NOW - timedelta(days=1),
    )
    score = evaluate_and_score([indicator], as_of=NOW).scored[0].score

    assert _codes(score) == ["SRC_COMMUNITY", "SINGLE_COMMUNITY_SOURCE"]
    assert score.score == 35, "45 - 10: a claim by one feed"
    assert score.band == "low"


def test_two_independent_community_feeds_are_medium():
    indicator = _indicator(
        indicator_type=IndicatorType.URL,
        value="http://example.com/dropper.bin",
        sources=["threatfox", "urlhaus"],
        last_seen=NOW - timedelta(days=1),
    )
    score = evaluate_and_score([indicator], as_of=NOW).scored[0].score

    assert _codes(score) == ["SRC_COMMUNITY", "CORROBORATED"]
    assert score.score == 60
    assert score.band == "medium"


def test_an_unclassified_source_asks_for_review_and_stays_low():
    indicator = _indicator(sources=["mystery_feed"], last_seen=NOW - timedelta(days=1))
    score = evaluate_and_score([indicator], as_of=NOW).scored[0].score

    assert "UNCLASSIFIED_SOURCE" in _codes(score)
    assert score.needs_review is True, "independence is unknown, so the score is not trusted"
    assert score.band == "low"
    assert score.score <= 39


def test_missing_timestamps_are_unknown_age_not_fresh():
    indicator = _indicator(sources=["feodo"], last_seen=None, first_seen=None)
    score = evaluate_and_score([indicator], as_of=NOW).scored[0].score

    assert "UNKNOWN_AGE" in _codes(score)
    assert "FRESH_AUTHORITATIVE" not in _codes(score), "absent data must never read as fresh"
    assert score.needs_review is True
    assert score.score == 50


def test_the_score_is_the_sum_of_its_own_reasons_when_no_cap_binds():
    indicator = _indicator(
        indicator_type=IndicatorType.URL,
        value="http://example.com/dropper.bin",
        sources=["threatfox", "urlhaus"],
        last_seen=NOW - timedelta(days=1),
    )
    score = evaluate_and_score([indicator], as_of=NOW).scored[0].score

    assert score.score == sum(reason.weight for reason in score.reasons)
    assert score.caps == (), "no cap was needed, and the output says so"


# --- caps are guarantees ------------------------------------------------------------------


def test_a_cap_binds_when_arithmetic_would_beat_it():
    generous = ScorePolicy(weights={**DEFAULT_WEIGHTS, "SRC_AUTHORITATIVE": 100})
    indicator = _indicator(last_seen=NOW - timedelta(days=40))
    score = evaluate_and_score([indicator], as_of=NOW, policy=generous).scored[0].score

    assert score.score == 49, "100 - 30 = 70, but stale evidence cannot reach the top band"
    assert score.band == "medium", "49 is the top of the middle band, never high"
    assert score.caps == ("CAP_STALE",)


def test_unknown_age_cannot_reach_the_top_band():
    generous = ScorePolicy(weights={**DEFAULT_WEIGHTS, "SRC_AUTHORITATIVE": 90})
    indicator = _indicator(sources=["feodo"], last_seen=None, first_seen=None)
    score = evaluate_and_score([indicator], as_of=NOW, policy=generous).scored[0].score

    assert score.band != "high"
    assert score.score <= 69
    assert "CAP_UNKNOWN_AGE" in score.caps


def test_an_unclassified_source_cannot_exceed_the_bottom_band():
    generous = ScorePolicy(weights={**DEFAULT_WEIGHTS, "SRC_UNCLASSIFIED": 90})
    indicator = _indicator(sources=["mystery_feed"], last_seen=NOW - timedelta(days=1))
    score = evaluate_and_score([indicator], as_of=NOW, policy=generous).scored[0].score

    assert score.score == 39
    assert score.band == "low"
    assert "CAP_UNCLASSIFIED" in score.caps


def test_a_single_community_feed_cannot_reach_the_top_band():
    indicator = _indicator(sources=["threatfox"], last_seen=NOW - timedelta(days=1))
    report = evaluate_and_score([indicator], as_of=NOW)
    score = report.scored[0].score

    assert score.band != "high", "T3: one feed is a claim, not a consensus"
    assert score.score <= 69


def test_the_score_is_clamped_to_the_int_band():
    huge = ScorePolicy(weights=dict.fromkeys(DEFAULT_WEIGHTS, 1000))
    score = evaluate_and_score(
        [_indicator(sources=["feodo"], last_seen=NOW - timedelta(days=1))],
        as_of=NOW,
        policy=huge,
    ).scored[0].score

    assert score.score == 100


# --- reproducibility ----------------------------------------------------------------------


def test_the_same_inputs_score_the_same_twice():
    indicator = _indicator(last_seen=NOW - timedelta(days=2))
    first = evaluate_and_score([indicator], as_of=NOW).summary()
    second = evaluate_and_score([indicator], as_of=NOW).summary()

    assert first == second
    assert first["policy_config_hash"] != first["rules_config_hash"], (
        "the two layers are hashed separately so a drift is attributable"
    )


def test_changing_a_weight_changes_the_config_hash():
    changed = ScorePolicy(weights={**DEFAULT_WEIGHTS, "CORROBORATED": 20})

    assert config_fingerprint(DEFAULT_POLICY) == config_fingerprint(ScorePolicy())
    assert config_fingerprint(DEFAULT_POLICY) != config_fingerprint(changed)


def test_a_missing_rule_contributes_nothing_and_imposes_no_cap():
    indicator = _indicator(sources=["threatfox"], last_seen=NOW - timedelta(days=40))
    report = score_all(evaluate([indicator], as_of=NOW, rules=(AgingRule(),)))

    codes = _codes(report.scored[0].score)
    assert "SINGLE_COMMUNITY_SOURCE" not in codes
    assert "CORROBORATED" not in codes
    assert report.scored[0].score.caps == (), "a rule that did not run must not cap the score"


def test_the_summary_never_carries_an_indicator_value():
    indicator = _indicator(value="198.51.100.77", last_seen=NOW - timedelta(days=1))
    report = evaluate_and_score([indicator], as_of=NOW)

    serialized = json.dumps(report.summary())
    assert "198.51.100.77" not in serialized
    assert report.scored[0].indicator.value == "198.51.100.77", (
        "in-memory rows keep their value; only published summaries are value-free"
    )


def test_parse_as_of_treats_a_bare_date_as_midnight_utc():
    assert parse_as_of("2026-11-23") == datetime(2026, 11, 23, tzinfo=UTC)
    assert parse_as_of("2026-11-23T12:00:00Z").tzinfo is not None
    with pytest.raises(ValueError):
        parse_as_of("not-a-date")


# --- the gold table -----------------------------------------------------------------------


def test_gold_roundtrip_preserves_scores_and_reasons(tmp_path):
    indicators = [
        _indicator(value="203.0.113.10", last_seen=NOW - timedelta(days=1)),
        _indicator(
            value="203.0.113.11", sources=["threatfox"], last_seen=NOW - timedelta(days=1)
        ),
    ]
    report = evaluate_and_score(indicators, as_of=NOW)
    path = write_gold(report, tmp_path / "gold" / "indicators.parquet")

    restored = read_gold(path)

    assert [item.score.score for item in restored] == [70, 35], "output is ranked high to low"
    assert restored[0].score.reasons == report.scored[0].score.reasons
    assert [item.score.score for item in report.scored] == [70, 35], "input order is by type/value"
    assert restored[1].score.caps == report.scored[1].score.caps
    assert {item.score.policy_config_hash for item in restored} == {report.policy_config_hash}, (
        "a row that cannot name its policy cannot be reproduced"
    )


def test_gold_schema_matches_the_written_file(tmp_path):
    import pyarrow.parquet as pq

    report = evaluate_and_score([_indicator(last_seen=NOW - timedelta(days=1))], as_of=NOW)
    path = write_gold(report, tmp_path / "indicators.parquet")

    assert pq.read_schema(path) == GOLD_SCHEMA


# --- CLI ----------------------------------------------------------------------------------


def test_cli_writes_gold_and_prints_counts_only(tmp_path, capsys):
    silver = tmp_path / "silver.parquet"
    gold = tmp_path / "gold.parquet"
    write_indicators(
        [_indicator(value="198.51.100.99", last_seen=NOW - timedelta(days=40))], silver
    )

    code = scoring_cli.main(
        [
            "--silver",
            str(silver),
            "--out",
            str(gold),
            "--as-of",
            "2026-11-23T12:00:00Z",
            "--json",
        ]
    )

    assert code == 0
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["bands"] == {"low": 1, "medium": 0, "high": 0}
    assert payload["reasons"]["STALE_EVIDENCE"] == 1
    assert "198.51.100.99" not in output
    assert len(read_gold(gold)) == 1


def test_cli_reports_a_missing_silver_table(tmp_path, capsys):
    code = scoring_cli.main(["--silver", str(tmp_path / "absent.parquet")])

    assert code == 1
    assert "not found" in capsys.readouterr().err
