"""The local fair-use guard: it must block repeats, and must fail open when unsure."""

from __future__ import annotations

import json

from threatintel.collectors.throttle import (
    record_fetch,
    seconds_until_allowed,
)


def test_missing_state_allows_the_first_fetch(tmp_path):
    state = tmp_path / "last_fetch.json"
    assert seconds_until_allowed("feodo", state_path=state) == 0.0
    assert not state.exists()


def test_interval_counts_down_then_expires(tmp_path):
    state = tmp_path / "last_fetch.json"
    record_fetch("feodo", state_path=state, now=1_000.0)

    wait = seconds_until_allowed("feodo", state_path=state, min_interval=3_600, now=1_100.0)
    assert wait == 3_500
    assert seconds_until_allowed("feodo", state_path=state, min_interval=3_600, now=4_600.0) == 0.0


def test_sources_are_tracked_independently(tmp_path):
    state = tmp_path / "last_fetch.json"
    record_fetch("feodo", state_path=state, now=1_000.0)

    assert seconds_until_allowed("urlhaus", state_path=state, min_interval=3_600, now=1_100.0) == 0
    assert seconds_until_allowed("feodo", state_path=state, min_interval=3_600, now=1_100.0) > 0


def test_zero_interval_disables_the_guard(tmp_path):
    state = tmp_path / "last_fetch.json"
    record_fetch("feodo", state_path=state, now=1_000.0)
    assert seconds_until_allowed("feodo", state_path=state, min_interval=0, now=1_001.0) == 0.0


def test_corrupt_state_fails_open(tmp_path):
    state = tmp_path / "last_fetch.json"
    state.write_text("{not json")
    assert seconds_until_allowed("feodo", state_path=state) == 0.0


def test_garbage_values_are_ignored_not_fatal(tmp_path):
    state = tmp_path / "last_fetch.json"
    state.write_text(json.dumps({"feodo": "yesterday", "urlhaus": 1_000.0}))

    assert seconds_until_allowed("feodo", state_path=state) == 0.0
    assert seconds_until_allowed("urlhaus", state_path=state, min_interval=3_600, now=1_100.0) > 0


def test_recording_merges_and_leaves_no_temp_file(tmp_path):
    state = tmp_path / "nested" / "last_fetch.json"
    record_fetch("feodo", state_path=state, now=1_000.0)
    record_fetch("urlhaus", state_path=state, now=2_000.0)

    stored = json.loads(state.read_text())
    assert stored == {"feodo": 1_000.0, "urlhaus": 2_000.0}
    assert sorted(p.name for p in state.parent.iterdir()) == ["last_fetch.json"]
