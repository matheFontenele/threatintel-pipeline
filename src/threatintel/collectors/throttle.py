"""Locally enforced minimum interval between fetches of the same source.

Fair use is a term of service, not a preference. abuse.ch rate-limits accounts with unusual
query volume for up to 72 hours (`docs/sources.md`), so a retry loop or a `--force` left in a
shell history is enough to lose access. The guard is local and dumb on purpose: it cannot be
bypassed by the provider changing an error code.

The state file is operational state, not evidence, so it lives outside bronze — losing it
must not invalidate a collection, and rebuilding it must not require re-downloading.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

DEFAULT_MIN_INTERVAL_SECONDS = 3600.0
DEFAULT_STATE_PATH = Path("data/state/last_fetch.json")


def _read(state_path: Path) -> dict[str, float]:
    try:
        data = json.loads(state_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(source): float(stamp)
        for source, stamp in data.items()
        if isinstance(stamp, int | float)
    }


def seconds_until_allowed(
    source: str,
    *,
    state_path: Path = DEFAULT_STATE_PATH,
    min_interval: float = DEFAULT_MIN_INTERVAL_SECONDS,
    now: float | None = None,
) -> float:
    """Return how long the caller must wait before fetching `source` again.

    Zero means allowed. A corrupt or missing state file means allowed: refusing to run
    because the bookkeeping is gone would be worse than one extra request.
    """
    if min_interval <= 0:
        return 0.0
    last = _read(state_path).get(source)
    if last is None:
        return 0.0
    elapsed = (time.time() if now is None else now) - last
    return max(0.0, min_interval - elapsed)


def record_fetch(
    source: str,
    *,
    state_path: Path = DEFAULT_STATE_PATH,
    now: float | None = None,
) -> None:
    """Record a successful fetch. Atomic, so a crash cannot truncate the state."""
    state = _read(state_path)
    state[source] = time.time() if now is None else now
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_name(state_path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    os.replace(tmp, state_path)
