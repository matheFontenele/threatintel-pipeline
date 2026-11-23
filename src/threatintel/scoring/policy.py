"""The scoring policy: integer weights, hard caps, and one place to change them.

The rules answer "is this signal present?". The scorer answers "how much does the first
answer move the priority?" — and the separation is deliberate. A rule that cannot show a
marginal effect in the ablation (`docs/methodology.md` §8) does not deserve its weight, and
that argument is only possible while the weights live in one reviewable table.

Two properties keep the number honest:

- **Integer weights, not probabilities.** A score of 70 means "70 points of the documented
  policy", not "70% likely malicious". No calibration has happened yet, so the policy says
  so in the output it ships.
- **Structural caps, not just penalties.** A stale indicator *cannot* reach the top band,
  and a single community feed *cannot* reach it either, no matter how the weights are
  tuned. These encode threats T3 and T4 of the threat model as guarantees rather than as
  arithmetic that a future edit might quietly undo.

`POLICY_VERSION` and `describe()` exist because a weight change changes every score: it
must be a new configuration with a new hash, not a silent reinterpretation of old output.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

POLICY_VERSION = "2026-11-23.2"

# Bands are named, not numeric, in the result. `high` is the only band that claims
# "look at this now"; the documentation maps that sentence to the policy, not to a URL.
BAND_HIGH = "high"
BAND_MEDIUM = "medium"
BAND_LOW = "low"
BAND_THRESHOLDS: tuple[tuple[str, int], ...] = ((BAND_HIGH, 70), (BAND_MEDIUM, 40))

# Weights are provisional hypotheses. Sign is the part that is argued, magnitude is the
# part that awaits calibration — and the report says exactly that.
DEFAULT_WEIGHTS: dict[str, int] = {
    "SRC_AUTHORITATIVE": 60,  # a curated catalogue / C2 blocklist
    "SRC_COMMUNITY": 45,  # a collaborative feed: a claim
    "SRC_UNCLASSIFIED": 30,  # a feed nobody has classified yet
    "FRESH_AUTHORITATIVE": 10,  # inside TTL *and* curated: the strongest combination
    "CORROBORATED": 15,  # two or more independent feeds
    "STALE_EVIDENCE": -30,  # past the type's TTL
    "UNKNOWN_AGE": -10,  # no timestamp to age against
    "SINGLE_COMMUNITY_SOURCE": -10,  # one community feed, alone
    "UNCLASSIFIED_SOURCE": -15,  # independence unknown
}

# Caps are the structural part of the policy. Keys are the situation, values the maximum
# score allowed in that situation.
DEFAULT_CAPS: dict[str, int] = {
    "stale": 49,  # T4: past TTL cannot be the top band
    "single_source": 69,  # T3: one community feed cannot be the top band
    "unknown_age": 69,  # freshness unknown cannot be the top band
    "unclassified_source": 39,  # independence unknown cannot exceed the bottom band
}


@dataclass(frozen=True)
class ScorePolicy:
    version: str = POLICY_VERSION
    weights: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    caps: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_CAPS))
    bands: tuple[tuple[str, int], ...] = field(default_factory=lambda: tuple(BAND_THRESHOLDS))

    def describe(self) -> dict[str, Any]:
        """Everything that can change a score. The config hash is taken over this."""
        return {
            "version": self.version,
            "weights": dict(sorted(self.weights.items())),
            "caps": dict(sorted(self.caps.items())),
            "bands": [list(item) for item in self.bands],
        }

    def band_for(self, score: int) -> str:
        for name, threshold in self.bands:
            if score >= threshold:
                return name
        return BAND_LOW


DEFAULT_POLICY = ScorePolicy()


def config_fingerprint(policy: ScorePolicy) -> str:
    """sha256 over the sorted policy description.

    Same contract as the rules engine: a weight edit is a new configuration, and a result
    that cannot name its configuration cannot be reproduced.
    """
    payload = json.dumps(policy.describe(), sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
