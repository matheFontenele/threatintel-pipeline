"""Explainable scoring: turn rule findings into a ranked, reproducible number.

The scorer consumes the findings produced by `threatintel.fp_rules` and adds one term per
signal, each of which appears in the output as `(code, weight, detail)`. The score is
therefore challengeable line by line: every point can be traced to a documented weight and
a rule verdict.

Two constraints are part of the public contract:

- **The number is not a probability.** It is points under a versioned policy; no
  calibration has been claimed (see `docs/methodology.md` §8-9).
- **Caps are guarantees, not arithmetic.** Some situations cannot reach the top band
  regardless of the weights, and the result says which cap bound it.

Results never carry an indicator value in their summaries, so a scoring report is
publishable under the same boundary as the rules report (`docs/decisions/0007`).
"""

from threatintel.scoring.engine import (
    Reason,
    Score,
    ScoredIndicator,
    ScoringReport,
    Tracks,
    VulnRow,
    build_tracks,
    evaluate_and_score,
    parse_as_of,
    score_all,
    score_indicator,
    split_tracks,
)
from threatintel.scoring.gold import (
    GOLD_SCHEMA,
    VULN_SCHEMA,
    GoldTable,
    VulnTable,
    read_gold,
    read_vulnerabilities,
    write_gold,
    write_vulnerabilities,
)
from threatintel.scoring.policy import (
    BAND_HIGH,
    BAND_LOW,
    BAND_MEDIUM,
    BAND_THRESHOLDS,
    DEFAULT_CAPS,
    DEFAULT_POLICY,
    DEFAULT_WEIGHTS,
    POLICY_VERSION,
    ScorePolicy,
    config_fingerprint,
)

__all__ = [
    "BAND_HIGH",
    "BAND_LOW",
    "BAND_MEDIUM",
    "BAND_THRESHOLDS",
    "DEFAULT_CAPS",
    "DEFAULT_POLICY",
    "DEFAULT_WEIGHTS",
    "GOLD_SCHEMA",
    "GoldTable",
    "POLICY_VERSION",
    "Reason",
    "Score",
    "ScorePolicy",
    "ScoredIndicator",
    "ScoringReport",
    "Tracks",
    "VULN_SCHEMA",
    "VulnRow",
    "VulnTable",
    "build_tracks",
    "config_fingerprint",
    "evaluate_and_score",
    "parse_as_of",
    "read_gold",
    "read_vulnerabilities",
    "score_all",
    "score_indicator",
    "split_tracks",
    "write_gold",
    "write_vulnerabilities",
]
