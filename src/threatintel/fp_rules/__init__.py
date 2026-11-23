"""Explainable false-positive rules over silver indicators.

Each rule reports a status per indicator (fired / not fired / not applicable /
insufficient data) and, when it fires, a coarse strength. The engine collects the findings,
recomputes `fp_reasons`, and emits a report that is reproducible from
`(snapshot, as_of, config_hash)` without ever carrying an indicator value.
"""

from threatintel.fp_rules.aging import DEFAULT_TTL_DAYS, POLICY_VERSION, AgingRule
from threatintel.fp_rules.base import Finding, Rule, RuleStatus, Strength
from threatintel.fp_rules.corroboration import CorroborationRule
from threatintel.fp_rules.engine import (
    DEFAULT_RULES,
    RulesReport,
    config_fingerprint,
    evaluate,
)

__all__ = [
    "DEFAULT_RULES",
    "DEFAULT_TTL_DAYS",
    "POLICY_VERSION",
    "AgingRule",
    "CorroborationRule",
    "Finding",
    "Rule",
    "RuleStatus",
    "RulesReport",
    "Strength",
    "config_fingerprint",
    "evaluate",
]
