"""The rule contract: a rule states what it looked at, whether it fired, and how strongly.

Three design choices are deliberate:

- **Rules are pure.** `evaluate(indicator, as_of=...)` reads the indicator and a fixed clock,
  never `datetime.now()`. An evaluation re-run months later must reproduce the same reason
  codes, otherwise the published metrics cannot be attached to a snapshot.
- **Rules distinguish "did not fire" from "could not decide".** An indicator with no
  timestamp is not fresh; it is unknown. Collapsing the two would quietly turn missing data
  into a clean bill of health.
- **Strength is an enum, not a float.** A number like `0.37` implies a calibration nobody
  has done yet. `strong` / `moderate` / `weak` says what is actually known, and the scorer
  maps it to a weight in one reviewable place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from threatintel.normalize.schema import Indicator


class RuleStatus(StrEnum):
    FIRED = "fired"
    NOT_FIRED = "not_fired"
    NOT_APPLICABLE = "not_applicable"
    INSUFFICIENT_DATA = "insufficient_data"


class Strength(StrEnum):
    """How much the finding says about false-positive risk.

    No rule may return `strong` yet: that claim requires the ablation table in
    `docs/methodology.md` §8 to show high suppression precision. Until then, `strong` is a
    reserved word.
    """

    MODERATE = "moderate"
    WEAK = "weak"


@dataclass(frozen=True)
class Finding:
    """One rule's verdict on one indicator. Never carries the indicator's value."""

    code: str
    indicator_id: str
    status: RuleStatus
    strength: Strength | None = None
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


class Rule(Protocol):
    code: str

    def evaluate(self, indicator: Indicator, *, as_of: datetime) -> list[Finding]:
        """Return findings for this indicator. One code per rule is the current norm."""
        ...

    def describe(self) -> dict[str, Any]:
        """Parameters that affect behaviour, for the config fingerprint."""
        ...
