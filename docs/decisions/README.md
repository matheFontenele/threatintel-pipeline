# Decision records

Short records of decisions that are expensive to reverse, or that a reader would
otherwise have to guess. One file per decision, sequential numbering, never deleted —
a reversed decision is *superseded*, not erased.

| # | Decision | Status |
|---|---|---|
| [0001](0001-decision-record-format.md) | Decision record format | accepted |
| [0002](0002-scope-detection-and-threat-intel.md) | Scope: detection/threat-intel as the primary track | accepted |
| [0003](0003-storage-duckdb-parquet.md) | Storage: DuckDB + Parquet, reviews in a separate file | accepted |
| [0004](0004-license-mit.md) | License: MIT | accepted, reversible |
| [0005](0005-python-package-layout.md) | Python package layout under `src/threatintel/` | accepted |
| [0006](0006-indicator-identity.md) | Indicator identity, normalization and merge | accepted |
| [0007](0007-publication-boundary.md) | Publication boundary: code and metrics public, feed data not | accepted |
| [0008](0008-scoring-policy.md) | Scoring: integer points, versioned policy, structural caps | accepted |
| [0009](0009-read-api-boundary.md) | Read API: one pinned run, keyset pages, no auth in Phase 1 | accepted |
| [0010](0010-indicator-and-vulnerability-tracks.md) | Separate indicator and vulnerability tracks; catalogue is facts, not a score | accepted |

## When a record is required

Write one when the decision:

- changes what the project *is* (scope, audience, licence);
- constrains future code in a way a reader cannot infer from the code itself (storage
  engine, schema contract, trust boundary);
- is made under uncertainty and will be revisited (weights, sources, quotas).

Not required for: naming, formatting, library choice inside an already-bounded scope.

## Template

```markdown
# NNNN — Title

- Status: proposed | accepted | superseded by NNNN
- Date: YYYY-MM-DD
- Supersedes: —

## Context
What forced a decision. Include the constraint, not just the wish.

## Decision
One sentence, then the specifics.

## Consequences
### Positive
### Negative
### Neutral / accepted cost

## Revisit if
The observable condition that should reopen this.
```

A record with no "revisit if" is a record that claims certainty it does not have.
