# 0008 — Scoring: integer points under a versioned policy, with structural caps

- Status: accepted
- Date: 2026-11-23
- Supersedes: —

## Context

The rules (`docs/rules.md`) produce verdicts, not a ranking. A consumer of the API needs a
short ordered list, and the project's premise is that the ordering is explainable. Three
shapes were available:

1. **A probability** — logistic regression or a tuned weighted sum normalised to `0..1`.
2. **A learned ranker** — a model trained on the labelled sample, with feature attributions.
3. **Integer points** — one documented weight per signal, a hard cap for a few situations,
   and named bands.

The labelled sample that a learned ranker needs does not exist yet; it is Week 2 work
(`methodology.md` §4–§9). A probability without calibration would be a number that looks
like a measurement and is not. That is the failure mode this project exists to avoid.

There is also a security requirement that a pure arithmetic sum does not satisfy on its own:
a single community feed flooding reports must not be able to push an indicator into the top
band, and stale evidence must not be the thing a consumer pages on. Threat model T3 and T4
state those as properties of the output, not as hopes about the weights.

## Decision

1. **Score = integer points.** Base by source class (authoritative 60, community 45,
   unclassified 30), plus one signed adjustment per rule verdict, clamped to `0..100`. The
   output never claims to be a probability, and `docs/scoring.md` says so in the first
   paragraph.
2. **Structural caps, applied after the sum.** `stale` ≤ 49, `single_source` ≤ 69,
   `unknown_age` ≤ 69, `unclassified_source` ≤ 39. These bound the result regardless of the
   weight table, so tuning cannot silently remove the guarantee. The result reports which
   caps bound it.
3. **Every point is a named reason.** Each contribution appears as `(code, weight, detail)`,
   and a test asserts the score equals the sum of its own reasons whenever no cap binds.
4. **The policy is versioned and hashed.** `POLICY_VERSION` plus a sha256 over the sorted
   policy description (`policy_config_hash`). A weight edit is a new configuration; scores
   from different hashes are not comparable.
5. **`needs_review` comes from the rules, not from the score.** It is set when a rule returns
   `insufficient_data`, because that is a missing fact a human can supply. A low score is
   not a review request.
6. **Gold is derived and full-rebuild.** `data/gold/indicators.parquet` is rewritten from
   silver on every scoring run. No incremental update in Phase 1.

## Alternatives rejected

- **Normalised probability.** Rejected until calibration exists: an uncalibrated `0.83`
  invites a threshold decision the project cannot defend.
- **Learned ranker now.** Rejected: training on the same hand-labelled set used for
  evaluation is the circularity §7 of the methodology forbids. A learned ranker can be
  added later as a *scored alternative* compared against this policy, not as the policy
  itself.
- **Weights without caps.** Rejected: it makes T3/T4 a property of the current numbers
  rather than of the system. A future tuning pass would remove the guarantee without anyone
  noticing.
- **Floating-point weights.** Rejected: they suggest precision the underlying judgements do
  not have, and they make the sum harder to check by hand. Integers are auditable; the reason
  codes carry the explanation either way.

## Consequences

### Positive

- The number can be challenged line by line, including by someone who disagrees with a
  weight: the table is one file, and the output cites the exact term.
- Caps make two threat-model properties testable. `test_a_cap_binds_when_arithmetic_would_beat_it`
  and its siblings fail if a tuning pass removes the guarantee.
- The scorer is a pure function of `(indicator, findings, policy)`, so it inherits the rules'
  reproducibility and is cheap to test.

### Negative

- The weights are provisional and the bands are a queue-sorting device, not a measurement.
  Published metrics must not use band membership as a prediction.
- Integer granularity means near-boundary cases (69 vs 70) can flip on a single weight edit;
  the policy hash is what makes such a change visible.
- The base term dominates while enrichment is absent, so the ranking is closer to "source
  class and age" than to a rich risk model. The reason distribution is published to make
  that visible.

### Accepted cost

A less impressive-looking score in exchange for one that is honest about being uncalibrated.
The evaluation in Week 2 measures the rules' effect on the score (`methodology.md` §8); it
does not retroactively turn the points into a probability.

## Revisit if

- the labelled sample is large enough to calibrate, in which case a probability can be added
  as a second output and compared against the points — this record is superseded, not edited;
- an ablation shows a weight's marginal contribution is indistinguishable from zero, in
  which case the weight is removed or set to zero and `POLICY_VERSION` changes;
- enrichment (FP-01/02/08) lands and the base term stops dominating, which is a reason to
  re-tune magnitudes, not to drop the caps.
