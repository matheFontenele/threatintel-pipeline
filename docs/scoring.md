# Scoring

The rules answer a factual question: *is this signal present?* Scoring answers a different
one: *how much should that signal move this indicator up the queue?* The split is deliberate
— a rule's value can only be measured by removing it and watching the score change
(`methodology.md` §8), and that argument needs the weights in one reviewable table rather
than scattered through rule code.

**What the number is not:** a probability. A score of 70 means *70 points under policy
`2026-11-23`*, not *70% likely malicious*. No calibration has been done, and the output is
versioned precisely so that nobody can mistake one interpretation for the other.

## 1. The policy

Everything that can change a score is in `src/threatintel/scoring/policy.py`:
`POLICY_VERSION`, the weight table, the caps, and the band thresholds. The report carries a
`policy_config_hash`, a sha256 over the sorted description of that policy. Editing a weight
is therefore a **new configuration**, not a silent reinterpretation of earlier output — the
same contract the rules engine already uses.

## 2. Weights

Scores start from the strongest claim the indicator carries, then take one adjustment per
signal. Sign is the part that is argued; magnitude is the part that awaits calibration and
is labelled as provisional in the code.

| Code | Weight | Meaning |
|---|---|---|
| `SRC_AUTHORITATIVE` | +60 | A curated catalogue or C2 blocklist (`cisa_kev`, `feodo`) |
| `SRC_COMMUNITY` | +45 | A collaborative feed — a claim, not a finding (`threatfox`, `urlhaus`) |
| `SRC_UNCLASSIFIED` | +30 | A feed nobody has classified; independence unknown |
| `KEV_EXPLOITATION` | +10 | The indicator is a CVE in the KEV catalogue |
| `FRESH_AUTHORITATIVE` | +10 | Inside its TTL *and* curated — the strongest combination |
| `CORROBORATED` | +15 | Two or more independent sources agree |
| `STALE_EVIDENCE` | -30 | Past the type's TTL (`FP-04_STALE` fired) |
| `UNKNOWN_AGE` | -10 | No timestamp to age against (`insufficient_data`) |
| `SINGLE_COMMUNITY_SOURCE` | -10 | One community feed, alone (`FP-05` fired) |
| `UNCLASSIFIED_SOURCE` | -15 | Source independence unknown (`insufficient_data`) |

Notes on the signs:

- **A curated source alone is not penalised.** FP-05 returns `not_applicable` for Feodo and
  KEV, and the scorer follows that verdict rather than inventing a second opinion.
- **Missing data is not clean data.** The rules distinguish `not_fired` from
  `insufficient_data`; the scorer does too, with `UNKNOWN_AGE` / `UNCLASSIFIED_SOURCE`
  instead of the positive terms.
- **A rule that did not run contributes nothing.** A partial rule set is scorable, and the
  absence of a reason code is visible in the output; the scorer never pretends a missing
  rule passed.

The score is the sum of the reasons, clamped to `0..100`, then capped by §4.

## 3. Bands

| Band | Threshold in the default policy | Reading |
|---|---|---|
| `high` | ≥ 70 | Look at this now |
| `medium` | ≥ 40 | Worth a review when capacity allows |
| `low` | < 40 | Keep for context; do not page anyone |

The band is a rendering of the policy, not a separate judgement: change a threshold and the
`policy_config_hash` changes with it.

## 4. Caps are guarantees, not arithmetic

Some situations cannot reach the top band **regardless of the weights**. These encode threats
T3 and T4 of the threat model as invariants rather than as sums a future edit might quietly
undo:

| Situation | Cap | Why |
|---|---|---|
| `stale` | 49 | T4: evidence past its TTL cannot be the top priority, however curated its source |
| `single_source` | 69 | T3: one community feed is a claim, not a consensus |
| `unknown_age` | 69 | Freshness unknown cannot be the top priority |
| `unclassified_source` | 39 | Independence unknown cannot leave the bottom band |

The result lists the caps that actually bound it (`score_caps`). An empty tuple means the
arithmetic stayed under every ceiling — it does **not** mean the indicator was fresh and
corroborated; that is what the reason codes are for.

Notice that a cap is a ceiling, not a subtraction: a stale indicator with a very strong base
lands at 49 (medium, never high) rather than at "70 minus something". The point is the
guarantee, not the arithmetic.

## 5. Worked examples

All values below are documentation ranges (RFC 5737 / RFC 2606); none is a real indicator.
Clock: `2026-11-23T12:00:00Z`.

| Indicator | Rule verdicts | Score | Band |
|---|---|---|---|
| `CVE-2024-1234`, KEV | FP-04 n/a (CVE is not aged), FP-05 n/a (authoritative alone) | 60 + 10 = **70** | high |
| `203.0.113.10`, Feodo, seen yesterday | FP-04 not fired, FP-05 n/a | 60 + 10 = **70** | high |
| `203.0.113.10`, Feodo, seen 40 days ago | FP-04 fired, FP-05 n/a | 60 − 30 = **30** | low |
| `203.0.113.10`, Feodo, no timestamps | FP-04 insufficient, FP-05 n/a | 60 − 10 = **50**, `needs_review` | medium |
| `http://example.com/a`, ThreatFox, fresh | FP-04 not fired, FP-05 fired | 45 − 10 = **35** | low |
| `http://example.com/a`, ThreatFox + URLhaus | FP-04 not fired, FP-05 not fired | 45 + 15 = **60** | medium |
| `203.0.113.10`, unclassified feed, fresh | FP-04 not fired, FP-05 insufficient | 30 − 15 = **15**, `needs_review` | low |

`needs_review` is set when any rule returned `insufficient_data`. It is a routing signal —
"a human should look at the missing fact" — not a verdict about the indicator.

## 6. Output: the gold table

Scoring reads silver and writes `data/gold/indicators.parquet` (gitignored, like all data).
The table is silver plus the score columns: `score`, `band`, `needs_review`,
`score_reasons_json`, `score_caps`, `policy_version`, `policy_config_hash`, and the run
metadata `as_of` and `rules_config_hash`. Reasons are JSON so DuckDB and the API can read the
table without the project's models. The hashes and clock are stored per row, so a row copied
out of the table can still name the run that produced it. A table whose rows disagree about
the run is rejected on read.

Rows are sorted by descending score, then type and value, so a consumer that truncates the
scan gets the top of the queue first. The CLI summary printed to stdout carries counts only:
bands, `needs_review`, and reason-code distribution. Like the rules report, it never carries
an indicator value, so it is publishable under `decisions/0007`.

The gold table is **derived output**. If silver changes, gold is stale; there is no
incremental invalidation in Phase 1 by design, because a full rescore of ~10^5 rows takes
seconds and a half-updated score table is worse than a stale one.

## 7. Reproducing a score set

```bash
make gold AS_OF=2026-11-23T12:00:00Z
# equivalent to:
python -m threatintel.scoring \
  --silver data/silver/indicators.parquet \
  --out data/gold/indicators.parquet \
  --as-of 2026-11-23T12:00:00Z --json
```

A published number needs `(snapshot, as_of, policy_config_hash, rules_config_hash)`. The
summary carries the last three; the snapshot is the silver file the run read. Omitting
`--as-of` uses the current clock and is convenient but not reproducible.

## 8. Known limits

- **Weights are uncalibrated.** The magnitudes are hypotheses. Bands separate the queue; they
  do not estimate a base rate, and no precision/recall claim is attached to them until the
  labelled evaluation in `methodology.md` §4–§9 exists.
- **Scores are not comparable across policy versions.** A 70 under one weight table is not a
  70 under another; the hash is the only valid comparison key.
- **The base term dominates.** With no enrichment (FP-01/02/08 absent), an indicator's score
  is mostly its source class and age. That is honest for the current data, and the reason
  codes make the imbalance visible rather than hiding it.
- **Caps can mask a strong signal.** A corroborated indicator with an unknown timestamp still
  cannot be `high`. The cap is reported so a reviewer can disagree with the policy knowingly.
- **`needs_review` is not a label.** It says a fact is missing, not that the indicator is
  suspicious.
- **No `strong` rule strength.** The word is still reserved until the ablation earns it, so
  no rule currently contributes a `strong`-class weight.
