# False-positive rules

The silver table is a list of claims. A rule turns one claim into a **verdict with a reason**:
did it fire, did it not, was it inapplicable, or was there not enough data to decide. Two
rules exist today — FP-04 (stale evidence) and FP-05 (single-source corroboration) — and both
run over the indicators already in silver, with no enrichment and no network access.

Nothing here scores or ranks yet. A rule answers "is this signal present?"; the scorer will
later decide what the signal is worth. Keeping the two apart is what makes the ablation in
[`methodology.md`](methodology.md) §8 possible: a rule that cannot show a marginal effect when
removed does not justify its complexity.

## 1. The rule contract

Every finding has a status, never a boolean:

| Status | Meaning |
|---|---|
| `fired` | The signal is present and the rule draws its conclusion |
| `not_fired` | Enough data, signal absent |
| `not_applicable` | The rule does not apply to this type or source by design |
| `insufficient_data` | The rule needed a fact the indicator does not carry |

`not_fired` and `insufficient_data` are deliberately separate. An indicator with no
timestamp is not fresh; it is unknown. Collapsing the two would quietly turn missing data
into a clean bill of health, which is the failure mode most FP filters have.

When a rule fires it also reports a **strength**, an enum rather than a float:

| Strength | Meaning |
|---|---|
| `strong` | Reserved. No rule may return it until the ablation shows high suppression precision |
| `moderate` | The signal is a direct fact about the indicator (e.g. its age) |
| `weak` | The signal is circumstantial (e.g. only one community feed reports it) |

A number like `0.37` would imply a calibration nobody has done. The scorer maps these three
words to weights in one reviewable place.

Rules are **pure**: `evaluate(indicator, *, as_of=...)` never calls `datetime.now()`. The
evaluation clock is an argument, so re-running a report months later reproduces the same
verdicts. A finding carries the indicator **id**, never its value, which is what allows the
report to be published for restricted feeds (see `decisions/0007`).

## 2. FP-04 — stale evidence (`FP-04_STALE`)

A public feed says "this was malicious", present tense, forever. An IP reported in March is
often a residential address by June. The rule ages each indicator against a per-type TTL:

| Type | TTL | Why this number |
|---|---|---|
| `ip` | 30 days | Address reassignment is routine; botnet infrastructure moves or dies quickly |
| `domain` | 180 days | Matches the six-month window ThreatFox still serves, the only range where "stale" is measurable inside its own retention |
| `url` | 30 days | A path stops resolving or starts serving something else fast |
| `hash` | 365 days | A file hash never becomes benign, it becomes irrelevant; one year is the most generous defensible bound |
| `cve` | none | KEV catalogues *exploitation*, not a decaying indicator. Aging it would delete the only non-IP type the pipeline has |

TTLs are a versioned **policy** (`POLICY_VERSION`), not scattered constants: changing one
changes every score, so it changes the report's `config_hash`.

The reference date is `last_seen` when present, else `first_seen`, else the rule reports
`insufficient_data`. Boundaries are explicit:

- an indicator **exactly at** its TTL does not fire — the boundary day is not yet stale;
- a timestamp **in the future** does not fire, but the finding says so and records a negative
  age, because that is bad data and should be visible rather than silently treated as fresh;
- a **date-only** timestamp (Feodo's live `last_online` shape) is treated as midnight UTC, so
  its age can be up to one day conservative — never optimistic.

**Why this rule is not theoretical.** On the 2026-11-23 live Feodo snapshot, all five listed
C2 hosts carried a `last_online` between February and March 2026 — roughly eight months before
collection, despite four of them being marked `offline` and one `online`. The feed's status
flag and its own timestamp disagree; the rule trusts the timestamp. FP-04 fires on all five.
That is the honest verdict for that snapshot, not a rule-quality claim: a five-row sample
whose rows are all old says nothing about how often the rule is right. Ablation on the
labelled set is the gate for that.

## 3. FP-05 — single source (`FP-05_SINGLE_SOURCE`)

The echo problem: one submission gets relayed into several "sources", and a scorer that
counts feed rows reads the relay as agreement. The fix is to count **independent feeds**, and
this rule is what makes the count operational. Sources are classified explicitly:

| Class | Sources | Alone means |
|---|---|---|
| Authoritative | `cisa_kev`, `feodo` | `not_applicable` — these publish confirmed exploitation / currently listed C2s; being alone is not suspicious |
| Community | `threatfox`, `urlhaus` | `fired` (`weak`) — a single submitter is a claim, not corroboration |
| Unclassified | anything else | `insufficient_data` — a new feed must be classified deliberately, not inherit a default |

Outcomes are mechanical:

- two or more classified feeds → `not_fired`, with the source names in the evidence;
- one authoritative feed → `not_applicable`;
- one community feed → `fired`, `weak`, with `distinct_reporters = 1`;
- no sources, or an unclassified source → `insufficient_data`.

CVE is out of scope: corroborating a vulnerability is a question about advisories, not about
feeds, and the rule reports `not_applicable` rather than pretending the feed count means
something.

**Known limitation, recorded so it is not discovered later.** Most of the current volume still
comes from one community feed, so for those rows the rule is close to "the indicator came from
ThreatFox". It stays `weak` on that basis. The 2026-11-23 snapshot is the first one where the
rule is not a restatement: 122 of ThreatFox's 494 URLs also appear in URLhaus, and those rows
move from `fired` to `not_fired`. That is a discrimination, not a quality metric — 122 shared
URLs prove the counting works, not that single-source indicators are usually false positives.
`methodology.md` §8 is still what must justify the weight.

## 4. When the rules disagree

FP-04 and FP-05 are independent and can point in opposite directions on one indicator: an
authoritative source can be stale (`not_applicable` for corroboration, `fired` for aging), and
a fresh indicator can be weakly corroborated (`not_fired` for aging, `fired` for
corroboration). The engine reports both findings and does not resolve the conflict. Resolving
it is a scoring decision, and hiding it inside a rule would make the conflict unauditable.

## 5. How `fp_reasons` is maintained

The engine **recomputes** `fp_reasons` instead of appending to it:

- a code owned by a rule in this run is replaced by whatever that rule says now, so a rule fix
  actually clears its stale annotations;
- a code owned by a rule that was **not** part of this run is preserved, so a partial run
  cannot clobber another rule's work;
- codes from outside this rule set are preserved untouched.

The result is idempotent: evaluating already-annotated rows again yields the same reasons.

## 6. Reproducing a report

```bash
make rules
# equivalent to:
python -m threatintel.fp_rules --silver data/silver/indicators.parquet --json
```

Every report carries three things that make a number meaningful (`methodology.md`, opening
rule): the **snapshot** it was read from, the **`as_of`** clock, and the **`config_hash`** —
a sha256 over the sorted rule descriptions, so any TTL or classification change produces a
new hash instead of silently reinterpreting old results.

The report contains indicator **ids and counts only**: no values, no timestamps per row.
`--write-annotated PATH` writes the recomputed `fp_reasons` to a separate Parquet file, so the
silver snapshot under evaluation is never mutated in place.

`--as-of` accepts an ISO 8601 datetime; a bare date means midnight UTC, a declared convention
rather than a local-time guess. Omitting it uses the current time, which is convenient and
not reproducible — publish the explicit value instead.

## 7. What is deliberately absent

- **No scoring.** Rules give verdicts; weights come later and are tuned on calibration data.
- **No `strong` strength.** The word is reserved until ablation earns it.
- **No quality metrics yet.** The fire rate in the example above is a description of one
  snapshot, not a precision estimate. Precision, recall and suppression cost require the
  labelled sample in `methodology.md` §4–§8 and are not claimed here.
- **No enrichment.** RIOT, rDNS, CDN ranges and GreyNoise (FP-01/02/08) need data the pipeline
  does not fetch yet.
