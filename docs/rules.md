# False-positive rules

The silver table is a list of claims. A rule turns one claim into a **verdict with a reason**:
did it fire, did it not, was it inapplicable, or was there not enough data to decide. Two
rules exist today — FP-04 (stale evidence) and FP-05 (single-source corroboration) — and both
run over the indicators already in silver, with no enrichment and no network access.

Rules do not score or rank. A rule answers "is this signal present?"; the scorer decides what
the signal is worth and lives separately in [`scoring.md`](scoring.md). Keeping the two apart
is what makes the ablation in [`methodology.md`](methodology.md) §8 possible: a rule that
cannot show a marginal effect when removed does not justify its complexity.

## The catalogue, frozen on 2026-11-23

This table is the single source of truth for rule ids. Before it existed, `docs/` cited
FP-01, 02, 03, 04, 05, 07, 08 and 10 in different places, which made it impossible to tell a
planned rule from an implemented one — and FP-06, FP-09 and FP-11 were cited nowhere at all.
A gap in the numbering is a gap, not a hidden rule.

| Id | Signal | Where it exists | State |
|---|---|---|---|
| FP-01 | RIOT membership (benign service) | prose only (`methodology.md` §7) | not implemented — needs enrichment |
| FP-02 | verified crawler via rDNS/CDN ranges | prose only (`methodology.md` §7) | not implemented — needs enrichment |
| FP-03 | the source's own false-positive list | prose only (`sources.md`, ThreatFox note) | not implemented — needs the hunting API |
| FP-04 | evidence past its type TTL | code (`fp_rules/aging.py`) + §2 below | **active** |
| FP-05 | single-source corroboration | code (`fp_rules/corroboration.py`) + §3 below | **active, defective** — counts feed names, not organizations |
| FP-06 | — | — | **never defined** in this repository |
| FP-07 | usage type (VPN / datacenter / residential) | one sentence in `sources.md` | not implemented — needs AbuseIPDB `usageType` |
| FP-08 | internet noise (mass scanning) | prose only (`methodology.md` §7) | not implemented — needs GreyNoise |
| FP-09 | — | — | **never defined** in this repository |
| FP-10 | KEV linkage | prose only; the `KEV_EXPLOITATION` weight was removed on 2026-11-23 | retired from the IOC track — see `decisions/0010` |
| FP-11 | Tranco popularity | — | **never defined** in this repository; a domain-popularity rule has been discussed, not specified |

Two consequences follow, and both are enforced rather than promised:

1. **A new rule ships with its row here in the same commit.** The `rules_config_hash` covers
   the `describe()` output of every implemented rule, so a rule that is not in this table but
   affects a verdict makes the published config unreproducible.
2. **An unimplemented rule is never cited as though it ran.** Docs say `not implemented`, the
   scoring table has no weight for it, and no evaluation claim rests on it. The current live
   run therefore has exactly two rules and one of them is known to be wrong in a way §3
   records.

**Why FP-05 is listed as defective rather than pending.** On the 2026-11-23 snapshot, 122
rows are `CORROBORATED` because a ThreatFox URL also appears in URLhaus. Both feeds are
operated by abuse.ch. It is one organization, not two, so the rule's own definition of
independence (`methodology.md` §5) says those rows are single-source. The fix counts
organizations, which requires a feed that is not abuse.ch — the reason it is scheduled after
the AbuseIPDB collector rather than before it.

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
| `cve` | none | A CVE is not an indicator and never reaches this table (`decisions/0010`). The branch stays so a misrouted row reports `not_applicable` instead of guessing an age |

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

**Known defect, recorded rather than exploited.** The rule counts *feed names*. It has no
model of the organization behind a feed, and every community name in the current source set
belongs to abuse.ch — ThreatFox and URLhaus, plus Feodo Tracker on the authoritative side. On
the 2026-11-23 snapshot, 122 of ThreatFox's 494 URLs also appear in URLhaus, so those rows
report `not_fired` / `CORROBORATED`. Under the definition of independence in
`methodology.md` §5 — different operators, neither a mirror of the other — that is one
organization, and the correct verdict is `fired`. The 122 rows are therefore a **false
corroboration**, and they are the entire `medium` band of the live run.

Consequences, stated so no reader has to infer them:

- The rule's discrimination on this snapshot is not evidence of quality; it is evidence of an
  under-specified input. `methodology.md` §8 still decides whether the weight survives.
- The fix is a `source_organizations` mapping and a count over organizations. It is not
  scheduled before a second, genuinely independent feed exists: with abuse.ch as the only
  community operator, the corrected rule would be `not_fired` nowhere and would carry no bit,
  which is itself the finding.
- Until then the live distribution is published as produced. Re-tuning the weights to hide
  it would remove the only visible symptom of the defect.

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

- **No calibration.** Rules give verdicts and the scorer turns them into points under a
  versioned policy; neither is a probability, and the evaluation does not claim one yet.
- **No `strong` strength.** The word is reserved until ablation earns it.
- **No quality metrics yet.** The fire rate in the example above is a description of one
  snapshot, not a precision estimate. Precision, recall and suppression cost require the
  labelled sample in `methodology.md` §4–§8 and are not claimed here.
- **No enrichment.** RIOT, rDNS, CDN ranges and GreyNoise (FP-01/02/08) need data the pipeline
  does not fetch yet.
