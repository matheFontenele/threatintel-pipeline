# Evaluation methodology

This is the part of the project that has to survive scrutiny. Everything else is
plumbing; this file states what is measured, how, and where the measurement is weak.

The rule for reading the rest: **no number in this repository is meaningful without the
snapshot id, the config hash and the label set it was produced from.** All three are
published with every result.

## 1. The problem with ground truth

A public feed can tell you "this IP was reported as abusive". It cannot tell you whether
that matters. Three separate questions get conflated in feed data:

| Question | Who can answer it |
|---|---|
| Is the reported behaviour real? | Corroboration, and a human looking at evidence |
| Is the target a benign service that happens to be reported? | Service ownership, verified from the operator's own published data |
| Does a defender need to act on it? | Context — which this project does not have for any real environment |

The project scores the *third* question (priority), uses the first two as inputs, and
must therefore be explicit that priority is a **modelled judgement**, not a fact.

## 2. Unit of evaluation

One row is one **indicator at a snapshot**: `(type, value, snapshot_id)`. Not a feed
row — the same IP in four feeds is one evaluation item. Indicators are time-dependent:
an IP can be malicious in March and reassigned to a residential customer in June. Every
evaluation is therefore run against a frozen snapshot and labels are dated.

## 3. Label taxonomy

Each sampled indicator gets exactly one label:

| Label | Definition | Counts as |
|---|---|---|
| `malicious` | Reported behaviour is corroborated by an independent source **and** the indicator is inside its TTL window for that behaviour | positive — should be acted on |
| `benign` | Infrastructure of a known-benign service, verified from the operator's published ranges or from forward+reverse DNS agreeing on ownership | negative |
| `noise` | Real activity that is not directed at anyone in particular (mass scanning, generic botnet background) | negative — act on it and you drown |
| `unclear` | Evidence insufficient, or sources contradict each other without a way to adjudicate | excluded from precision/recall; counted as `needs_review` |

`unclear` is not a failure of the protocol, it is a result. The share of `unclear` items
is a published metric: a system that sends 60% of its input to review has not solved the
problem, it has moved it.

**Why `noise` is separate from `malicious`.** Collapsing them would make the filter look
either brilliant or useless depending on threshold, because most of a public feed *is*
malicious-but-irrelevant. Keeping them apart is what lets the report say "we removed 71%
of the volume and lost 4 points of recall on what matters".

### 3.1 Two taxonomies, one mapping

Four labels are needed to label honestly; three are needed to report honestly. The report
publishes three headline labels and the mapping, because a reader wants to know whether the
system is wrong, not how it is wrong:

| Internal label | Headline label | In the denominator |
|---|---|---|
| `malicious` | `threat` | yes |
| `benign` | `false_positive_or_collateral` | yes |
| `noise` | `false_positive_or_collateral` | yes |
| `unclear` | `unverifiable` | **no** |

`unverifiable` is excluded from the denominator, not counted as either outcome. A system that
cannot decide has not answered the question, and silently scoring it as a false positive (or
as a true positive) would invent evidence.

The mapping is lossy on purpose and the loss is reported: `noise` and `benign` collapse into
one headline number, so a rule that suppresses scanners and a rule that suppresses a
compromised legitimate site look equally good at headline level. That is why the per-rule
ablation in §8 is broken down by internal label — the 2×2 headline table is the summary, not
the evidence.

**Naming.** The operator's review workflow names the three headline labels in Portuguese
(`ameaça`, `fp_ou_colateral`, `não_verificável`); this document and any published report use
the English names above. They are the same three rows, so a label file does not have to be
rewritten to be counted.

## 4. Sampling

Stratified by `(source, type, band, rule state)`, with a floor per cell, seeded, drawn from
the snapshot under evaluation. Stratifying by band and rule state — not only by source and
type — is what makes an ablation possible at all: the cells a rule touches must be populated.

### 4.1 How many items, and what they can support

The honest arithmetic first, because it constrains what the report may claim:

- a 60/40 split at 300 items leaves ~120 test items;
- if corroborated or stale items are 1–2% of the population and are oversampled to ~15% of
  the sample, a test cell has roughly 15–20 items;
- a Wilson 95% interval at n = 40 and p = 0.9 is about **±9 percentage points**.

So:

- **200–300 items** support the three headline numbers and **3–4 pre-declared aggregates**,
  each reported with its interval. Nothing finer. A per-rule × per-type table at that size is
  noise dressed as precision.
- **400–600 items** are required before a per-rule or per-cell claim is published, and even
  then only with intervals and exact denominators.
- Below ~150 the report publishes the protocol and the interval width, and states that the
  sample does not support a precision claim. It does not publish a point estimate.

The choice is made **before** the test set is touched, and it is written into the report
header. Deciding the sample size after seeing which cells look interesting is the same
practice as tuning on the test set.

### 4.2 Post-stratification weights are mandatory

Oversampling hard cases makes the sample unrepresentative by construction. Without weights,
the sample precision estimates the precision *of the sample*, which is not the precision of
the system — and a report that does not say so is wrong.

Each item carries `w = N_cell / n_cell` from the snapshot population. The headline precision,
recall and share-of-review are weighted sums with those weights; intervals come from a
stratified bootstrap or a design-effect-adjusted Wilson, and the method is named. Unweighted
per-stratum rates are also published, clearly labelled as per-stratum, because they are what
the ablation reads.

A stratum present in the sample but absent from the population (or the reverse) is a sampling
bug, and the script fails rather than inventing a weight. The weights, the population counts
per cell and the seed are part of the published artifact.

Deliberate oversampling of the hard cases, because a set dominated by obvious malware
measures nothing:

- indicators that only one source reports (the echo problem, FP-05);
- indicators whose source score is high but whose tags suggest scanning (FP-08);
- indicators inside large cloud/CDN ranges (FP-02).

Catalogue entries are **not** in this sample. They are published as facts in the
vulnerability track and are not scored, so there is no indicator verdict to evaluate
(`decisions/0010`).

The sampling script records the seed and the exact snapshot id. Sampling is regenerated
with `eval/sample.py` (Week 5); the label set is versioned in the repository.

## 5. Labeling protocol

For each item the labeler writes: the label, the evidence consulted, and a one-line
justification. A label without recorded evidence is not a label — it cannot be defended
later, by the author or by a reader.

Decision order, applied mechanically so that labels do not drift:

1. Does the indicator belong to a verified benign service (ownership confirmed by the
   service's own published ranges, or forward and reverse DNS agreeing)? → `benign`.
2. Is the reported behaviour corroborated by at least one **independent** source, and
   still within TTL? → `malicious`.
3. Is the activity real but undirected (mass scan, generic botnet sweep)? → `noise`.
4. Otherwise → `unclear`.

Independence is defined, not assumed: two feeds are independent if they have different
operators and neither is documented as a mirror/relay of the other. A single submitter
appearing in three feeds is one source.

The organization is the unit, and that is not a theoretical distinction here. abuse.ch
operates ThreatFox, URLhaus and Feodo Tracker, so an indicator appearing in two of them is
reported by one organization. The 2026-11-23 snapshot has 122 such URLs; the rule counts feed
names and calls them corroborated, which the definition above says is wrong. This is recorded
in `rules.md` §3 as an active defect, not resolved by relabelling the evidence.

## 6. Split, and touching the test set once

- 60% calibration, 40% test, stratified, seeded.
- Weights, thresholds and class boundaries are tuned **only** on calibration.
- The test set is evaluated once per released configuration. If the configuration
  changes after a test run, the report states that a second test run occurred and why.
  Hiding a test run is the single easiest way to lie in this project, so the log of test
  runs is append-only and published.

## 7. Circularity: the rule that makes the numbers mean something

If a rule filters on signal *S*, then `S` cannot also be the ground truth for evaluating
that rule. Otherwise the rule scores perfectly by construction. Concretely:

| Rule | Consumes | Therefore cannot be validated by |
|---|---|---|
| FP-01 RIOT membership | RIOT | "is in RIOT" as a label |
| FP-02 verified crawler | rDNS/CDN ranges | rDNS agreement alone |
| FP-03 source FP list | the source's own FP list | that list |
| FP-04 stale evidence | `first_seen` / `last_seen` | "looks old" as a label |
| FP-05 single source | independent organization count | "reported by two feeds" as a label |
| FP-08 internet noise | GreyNoise noise classification | GreyNoise classification |

FP-10 (KEV linkage) is not in this table any more: it left the indicator track with
`decisions/0010`, and the catalogue is published as facts, so there is no rule whose input
could leak into its own evaluation.

So:

1. **Labels come from the human protocol in §5**, using evidence outside the rule's own
   signal. For the FP-01 stratum, that means checking who actually owns the range.
2. **Reference sets are candidates, not labels.** "Reported by two independent sources"
   and "listed in RIOT" generate *sampling candidates*; a human assigns the final label.
3. **Ablation is mandatory.** A rule that cannot show a marginal effect when removed is
   a rule that does not justify its complexity, and it is reported as such.

## 8. Ablation

For each rule, run the full system and the system with that rule disabled, on the
calibration set. Publish:

| Quantity | Meaning |
|---|---|
| Rule fire rate | share of items the rule touches |
| Suppression precision | of items the rule down-ranks, share labeled `benign`/`noise` (benefit) |
| Suppression cost | of items the rule down-ranks, share labeled `malicious` (harm) |
| Δ recall | recall lost by removing the rule |
| Δ review share | change in volume routed to human review |

A rule whose suppression precision is no better than the base rate among the items it
touches is not filtering, it is guessing — and the report says so.

## 9. Metrics

Evaluated on items the system classifies as actionable (i.e. not routed to
`needs_review`), using the three headline labels of §3.1 and the post-stratification
weights of §4.2:

```
precision = TP / (TP + FP)
recall    = TP / (TP + FN)      FN includes malicious items routed to needs_review
FPR       = FP / (FP + TN)      among reference negatives (benign + noise)
review    = |needs_review| / N
```

Every term is a weighted count. `unverifiable` items are excluded from `N` and from all four
metrics, and their share is reported separately — that share is the honest cost of not
answering, not a rounding error.

Plus:

- **review share** and, within it, the share that turns out `malicious` — the review
  queue exists to catch what the filter cannot decide, so its yield matters;
- **per-rule table** from §8;
- **runtime** for a full snapshot (seconds; it is a batch job, not a benchmark);
- **exact denominators** (unweighted, alongside the weighted estimates), printed, so a reader
  can recompute by hand.

With an effective sample in the low hundreds, point estimates are reported with **95% Wilson
intervals**, design-adjusted when weights are applied. A precision of 0.91 on 34 actionable
items is `[0.77, 0.97]`, and the report writes it that way rather than pretending the third
digit exists. If the interval is wider than the claim it is meant to support, the claim is
withdrawn, not softened.

## 10. Reporting rules

Published with every result: snapshot id, config hash (weights + thresholds + rule
version), label-set version, confusion matrix, all four metrics with intervals, the
per-rule ablation table, and **at least five concrete failure cases** — indicators the
system got wrong, with the reason code that misled it.

No cherry-picking of snapshots. If a snapshot looks bad, it is reported; the interesting
write-up is usually the bad one.

## 11. Limitations

Stated here so they are not discovered by a reader:

1. **Small N, one labeler.** The author labels everything; double-labeling a subset
   (`§6`, plus 20% re-labeled after a gap, Cohen's κ reported) measures self-consistency,
   not truth.
2. **Selection bias.** Sampling from feeds can only find what feeds contain. An indicator
   nobody reports cannot be measured, and its absence is not evidence of safety.
3. **Snapshot decay.** Metrics describe a date. Feed composition changes; the pipeline
   may behave differently a month later, and the report is not retroactively true.
4. **No environment context.** "Actionable" here means "a reasonable defender would look
   at this", not "relevant to your estate". An indicator can be correctly scored and
   still useless to a specific reader.
5. **KEV is availability-biased.** KEV presence means known exploitation *somewhere*,
   not exploitation against you, and absence means nobody has published it yet. It is one
   reason the catalogue is served as facts instead of a score (`decisions/0010`).
6. **Boundary labels are judgement calls.** `noise` vs `opportunistic` has no objective
   line. The protocol fixes an order of questions to keep it consistent; it does not
   make it correct.

## 12. Reproducing a result

```bash
python -m threatintel.eval.run_eval \
  --snapshot snapshots/2026-12-01 \
  --labels   eval/labeled_sample/v1.csv \
  --config   eval/configs/v1.yaml
```

The command prints the config hash and refuses to run if the hash does not match the one
recorded in the published results, so a report cannot silently drift from the code that
produced it.
