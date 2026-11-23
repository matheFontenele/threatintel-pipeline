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

## 4. Sampling

Stratified by `(source, type)`, with a floor per cell, seeded, drawn from the snapshot
under evaluation. Target 200–300 items; below ~150 the confidence intervals are too wide
to support any claim, and the report says so instead of quietly reporting a point
estimate.

Deliberate oversampling of the hard cases, because a set dominated by obvious malware
measures nothing:

- indicators that only one source reports (the echo problem, FP-05);
- indicators whose source score is high but whose tags suggest scanning (FP-08);
- indicators inside large cloud/CDN ranges (FP-02);
- KEV-linked indicators (FP-10) — sampled *separately*, see §7.

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
| FP-05 single source | independent feed count | "reported by two feeds" as a label |
| FP-08 internet noise | GreyNoise noise classification | GreyNoise classification |
| FP-10 KEV linkage | KEV | "is in KEV" as a label |

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
`needs_review`):

```
precision = TP / (TP + FP)
recall    = TP / (TP + FN)      FN includes malicious items routed to needs_review
FPR       = FP / (FP + TN)      among reference negatives (benign + noise)
review    = |needs_review| / N
```

Plus:

- **review share** and, within it, the share that turns out `malicious` — the review
  queue exists to catch what the filter cannot decide, so its yield matters;
- **per-rule table** from §8;
- **runtime** for a full snapshot (seconds; it is a batch job, not a benchmark);
- **exact denominators**, printed, so a reader can recompute by hand.

With N in the low hundreds, point estimates are reported with **95% Wilson intervals**.
A precision of 0.91 on 34 actionable items is `[0.77, 0.97]`, and the report writes it
that way rather than pretending the third digit exists.

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
   not exploitation against you, and absence means nobody has published it yet.
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
