# 0007 — Publication boundary: code and metrics are public, feed data is not

- Status: accepted
- Date: 2026-11-23
- Supersedes: —

## Context

The project's credibility rests on publishing the methodology and the numbers, including
the failure cases (`methodology.md` §10). It also ingests sources whose terms forbid
redistribution: abuse.ch §7.3 prohibits derivative works and AI training on the data
without express consent, and ThreatFox/URLhaus are not in the CC0 exemption of §3.4.

"Publish the evaluation" and "do not republish the feed" collide at exactly one point: an
evaluation artifact that names an indicator. A label file with `203.0.113.44, malicious` is
a republished indicator with an annotation. A demo dataset is worse.

The temptation is to treat a derived score as not-the-data. It is not a defensible reading
when the row contains the indicator value the provider served.

## Decision

1. **Published**: source code, schemas, rule definitions, methodology, source inventory,
   aggregate metrics, confusion matrices, per-rule ablation, reason-code distributions,
   runtimes, and the hash of the evaluation config.
2. **Never published**: indicator values obtained from a restricted source — not in a demo
   dataset, not as a test fixture, not in a label file, not in an issue or a screenshot.
3. **Test fixtures use documentation values only** — RFC 5737 IPv4 (`192.0.2.0/24`,
   `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 IPv6 (`2001:db8::/32`), RFC 2606 domain
   suffixes (`.example`, `.test`, `.invalid`). Enforced by
   `tests/test_publication_boundary.py`, so a live IOC cannot be pasted into a fixture
   without the suite failing.
4. **Labels for restricted sources stay local.** The published eval artifact is the metric
   table plus the sampling rule (stratification, seed, floor per cell) and the config hash.
   A reader reproduces the result by drawing their own sample with their own key and
   labelling it with the published protocol — not by reading our label file.
5. **No hashed indicator values in published artifacts.** The obvious compromise — publish
   `sha256(value)` — is unsafe for IPs: IPv4 is small enough to enumerate, so the hash is
   reversible. A secret-keyed HMAC would be irreversible but also unverifiable by a reader,
   which is the worst of both. Aggregate counts are the honest ceiling.
6. **No AI training on any feed data.** Phase 1 has no model, but the constraint is
   recorded so it is not quietly violated later.

KEV is the exception that makes the demo possible: it is a US government work product
(public domain), so CVE identifiers and KEV attributes may be published, and the sample
label set can use KEV-derived items without restriction.

## Consequences

### Positive

- The legal posture is clean and stated, not accidental. A reader can see *why* there is no
  demo dataset instead of assuming the author had nothing to show.
- Reproducibility is defined honestly: same protocol, same code, independently drawn
  sample. That is a stronger claim than "trust my CSV".
- The fixture test converts a policy into a build failure, which is the only kind of policy
  that survives a tired afternoon.

### Negative

- A reviewer cannot recompute the exact published precision/recall without a free abuse.ch
  key and their own labelling effort. The report must say so plainly rather than implying
  bit-for-bit reproducibility.
- No shareable sample means demos and screenshots have to use KEV or synthetic data.
- Anyone who wants to check the work has to trust the protocol description. Partly mitigated
  by publishing the seeded sampling code and the label taxonomy test-by-test.

### Accepted cost

Less impressive-looking artifact in exchange for not breaching a provider's terms. The
project can be checked by a stranger with a checkout and a free key, which is what
`README.md` already promises; it cannot be checked by a stranger with only a browser.

## Revisit if

- abuse.ch/Spamhaus grants written consent for publication, or the operator holds a
  subscription whose terms permit redistribution — then a public sample becomes possible and
  this record is superseded, not edited;
- the source mix moves to sources that permit redistribution (KEV-only, or CC0 feeds such as
  Feodo Tracker per §3.4), in which case the eval set can be published directly;
- a privacy obligation (LGPD, T10) turns out to be stricter than the provider's terms, in
  which case the boundary tightens and this record is amended by a new one.
