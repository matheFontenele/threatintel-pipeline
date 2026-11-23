# 0002 — Scope: detection / threat-intel as the primary track

- Status: accepted
- Date: 2026-11-23
- Supersedes: —

## Context

The original project qualified leaked documents against a two-year internal history
(4,967 events, 33 clients). That history is not available, and it contains client data
that cannot be published. A portfolio piece built on private data has no audience and no
verifiable claim.

Three tracks were possible: detection/threat-intel engineering, AppSec, or AI security.
The existing skills and the existing tooling (Gaara, a defensive security copilot) point
at detection.

## Decision

The primary track is **detection / threat-intelligence engineering**: ingest a few public
feeds, normalize indicators, apply explainable false-positive rules, score with reasons,
and evaluate against a hand-labeled set.

Secondary: the Gaara open-core work, kept as a separate narrative and a separate
repository boundary. Honeypot data collection is explicitly deferred — it is the most
convincing possible data source, and also the one with the most legal and operational
constraints (isolation, LGPD retention, provider terms). It is a later phase, not a
prerequisite.

Frontend is out of scope: consumers build their own dashboards on top of the API, which
is the product.

## Consequences

### Positive

- Every claim in the README can be checked by a stranger with a checkout and a free key.
- The interesting engineering problem (evaluation of a noisy signal) is the centre of the
  project instead of an afterthought.
- No client data anywhere: the repository can be public from the first commit.

### Negative

- No proprietary corpus means no proprietary advantage; the differentiation has to come
  from methodology and honesty.
- Public feed noise is a harder problem than classifying a curated corpus, and the metrics
  will look worse than a synthetic benchmark would.

### Accepted cost

The project does not demonstrate document/OCR engineering any more. That skill stays in
the private repository; it is not carried over here, and copying any of its content in —
client names included — is prohibited.

## Revisit if

A legitimately publishable corpus appears (e.g. the operator runs a honeypot long enough
to own the data). That would strengthen this track rather than replace it.
