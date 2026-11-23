# 0001 — Decision record format

- Status: accepted
- Date: 2026-11-23
- Supersedes: —

## Context

The project is a portfolio piece: a reader has to be able to judge the engineering
judgement behind it, not just read the code. Chat history is not an artifact. A single
long design document becomes stale the first time a decision changes, and then nobody
trusts any part of it.

## Decision

One short Markdown file per decision in `docs/decisions/`, numbered, with a fixed
structure: context, decision, consequences (positive, negative, accepted cost), and the
condition that would reopen it. Decisions are superseded, never deleted. The index in
`README.md` is the only place that tracks status.

## Consequences

### Positive

- Rationale survives the conversation that produced it, and is diffable in review.
- "Why not X?" has an answer that does not depend on the author being present.
- Reversal is visible: a superseded record plus a new one tells the whole story.

### Negative

- Overhead per decision. Mitigated by keeping records to one page; a record that needs
  three pages is usually two decisions.
- Risk of records written to look good after the fact. Mitigated by dating them and by
  publishing the "revisit if" clause, which is falsifiable.

### Accepted cost

Documentation is not code. Making the record is cheaper than re-deriving the reasoning
six weeks later, but it is not free.

## Revisit if

The number of records grows past what a reader will scan (roughly 20). At that point the
index gets grouped by area rather than renumbering anything.
