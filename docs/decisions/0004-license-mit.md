# 0004 — License: MIT

- Status: accepted, reversible
- Date: 2026-11-23
- Supersedes: —

## Context

The repository is a portfolio artifact: the point is that people read, run and reuse it.
The licence has to be trivially understandable to a recruiter and unproblematic for anyone
who wants to lift a rule or a schema into their own work.

The alternative considered was Apache-2.0, which adds an explicit patent grant and a
trademark clause. Neither matters much for a few thousand lines of Python, and the extra
text makes the project look heavier than it is.

## Decision

MIT, in `LICENSE`, copyright held by the author.

## Consequences

### Positive

- The most permissive and most recognised option; no reading required to know what is
  allowed.
- Forking and reuse require nothing from the reader.

### Negative

- No patent grant. Irrelevant at this scale, but worth stating rather than discovering.
- No copyleft: a commercial user may take the code and publish nothing back.

### Accepted cost / reversibility

The licence is recorded as reversible in the sense that it can be changed for *future*
versions; already-published versions stay MIT. If the project later becomes the open core
of a commercial tool, the boundary is drawn with **new** code and a separate repository,
not by retroactively restricting what was published.

## Revisit if

The Gaara open-core split (secondary track) lands in the same repository. Mixing an
open-core boundary with an MIT root licence would be confusing; that discussion is
tracked separately and intentionally not settled here.
