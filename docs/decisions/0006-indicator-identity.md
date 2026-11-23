# 0006 — Indicator identity, normalization and merge

- Status: accepted
- Date: 2026-11-23
- Supersedes: —

## Context

Every join in this project depends on one question: when two rows describe "the same"
indicator. Corroboration counts distinct sources per indicator; reviews attach to an
indicator; re-running a collector must not create a second copy; the API addresses an
indicator by id.

The plan sketch allowed a random `id` (UUID) and a single `bronze_ref` text field. Both
work only if a row never merges with another, which is exactly what ingestion does.

## Decision

1. **Identity is `(type, normalized value)`.** The id is
   `uuid5(ID_NAMESPACE, "<type>|<normalized value>")` with a fixed namespace constant.
2. **Normalization is explicit per type**: IPs canonicalized (`inet_ntop` form, IPv4-mapped
   IPv6 folded to IPv4), domains lowercased/IDNA-encoded/dot-stripped, URLs rebuilt from
   parts (credentials and fragments dropped, default ports removed), hashes lowercased,
   CVEs uppercased.
3. **`attributes` is keyed by source name**, so merging two providers can never make one
   overwrite the other's fields.
4. **`bronze_refs` is a list**, replacing the single `bronze_ref` from the sketch: one
   indicator legitimately has evidence in several files.
5. **Merge is defined, not arbitrary**: sources unioned per provider, dates widened to the
   min/max window, `distinct_reporters` recomputed from `len({sources})`, attributes
   unioned by source key.
6. **Rejected rows are recorded with a reason**, never coerced or silently dropped. A bad
   entry costs one indicator, not the collection.

## Consequences

### Positive

- Re-ingest is idempotent: the same source on two dates produces one row with two bronze
  refs and `distinct_reporters = 1`.
- Reviews survive re-ingestion, because the id does not change.
- A malformed value cannot enter silver — `Indicator` re-validates on read, so a corrupt
  file fails loudly instead of producing a wrong join later.

### Negative

- **The namespace constant is load-bearing.** Changing it renumbers every indicator and
  detaches every review. Treat it as a schema migration, not a refactor.
- Normalization rejects more than it accepts (single-label domains, CIDR ranges, FTP URLs).
  That is deliberate: a public feed row that is not a public indicator is not silently
  "fixed" into one.
- `attributes` JSON-per-source is not directly queryable as columns; consumers must
  `json_extract`. Accepted, because the alternative is a column union that grows with
  every new feed.

### Accepted cost

Merging is not associative in one edge case: `ingest_version` keeps the last writer's
value. That records *when the row was last touched*, which is the useful meaning; it is
not used for equivalence anywhere.

## Revisit if

- an indicator needs aliasing (URL shorteners expanding to the same target, CVE aliases,
  domain-to-IP binding): that is a separate relation, not a change to the id;
- a source reports values we normalize differently from its own record and joins start
  failing — then normalization needs a per-source override, and the override has to be
  versioned, not patched in place.
