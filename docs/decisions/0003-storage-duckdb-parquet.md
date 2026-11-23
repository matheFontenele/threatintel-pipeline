# 0003 — Storage: DuckDB + Parquet, with reviews in a separate file

- Status: accepted
- Date: 2026-11-23
- Supersedes: —

## Context

Volume is small: tens of thousands of indicators per day, a few years of history at most,
one writer (the operator). The workload is analytical (group by source, type, class, date)
plus a read API and a handful of review writes.

Candidates were PostgreSQL, SQLite, and DuckDB + Parquet. PostgreSQL means operating a
service and a migration toolchain for a dataset that fits in memory; it also invites
consumers to ask for direct database access, which this project refuses. SQLite is fine
for the operational writes and weak for the analytical scans.

## Decision

- **Bronze**: immutable Parquet, partitioned by `source` and `collection_date`.
- **Silver / gold**: Parquet, rebuilt per run; DuckDB is the query engine reading them
  directly (`read_parquet`).
- **API**: opens the store **read-only**.
- **Reviews**: a separate DuckDB file (`reviews.duckdb`), written only by the API process.

The split matters: DuckDB allows a single writer per file. Sharing one file between the
pipeline (bulk write) and the API (review inserts) would produce lock contention on the
one interaction that must never fail — a human recording a label.

## Consequences

### Positive

- No server to operate; the whole store is files in a directory, copyable between the two
  work machines.
- Parquet is the interchange format anyway: the same files feed the Gaara snapshot export
  and any BI tool, with no extra code.
- Analytical queries over Parquet with DuckDB are fast at this size without indexes,
  tuning, or a schema migration when a column is added.
- Read-only API plus a separate write store makes "the API cannot corrupt gold" a
  structural property, not a code-review habit.

### Negative

- No multi-process concurrency. Running two collectors against the same bronze directory
  simultaneously is unsupported; the Makefile serializes runs.
- No transactions spanning review writes and gold reads. Acceptable: a review references
  an indicator id, it does not mutate it.
- DuckDB is not a service, so "just connect to the database" from another machine is not
  possible. This is aligned with the API-as-product decision (`0002`), but it will be
  experienced as a limitation by anyone who wants SQL access.

### Accepted cost

Rebuilding silver/gold per run instead of updating rows in place. At this volume a full
rebuild is seconds, and it removes an entire class of incremental-update bugs.

## Revisit if

Any of these becomes true:

- more than one process needs to write the analytical store;
- a second machine must query live data rather than a copied snapshot;
- the store exceeds roughly 50 GB, or a dashboard query exceeds ~1 s;
- row-level security or per-consumer SQL access becomes a real requirement — at which
  point PostgreSQL (with a dedicated read-only `consumo` schema) replaces this, and the
  Parquet files stay as the archival layer.
