# 0009 — Read-only API boundary: one pinned run, keyset pages, no auth in Phase 1

- Status: accepted
- Date: 2026-11-23
- Supersedes: —

## Context

`docs/decisions/0002` makes the API the product and puts consumers outside the store. The threat model states the resulting boundary as B3: the API is the only reader
of silver/gold, and consumers never hold a database handle. That leaves the shape of the
read path to decide.

Three constraints drive it:

1. **Reproducibility is a published claim.** A response that cannot be tied to the run that
   produced it is an anecdote. Gold already stores `as_of`, `policy_config_hash` and
   `rules_config_hash` per row.
2. **The data is replaced, not appended.** `make gold` rewrites the table atomically. Offset
   pagination over a file that can be replaced between two requests is unsound, and a
   long-lived SQL view over `read_parquet` resolves the path per query — a run landing
   mid-flight could serve rows from one configuration with metadata from another.
3. **Phase 1 is single-operator and loopback.** Authentication would be an untested auth
   layer in a project whose premise is fewer trusted components.

## Decision

1. **Read-only JSON over gold, versioned under `/v1`.** Four surfaces: list, detail, stats,
   health. No writes, no review endpoint, no admin route. Review is a separate surface that
   will arrive through its own decision, not as a silent extension of this one.
2. **One run per process.** At startup the API copies the Parquet file into an in-memory
   DuckDB table, and refuses to start if the rows disagree about the run. Publishing a new run
   is a restart. This trades hot reload for the guarantee that no response mixes two runs.
3. **Every indicator and aggregate response carries `run` metadata.** `as_of`, both hashes,
   `policy_version` and the row count. `/health` carries only liveness and the pinned count,
   because it is a probe, not a data response.
4. **Keyset pagination on `(score, id)`.** Ordering is `score DESC, id ASC`; the cursor is
   base64url JSON of a unique `id` and its score. No indicator value appears in a URL or an
   access log. A page is `limit + 1` rows, and the extra row decides whether `next_cursor`
   exists.
5. **A stable error envelope.** `{"error": {"code", "message", "fields?"}}` with documented
   codes (`invalid_cursor` 400, `not_found` 404, `method_not_allowed` 405,
   `validation_error` 422, `gold_unavailable` 503). Validation errors name the parameter and
   never echo the submitted value.
6. **Loopback by default, no auth, no CORS, no TLS.** Binding elsewhere prints a warning and
   is expected to sit behind an authenticating proxy. Security headers mark the body as data
   (`nosniff`, `default-src 'none'`, `no-store`); the service does not render values into
   HTML or CSV.
7. **Filters are bound parameters, not SQL strings.** Accepted filter columns are a fixed
   set; values reach DuckDB through placeholders, and the JSON filters use DuckDB's
   `json_each` rather than string matching.

## Alternatives rejected

- **Serving directly from a Parquet view.** Rejected: path resolution per query makes the
  run a moving target between requests, which is exactly the failure the metadata is meant
  to expose.
- **Offset pagination (`?offset=`).** Rejected: neither stable nor cheap over a replaced
  table, and it invites deep scans.
- **Exposing the gold row as-is.** Rejected: `attributes_json` and `sources_json` are
  source-specific, and a response model is the reviewable place where their shape is
  asserted. It also makes every field addition a visible contract change.
- **Token auth in Phase 1.** Rejected for now: loopback plus an explicit warning is smaller
  and more honest than a home-grown auth path. The proxy is the supported remote deployment.
- **GraphQL or a query language.** Rejected: one consumer shape exists today, and a generic
  query surface is a larger publication-boundary problem than four endpoints.
- **Streaming from Parquet on every request.** Rejected at this volume: the snapshot loads in
  about a second and every subsequent page is an in-memory query.

## Consequences

### Positive

- A consumer can reproduce a number by comparing the `run` block with the gold summary; no
  response is anonymous.
- The run is a property of the process, so the API cannot serve a half-published table.
- Cursor paging is stable under concurrent replacement, and ids keep values out of URLs.
- The contract is generated from the response models, so `/openapi.json` and the code cannot
  drift.

### Negative

- A new gold run requires a restart; there is no hot reload and no way to query the previous
  run.
- The whole table is resident per process, which caps this design at a size far above the
  current 10^5 rows but not at arbitrary scale.
- A remote, unauthenticated bind is one flag away. The warning is a speed bump, not a
  control.
- No rate limiting or TLS in-process; both belong to the proxy.

### Accepted cost

Operational simplicity and a run that cannot mix itself, in exchange for a restart to
publish and no query surface beyond the four endpoints.

## Revisit if

- a consumer needs multi-run history, in which case the snapshot model becomes a run registry
  and this record is superseded, not edited;
- remote access becomes a requirement rather than an accident, in which case auth and TLS are
  designed here or delegated with an explicit contract to the proxy;
- the table no longer fits comfortably in memory, which reopens the storage decision
  (`0003`) rather than this one alone;
- the review surface lands, which needs its own decision on writes, identity and who may
  label what.
