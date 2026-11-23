# API

The API is the product (`decisions/0002`). Consumers read indicators, the vulnerability
catalogue and aggregates over JSON; they never open the Parquet files, never hold a DuckDB
handle, and never recompute a rule or a score. That boundary is B3 of the threat model, and
it is enforced by the service being the only reader of `data/gold/`.

What the API serves is **one run per process, over two tables**. It copies both into memory
at startup, so the clock and both configuration hashes it publishes are the ones the rows
were produced with — a `make gold` landing mid-flight cannot mix two runs. Publishing a new
run means restarting the service, which is a deliberate, visible event rather than a silent
change in what the next request returns.

The two surfaces are not interchangeable. `/v1/indicators` returns ranked claims about
maliciousness, with a score and the reason codes behind it. `/v1/vulnerabilities` returns
catalogue facts about CVEs and deliberately **has no score**: priority is a function of an
asset inventory this service does not have (`decisions/0010`).

## 1. Running it

```bash
make api
# equivalent to:
python -m threatintel.api \
  --gold data/gold/indicators.parquet \
  --vulnerabilities data/gold/vulnerabilities.parquet
```

Defaults: `127.0.0.1:8000`, both files under `data/gold/`. If `--vulnerabilities` is omitted
it defaults to `vulnerabilities.parquet` beside the gold file, because the two are written by
one run and serving them from different directories would make mismatched clocks possible.
A missing, unreadable or mixed-run table fails at startup with exit status 1, because a
healthy-looking API over no data — or over two runs at once — is worse than a service that
refuses to start.

| Surface | URL |
|---|---|
| Interactive docs | `/docs` |
| OpenAPI document | `/openapi.json` |
| Liveness | `/health` |
| Indicators | `/v1/indicators`, `/v1/indicators/{id}` |
| Vulnerability catalogue | `/v1/vulnerabilities` |
| Run aggregates | `/v1/stats` |

API version `1.0.0`, paths under `/v1`. Adding a field is compatible; removing one or
changing its meaning is not.

## 2. Run metadata

Indicator and aggregate responses carry a `run` object:

```json
{
  "as_of": "2026-11-23T00:00:00Z",
  "policy_version": "2026-11-23.2",
  "policy_config_hash": "5d858fabbe07...",
  "rules_config_hash": "9a1e92ee8bd1...",
  "indicators": 113686
}
```

These are the same values the scoring CLI computes; a mismatch means the service is serving
a different run than the one you think. `as_of` is `null` only for an empty table, which is a
valid snapshot (zero rows) rather than an error.

The catalogue's `run` object is smaller, because there is no policy to hash: `as_of` and
`vulnerabilities` (row count). Its `as_of` is the same clock as the indicator run, since one
scoring run writes both.

## 3. Listing indicators

`GET /v1/indicators`

| Parameter | Type | Meaning |
|---|---|---|
| `type` | `ip`, `domain`, `url`, `hash` | Indicator type |
| `band` | `high`, `medium`, `low` | Band under the run's policy |
| `min_score`, `max_score` | integer `0..100` | Inclusive bounds |
| `reason` | `^[A-Z0-9_]{3,40}$` | Has this reason code, e.g. `CORROBORATED` |
| `source` | `^[a-z0-9_]{2,40}$` | Was reported by this source, e.g. `feodo` |
| `needs_review` | boolean | A rule returned `insufficient_data` |
| `limit` | integer `1..200`, default `50` | Page size |
| `cursor` | opaque string | Continuation token from `next_cursor` |

Ordering is fixed: `score DESC, id ASC`. The id is the indicator's uuid5 and is unique and
stable, which is what makes the cursor well-defined without putting an indicator value in a
URL — those end up in proxy logs and browser history.

A page returns `items`, `next_cursor` (null on the last page) and the `limit` used. Pass
`next_cursor` back as `cursor` for the next page; the other filters must stay the same, since
the cursor only encodes the position `(score, id)`. A cursor is meaningful only against the
run it came from: if the service was restarted on a new run, paging may skip or repeat rows.
Compare `run.as_of` and the hashes to detect that.

```json
{
  "run": {"as_of": "2026-11-23T00:00:00Z", "...": "..."},
  "items": [
    {
      "id": "0038ec50-f5ce-5da6-b4b6-35724cebd4e8",
      "type": "ip",
      "value": "203.0.113.10",
      "score": 70,
      "band": "high",
      "needs_review": false,
      "reasons": [
        {"code": "SRC_AUTHORITATIVE", "weight": 60, "detail": "feodo"},
        {"code": "FRESH_AUTHORITATIVE", "weight": 10, "detail": "inside TTL and curated"}
      ],
      "caps": [],
      "first_seen": null,
      "last_seen": "2026-11-22T00:00:00Z",
      "sources": [{"name": "feodo", "external_id": null, "first_seen": null, "last_seen": "2026-11-22T00:00:00Z"}]
    }
  ],
  "next_cursor": "eyJzY29yZSI6NzAsImlkIjoiMDAzOGVjNTAifQ",
  "limit": 50
}
```

`type=cve` is **removed** from this endpoint, not aliased: a CVE is not an indicator and is
served by `/v1/vulnerabilities`. A request with `type=cve` fails validation with `422
validation_error` rather than returning an empty page, so a consumer that kept the old query
learns about the change instead of silently reading nothing.

`reasons` is the full explanation of the score: every point is one entry, and `caps` lists the
structural ceilings that actually bound the result. An empty `caps` list does not mean the
indicator was fresh and corroborated — the reason codes carry that. An empty `reasons` list
would mean the scorer produced nothing to explain, which the policy does not do today.

## 4. Indicator detail

`GET /v1/indicators/{id}`

The list row plus the fields that are too large or too specific for a page: `tags`,
`usage_type`, `fp_reasons`, `attributes` (source-specific facts, keyed by source name so one
provider cannot overwrite another), `ingest_version`, `bronze_refs`, `policy_version` and
`policy_config_hash`. Unknown ids return `404 not_found`.

`bronze_refs` name the raw payloads the indicator came from; they are paths, not data, and
they are only resolvable on the operator's machine.

## 5. The vulnerability catalogue

`GET /v1/vulnerabilities`

| Parameter | Type | Meaning |
|---|---|---|
| `ransomware` | boolean | The catalogue's own ransomware-campaign flag |
| `limit` | integer `1..200`, default `50` | Page size |
| `cursor` | opaque string | Continuation token from `next_cursor` |

Ordering is fixed: `date_added DESC, cve_id ASC`. That is chronology, not priority — the
catalogue does not know what an operator runs, so it does not pretend to rank. An entry with
no publication date sorts last rather than being dropped.

Each item carries `cve_id`, `date_added`, `due_date`, `ransomware`, `vendor_project`,
`product`, `required_action`, `short_description`, `cwes`, `notes`, `tags`, `sources`,
`bronze_refs` and `ingest_version`. There is **no `score`, `band`, `priority` or `risk`
field**. Rankings of this table exist only when a consumer joins it with its own estate data.

```json
{
  "run": {"as_of": "2026-11-23T00:00:00Z", "vulnerabilities": 1790},
  "items": [
    {
      "id": "5c2f...",
      "cve_id": "CVE-2024-1234",
      "date_added": "2024-05-01T00:00:00Z",
      "due_date": "2024-05-22T00:00:00Z",
      "ransomware": true,
      "vendor_project": "Example",
      "product": "Example Server",
      "required_action": "Apply updates per vendor instructions.",
      "short_description": "...",
      "cwes": ["CWE-78"],
      "notes": "...",
      "tags": ["kev", "ransomware_campaign_use"],
      "sources": [{"name": "cisa_kev", "...": "..."}],
      "bronze_refs": ["data/bronze/cisa_kev/..."],
      "ingest_version": "0.1.0"
    }
  ],
  "next_cursor": "eyJ2IjoxLCJrIjoxNzYz...",
  "limit": 50
}
```

The cursor is a **different codec** from the indicator cursor. A token from one endpoint
presented to the other fails with `400 invalid_cursor`; it is not silently reinterpreted
against a table with different ordering columns.

## 6. Run aggregates

`GET /v1/stats` returns whole-run counts, not filter-aware ones:

```json
{
  "run": {"as_of": "2026-11-23T00:00:00Z", "...": "..."},
  "bands": {"high": 0, "medium": 122, "low": 113564},
  "distinct_scores": 3,
  "needs_review": 0,
  "reasons": {"CORROBORATED": 122, "SINGLE_COMMUNITY_SOURCE": 113559, "...": 0},
  "vulnerabilities": {
    "count": 1790,
    "ransomware": 362,
    "earliest_date_added": "2021-12-10T00:00:00Z",
    "latest_date_added": "2026-11-19T21:00:00Z"
  }
}
```

`reasons` counts indicators per reason code, so it is the distribution of the published
explanation, not a per-rule rate. Rule rates are in the rules report (`docs/rules.md`).
`distinct_scores` is carried explicitly because the current run has only three values: a
degenerate distribution is a finding, and it should not have to be inferred from a histogram
that a consumer does not compute.

`/health` reports the pinned row count per track:

```json
{"status": "ok", "indicators": 113686, "vulnerabilities": 1790}
```

## 7. Errors

Every error is the same envelope, so a consumer can branch on `code` instead of parsing
prose:

```json
{"error": {"code": "invalid_cursor", "message": "cursor is not base64url-encoded JSON"}}
```

| Status | Code | Cause |
|---|---|---|
| 400 | `invalid_cursor` | Cursor does not decode to the payload of *this* endpoint's cursor codec, or is out of range |
| 404 | `not_found` | Unknown indicator id, or unknown path |
| 405 | `method_not_allowed` | The API is read-only |
| 422 | `validation_error` | A query parameter failed validation; `fields` lists location and message |
| 503 | `gold_unavailable` | The pinned table became unreadable; restart the service |

`fields` in a validation error names the parameter (`query.band`) and the rule it broke. The
handler does not echo the submitted value, so a malformed request does not write an indicator
into a log line.

## 8. Security posture

Phase 1 has **no authentication and no TLS**, so the default bind is loopback and the CLI
prints a warning if `--host` is anything else. Exposing it is an explicit act, and the
supported way is an authenticating reverse proxy in front of it — not a token checked in this
codebase, which would be an untested auth implementation in a project about trusting less.

- **Read-only.** There is no write surface, no review endpoint and no admin route. Review is
  a separate future surface with its own decision record; it will not be bolted onto this
  contract silently.
- **No CORS.** A browser cannot call the API cross-origin, by omission. Adding CORS is a
  decision with an origin allowlist, not a default.
- **JSON only.** Responses set `X-Content-Type-Options: nosniff`,
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and
  `Cache-Control: no-store`. The service never renders a value into HTML or CSV; escaping is
  the consumer's obligation (B4), and the headers say this body is data, not a document.
- **Values are data.** An indicator value is arbitrary third-party text. A consumer that
  interpolates it into a shell command, SQL string or HTML page owns that decision.
- **No rate limit.** Loopback, single operator, no cost per request. A remote deployment
  should rate-limit at the proxy.
- **One process, one writer-free snapshot.** DuckDB runs in memory over rows copied from
  Parquet; the file is never written by this service.

## 9. Known limits

- **No priority on the catalogue.** `/v1/vulnerabilities` has no score, by design. Sorting is
  chronological. Any consumer-facing ranking is the consumer's, because only the consumer
  knows which software it runs (`decisions/0010`).
- **No lookup by value.** Filtering by `value` is not offered: ids keep indicator values out
  of URLs and access logs, and the value is already in the response. A value search can be
  added later if a consumer needs it, with its own publication-boundary review.
- **The cursor is per endpoint.** Indicator and vulnerability cursors are different codecs
  and are rejected by the other endpoint. Within one endpoint, a cursor still only encodes
  position and a restart on a new run may skip or repeat rows.
- **No tag/date filters, no per-source aggregates.** The columns exist in gold; the
  endpoints expose only what the current consumers asked for.
- **Stats ignore filters.** `bands` and `reasons` describe the whole run. A filtered
  distribution is a client-side sum over pages, or a new endpoint with a documented contract.
- **One run per process.** There is no way to query a previous run through the API. Keep the
  Parquet file (or its hash) if a number must be reproduced later.
- **No ETag or conditional requests.** `Cache-Control: no-store` is the whole cache policy.

## 10. Checking a deployment

```bash
curl -s localhost:8000/health
curl -s 'localhost:8000/v1/indicators?band=medium&limit=5' | jq '.run, (.items | length)'
curl -s 'localhost:8000/v1/vulnerabilities?ransomware=true&limit=5' | jq '.run, (.items | length)'
curl -s localhost:8000/v1/stats | jq '.bands, .distinct_scores, .vulnerabilities'
```

Compare the `run` block against the summary printed by `make gold`. If they differ, the
service is still holding the previous run: restart it. The full contract, including every
schema, is at `/openapi.json`; the examples in this document use documentation ranges only.
