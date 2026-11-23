# API

The API is the product (`decisions/0002`). Consumers read indicators and aggregates over
JSON; they never open the Parquet file, never hold a DuckDB handle, and never
recompute a rule or a score. That boundary is B3 of the threat model, and it is enforced by
the service being the only reader of `data/gold/`.

What the API serves is **one scored run per process**. It copies gold into memory at
startup, so the clock and both configuration hashes it publishes are the ones the rows were
produced with — a `make gold` landing mid-flight cannot mix two runs. Publishing a new run
means restarting the service, which is a deliberate, visible event rather than a silent
change in what the next request returns.

## 1. Running it

```bash
make api
# equivalent to:
python -m threatintel.api --gold data/gold/indicators.parquet
```

Defaults: `127.0.0.1:8000`, `data/gold/indicators.parquet`. A missing, unreadable or
mixed-run table fails at startup with exit status 1, because a healthy-looking API over no
data — or over two runs at once — is worse than a service that refuses to start.

| Surface | URL |
|---|---|
| Interactive docs | `/docs` |
| OpenAPI document | `/openapi.json` |
| Liveness | `/health` |
| Indicators | `/v1/indicators`, `/v1/indicators/{id}` |
| Run aggregates | `/v1/stats` |

API version `1.0.0`, paths under `/v1`. Adding a field is compatible; removing one or
changing its meaning is not.

## 2. Run metadata

Indicator and aggregate responses carry a `run` object:

```json
{
  "as_of": "2026-11-23T10:30:00Z",
  "policy_version": "2026-11-23",
  "policy_config_hash": "d5a98f5b697e...",
  "rules_config_hash": "9a1e92ee8bd1...",
  "indicators": 115476
}
```

These are the same values the scoring CLI computes; a mismatch means the service is serving
a different run than the one you think. `as_of` is `null` only for an empty table, which is a
valid snapshot (zero rows) rather than an error.

## 3. Listing indicators

`GET /v1/indicators`

| Parameter | Type | Meaning |
|---|---|---|
| `type` | `ip`, `domain`, `url`, `hash`, `cve` | Indicator type |
| `band` | `high`, `medium`, `low` | Band under the run's policy |
| `min_score`, `max_score` | integer `0..100` | Inclusive bounds |
| `reason` | `^[A-Z0-9_]{3,40}$` | Has this reason code, e.g. `KEV_EXPLOITATION` |
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
  "run": {"as_of": "2026-11-23T10:30:00Z", "...": "..."},
  "items": [
    {
      "id": "0038ec50-f5ce-5da6-b4b6-35724cebd4e8",
      "type": "cve",
      "value": "CVE-2024-1234",
      "score": 70,
      "band": "high",
      "needs_review": false,
      "reasons": [
        {"code": "SRC_AUTHORITATIVE", "weight": 60, "detail": "..."},
        {"code": "KEV_EXPLOITATION", "weight": 10, "detail": "..."}
      ],
      "caps": [],
      "first_seen": null,
      "last_seen": null,
      "sources": [{"name": "cisa_kev", "external_id": null, "first_seen": null, "last_seen": null}]
    }
  ],
  "next_cursor": "eyJzY29yZSI6NzAsImlkIjoiMDAzOGVjNTAifQ",
  "limit": 50
}
```

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

## 5. Run aggregates

`GET /v1/stats` returns whole-run counts, not filter-aware ones:

```json
{
  "run": {"as_of": "2026-11-23T10:30:00Z", "...": "..."},
  "bands": {"high": 1790, "medium": 122, "low": 113564},
  "needs_review": 0,
  "reasons": {"KEV_EXPLOITATION": 1790, "SRC_AUTHORITATIVE": 1795, "...": 0}
}
```

`reasons` counts indicators per reason code, so it is the distribution of the published
explanation, not a per-rule rate. Rule rates are in the rules report (`docs/rules.md`).

## 6. Errors

Every error is the same envelope, so a consumer can branch on `code` instead of parsing
prose:

```json
{"error": {"code": "invalid_cursor", "message": "cursor is not base64url-encoded JSON"}}
```

| Status | Code | Cause |
|---|---|---|
| 400 | `invalid_cursor` | Cursor does not decode to `{score, id}` or is out of range |
| 404 | `not_found` | Unknown indicator id, or unknown path |
| 405 | `method_not_allowed` | The API is read-only |
| 422 | `validation_error` | A query parameter failed validation; `fields` lists location and message |
| 503 | `gold_unavailable` | The pinned table became unreadable; restart the service |

`fields` in a validation error names the parameter (`query.band`) and the rule it broke. The
handler does not echo the submitted value, so a malformed request does not write an indicator
into a log line.

## 7. Security posture

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

## 8. Known limits

- **No lookup by value.** Filtering by `value` is not offered: ids keep indicator values out
  of URLs and access logs, and the value is already in the response. A value search can be
  added later if a consumer needs it, with its own publication-boundary review.
- **No tag/date filters, no per-source aggregates.** The columns exist in gold; the
  endpoints expose only what the current consumers asked for.
- **Stats ignore filters.** `bands` and `reasons` describe the whole run. A filtered
  distribution is a client-side sum over pages, or a new endpoint with a documented contract.
- **One run per process.** There is no way to query a previous run through the API. Keep the
  Parquet file (or its hash) if a number must be reproduced later.
- **No ETag or conditional requests.** `Cache-Control: no-store` is the whole cache policy.

## 9. Checking a deployment

```bash
curl -s localhost:8000/health
curl -s 'localhost:8000/v1/indicators?band=high&limit=5' | jq '.run, (.items | length)'
curl -s localhost:8000/v1/stats | jq '.bands'
```

Compare the `run` block against the summary printed by `make gold`. If they differ, the
service is still holding the previous run: restart it. The full contract, including every
schema, is at `/openapi.json`; the examples in this document use documentation ranges only.
