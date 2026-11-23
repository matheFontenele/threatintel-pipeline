# Sources, terms and collection rules

Everything here is marked **unverified** until someone reads the provider's terms and
records the date. A collector does not ship while its row still says `unverified` — that
is the gate, not a suggestion.

Quotas and endpoints change without notice. Treat the numbers below as "what the
documentation said when this file was written (2026-11-23)", not as current truth.

## Policy

1. **Bring your own key.** The repository contains no credentials, no `.env`, and no
   fixture that needs a real key. `.env.example` lists variable names only.
2. **No feed data in the repository.** Code, schema, and hand-made *labels* are public.
   Raw payloads, full dumps and snapshots are not.
3. **Record provenance on every row**: source name, external id, first/last seen,
   `collected_at`, and the terms version in force. Without it a scoring decision cannot
   be re-derived.
4. **Batch before per-item.** Bulk endpoints and exports first; per-IP lookup only for
   indicators that survive the filters, cached with a TTL.
5. **No unauthenticated scraping of HTML pages.** If a provider offers a documented API
   or export, use it; if it does not, it is not a source for this project.
6. **Do not redistribute.** Publishing a derived score is not the same as republishing a
   feed, and only the former happens here. Whether derived scores are permitted is
   exactly what the terms review decides per source.

## Inventory

| # | Source | Provides | Auth | Free tier (as documented) | Planned cadence | Redistribution | Status |
|---|---|---|---|---|---|---|---|
| 1 | **CISA KEV** | CVEs with known exploitation in the wild | none | public JSON/CSV | daily | public domain work product — verify | `verified 2026-11-23` (endpoint + shape); redistribution still `unverified` |
| 2 | **abuse.ch — URLhaus** | malicious URLs, payload hashes | Auth-Key in the URL path (free) | bulk export, regenerated every 5 min; do not fetch more often | daily | no derivative works without consent (§7.3) — see `decisions/0007` | `verified 2026-11-23` (terms + export URL); collector + normalizer implemented; live run: 103,814 rows, 10 rejected |
| 3 | **abuse.ch — ThreatFox** | IOCs (IP/domain/URL/hash) with malware family | Auth-Key in `Auth-Key` header (free) | `POST` batch query, `days` 1–7; drops IOCs older than 6 months (from 2025-05-01) | daily | no derivative works without consent (§7.3) — see `decisions/0007` | `verified 2026-11-23` (terms + endpoint); collector + normalizer implemented; live run: 10,392 IOCs over 7 days |
| 4 | **abuse.ch — Feodo Tracker** | botnet C2 IPs | **none** — public JSON | no key, no documented limit; still one fetch per hour locally | daily | **CC0, publishable** (§3.4) — see `decisions/0007` | `verified 2026-11-23` (endpoint + shape); collector + normalizer implemented |
| 5 | **abuse.ch — MalwareBazaar** | malware samples, hashes | Auth-Key (free) | API | weekly, metadata only | same as above | `unverified` |
| 6 | **AbuseIPDB** | crowd-sourced IP abuse reports, confidence score, usage type, blacklist | API key (free tier) | docs list `check` 1,000/day and `blacklist` 5/day, blacklist cap 10,000; per-minute limit not documented; free-tier mapping to the "Standard" plan **unconfirmed** | daily blacklist, `check` on a sample | **terms unconfirmed** — treat per-IP data as non-publishable | `unverified` (documented limits read 2026-11-23; terms page 404 at review time) |
| 7 | **GreyNoise Community** | IP classification: `noise`, `RIOT` | API key | 50 searches/week — severe | on-demand, ≤ tens of IPs per run | **unconfirmed**; evaluation-evidence use not documented either | `unverified` |
| 8 | **NVD** | CVE metadata, CVSS | optional key | 5 req/30 s without key, higher with | weekly, CVE metadata only | public domain | `unverified` |
| 9 | **OSV** | package vulnerabilities | none | query API | on-demand | CC-BY-4.0 style — verify | `unverified` |
| 10 | **Tranco** | top-1M domain popularity, daily list with permanent ids | none | one million domains, updated daily by 00:00 UTC; no documented download-frequency limit | daily pinned list id | **unconfirmed** — cite the list id, do not commit the list | `unverified` |

Ingestion order is deliberate: 1 → 2/3/4 → 6 → 10 → 7. KEV first because it is small,
authoritative, credential-free, and it feeds the vulnerability track instead of the scorer.
AbuseIPDB (6) is the first source that could break the single-organization monopoly on
reporting, so it precedes the rules that count organizations. Tranco (10) is an annotation,
not a feed, and comes after there is something to annotate. GreyNoise (7) is last because its
limits make it enrichment, never bulk scoring.

## Per-source notes

### CISA KEV

- Catalogue of CVEs with confirmed exploitation. Small (order of 10^3), stable identifiers,
  public JSON and CSV.
- **Observed on 2026-11-23**: `HTTP 200`, 1,871,127 bytes, 1,790 entries, `count` field
  agreeing with `len(vulnerabilities)`, `dateReleased` in the payload. The collector in
  `src/threatintel/collectors/kev.py` validates exactly this shape before writing bronze,
  so a format change fails loudly instead of corrupting the store.
- **What it means**: exploitation observed *somewhere*, published. Not "affects you" and
  not "is being exploited right now".
- **Where it goes**: the vulnerability track, as catalogue facts with no score
  (`decisions/0010`). It no longer contributes to any indicator score, so it is also a
  legitimate label source — a CVE's KEV status is a fact rather than a model output, and
  FP-10 is retired from the IOC track.
- Still open: whether derived scores based on KEV may be published. Treat the catalogue as
  a public-domain US government work product, but confirm before publishing a dataset that
  embeds it wholesale.

### abuse.ch

Terms of Use read **2026-11-23** (effective 2025-11-04, last updated 2026-10-21) at
<https://abuse.ch/terms-of-use/>. Key clauses, quoted because paraphrase loses the teeth:

- **§7.3** — you may not *"copy, adapt, alter, translate, modify or make derivative works
  based on the Platforms and/or any other of our or Spamhaus' intellectual property,
  without the express consent of abuse.ch and/or Spamhaus"*.
- **§7.3** — *"Data or Confidential Information may not be used by users to customise,
  train, or otherwise improve any artificial intelligence model or product … without
  Spamhaus' express prior written consent."*
- **§3** — free access is bounded by fair use: *"Query Volume Limits, and file Export Volume
  Limits, defined as volumes of Queries and Exports reasonably expected for non-commercial
  or non-profit purposes"*.
- **§4.1** — commercial or for-profit use *"may require a paid subscription, which will be
  managed by Spamhaus"*.
- **§3.4** — Feodo Tracker, SSL Blacklist and YARAify are explicitly CC0 and exempt from the
  above. ThreatFox and URLhaus are **not** in that list.

Consequences, recorded in `decisions/0007-publication-boundary.md`:

- An operator may ingest locally with their own key for their own analysis. The repository
  ships code, not data.
- **No ThreatFox/URLhaus-derived indicator value is published** — not as a demo dataset, not
  as a sample in the test suite, not in a label file. Publishing a per-indicator score would
  embed the indicator, which is exactly the redistribution §7.3 restricts.
- Published evaluation artifacts carry **aggregate metrics and the sampling rule**, never
  the labelled indicator values. A salted hash is not a safe substitute: an IPv4 address is
  small enough to enumerate, so the hash is reversible. `docs/methodology.md` promises
  reproducibility; for restricted sources the honest version is "same protocol, own sample",
  and the report says so.
- No model training on the data. Not a constraint today (Phase 1 has no LLM), but recorded so
  it stays one.

Operational notes:

- One Auth-Key covers URLhaus, ThreatFox and MalwareBazaar. Feodo Tracker needs no key at
  all — its blocklist is served openly.
- **Local fair-use guard** (`collectors/throttle.py`): the CLI records the last successful
  fetch per source in `data/state/last_fetch.json` and refuses a second one inside the
  minimum interval (default one hour). The state file is operational, not evidence: losing
  it never invalidates a collection. `--min-interval 0` exists for deliberate one-offs and
  `--force` does **not** bypass the guard.
- **ThreatFox retention**: IOCs older than 6 months are no longer served (policy from
  2025-05-01). This is a hard freshness floor — the pipeline cannot assume a stable history,
  and aging rules must not be calibrated against data the source silently drops.
- **ThreatFox endpoint** (`verified 2026-11-23`): `POST https://threatfox-api.abuse.ch/api/v1/`
  with header `Auth-Key` and body `{"query": "get_iocs", "days": N}`, `1 <= N <= 7`.
  `query_status` is `ok` or `no_result`. `ioc_type` values handled: `domain`, `url`,
  `ip:port`, `md5_hash`, `sha1_hash`, `sha256_hash`. Timestamps are
  `YYYY-MM-DD HH:MM:SS UTC`. Because the key travels in a header and the body is a POST,
  nothing credential-bearing appears in a URL, which is why this source could ship before
  URLhaus.
- The Hunting API publishes a **false-positive list**. It is a useful rule input (FP-03) and,
  for that reason, not a valid label for items that rule touches.
- **URLhaus** (`verified 2026-11-23` for the export URL) embeds the Auth-Key in the URL
  path (`/v2/files/exports/<KEY>/recent.csv`). A key in a URL ends up in exception messages,
  proxies, and any log that records the request line — a direct conflict with T5. The
  redaction design is now implemented in `collectors/urlhaus.py`:
  - redirects are refused rather than followed;
  - no error message interpolates the URL, only the HTTP status;
  - transport failures are re-raised with `from None`, dropping the chained httpx exception
    whose text contains the URL;
  - `_meta.json` stores the endpoint with `<KEY>` and the write is refused if the key appears
    in the serialized metadata;
  - the key is validated as a bare path segment (no `/`, `.`, `?`) before it is interpolated.
- **URLhaus export shape** (`verified 2026-11-23`, live run): `HTTP 200`,
  `content-type: text/plain`, 26,813,013 bytes, 103,814 data rows. Columns:
  `id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter`.
  The body opens with a `#` comment banner and **comments out its own header line**
  (`#id,dateadded,...`), so a plain `csv.DictReader` mistakes the banner for a one-column
  header and never sees the real columns. `parse_export` finds the header by shape — every
  comma-separated token must look like a column name and at least two required columns must
  be present — which a data row cannot satisfy (numeric `id`, timestamped `dateadded`, a URL
  with a scheme). `parse_export` is shared with the normalizer so the ingest gate and the
  silver mapping read the same bytes the same way.
- **URLhaus contents** (same run): `url_status` is `online` (79,619) or `offline` (24,195);
  `last_online` is empty for 2,332 rows; `dateadded` spans roughly 30 days
  (oldest 2026-10-23 21:02 UTC). Ten rows carry URLs the normalizer rejects (unsupported
  scheme or no host); they are rejected individually, not fatally. 103,804 unique normalized
  URLs survive, and **122 of ThreatFox's 494 URLs are corroborated exactly**. Because
  ThreatFox and URLhaus are both abuse.ch properties, that overlap is not independent
  corroboration; it is the defect `rules.md` §3 records, and it is the whole `medium` band of
  the current run.
- Because the recent-URL window is about 30 days and the URL TTL is 30 days, the oldest tail
  of the export sits exactly on the FP-04 boundary, and how many rows cross it depends on the
  hour of the run. The 2026-11-23 snapshot scored at 10:45 UTC had 99 stale URL rows; the
  same silver scored at 00:00 UTC had none. Both are correct readings of the rule at their
  clock, and neither is a measurement of the rule's accuracy. A rule whose firing count moves
  by 99 rows inside one day is a rule whose *evaluation* needs a fixed clock.
- **A second export changes that for `url`.** URLhaus documents a **full dump** containing
  URLs that are either actively distributing malware or were added within the past **90
  days**, alongside the 30-day `recent.csv`. The full dump is not a historical archive — it is
  still one rolling window — but a 90-day window against a 30-day TTL puts a large, stable
  population past the boundary. That makes FP-04's mechanism measurable for `url` without
  waiting 35 days, and it is the reason the full dump is the planned input for the next
  collection change. The 30-day export stays available for comparisons.
- The normalizer maps one row to one URL indicator. `url_status`, `threat` and `reporter`
  are attributes; tags combine the `tags` column with `threat`; the submitter stays inside
  the `reporter` attribute and `distinct_reporters` remains 1, because URLhaus is one feed
  and counting submitters as independent sources is the echo problem in disguise.
- **Feodo endpoint** (`verified 2026-11-23`):
  `GET https://feodotracker.abuse.ch/downloads/ipblocklist.json`, no key, a JSON **array**.
  Entry fields observed: `ip_address, port, status, hostname, as_number, as_name, country,
  first_seen, last_online, malware`. `status` is `online` or `offline`. `first_seen` is a
  full `YYYY-MM-DD HH:MM:SS` in UTC; the live export serves `last_online` as a bare
  `YYYY-MM-DD` (verified 2026-11-23), so the normalizer accepts both and treats a bare date
  as midnight UTC. The same IP appears once per open port, so the normalizer
  groups by IP, keeps `ports` as an attribute, and calls the host `online` if any entry is.
  An empty array is legitimate — the provider prunes the list, so zero entries is a fact
  about the botnets, not a broken feed. Note that "listed" is not "currently active": on
  the 2026-11-23 snapshot every entry's `last_online` was months old, which is exactly what
  FP-04 exists to surface.

### Historical depth (unconfirmed)

The pipeline needs multi-day history to evaluate an ageing rule, and the providers do not
offer it:

- **ThreatFox** serves a 1–7 day query window and removes IOCs older than six months. No
  public historical snapshot archive was found — not from abuse.ch and not from a credible
  third party whose licence and provenance could be cited.
- **URLhaus** regenerates its exports every five minutes over rolling windows (30 days,
  90 days, active-only). No archive of past windows was found.
- A third-party mirror may exist; importing one would require confirmed provenance and
  licence, and **none was confirmed**. The honest position is that continuity of evidence is
  something this project has to create by collecting on a schedule and pinning each
  collection, not something it can download.
- Consequence for the roadmap: FP-04's *mechanism* is tested with a synthetic multi-day
  fixture; its *measurement* waits until the project has collected enough days itself, or
  until a licence-clean archive is found and recorded here.

### AbuseIPDB

Documented 2026-11-23 at <https://docs.abuseipdb.com/>. The site terms link returned 404 at
review time, so **every statement about permission is unconfirmed**; only endpoint shapes and
documented quotas are recorded here.

- Crowd-sourced: the confidence score is a function of reports, not of ground truth. A single
  reporter can move an IP; a shared VPN egress accumulates reports from many unrelated
  incidents. `numDistinctUsers` is the closest the API comes to saying how many humans are
  behind the score, and it is still not independence.
- Limits (documented, plan-specific): `check` 1,000 requests/day, `blacklist` 5 requests/day,
  blacklist `limit` capped at 10,000. A per-minute limit is not documented. The documentation
  names a "Standard" tier and does not state that it equals the free tier.
- Fields on `check`: `abuseConfidenceScore`, `usageType`, `domain`, `isWhitelisted`,
  `numDistinctUsers`, `totalReports`, `lastReportedAt`, and `reports[]` only with `verbose`.
  `blacklist` returns IP, score and last-report time — no reports array.
- **Batch before per-item, as the policy says.** The blacklist is one request for many
  indicators; `check` is for a deliberate sample, not for the population.
- `usage_type` (residential / datacenter / VPN) is genuinely useful for FP-07 and is not
  available from most other free sources. It is the main reason this source is on the list.
- **Planned role: baseline comparator, not scoring input.** If the source lands, its
  `abuseConfidenceScore` is evaluated as a competing score — "how much precision does this
  pipeline add over the number the source already publishes?" — and is not a weight in the
  policy. A feed's own confidence in its own reports is exactly the kind of self-referential
  input `methodology.md` §7 rules out as a label.
- **Redistribution is the open question.** The score may be publishable; the report list
  probably is not. Nothing from this source is committed or published until the terms are
  read and the conclusion recorded in the status column above.

### Tranco

Documented 2026-11-23 at <https://tranco-list.eu/>.

- One million domains, updated daily and available by 00:00 UTC. Lists have **permanent ids**,
  and past versions are retrievable, which is what makes a popularity check reproducible:
  pin the id, record it in the run manifest, and the same list can be fetched again.
- Download frequency is not restricted in the documentation. The pipeline still fetches once
  per scoring run and caches the file.
- **Licence/redistribution unconfirmed.** Cite the list id; do not commit the list. A check
  against it can be published as a boolean per domain only if the licence permits derived
  output — the conservative reading is that it does not, so a Tranco-derived annotation has
  to be reported as a rule outcome, not as a copied rank.
- **Asymmetry that motivates the planned rule.** For a `domain` indicator, the unit is the
  whole name, so popularity argues the *domain* is benign and someone reported a malicious
  URL hosted on it. For a `url` indicator, the unit is the path, so a popular host and a
  malicious path can coexist: the finding is **`collateral_risk`**, an annotation, and it
  does not lower the score. A single popularity rule applied to both types would either
  suppress real malicious paths on popular hosts or fail to suppress compromised-domain
  noise.
- Provider-side evidence that the asymmetry is real: URLhaus publishes RPZ and hostfile
  variants that **exclude hostnames under the Tranco top-1M**, to reduce false positives. That
  is an operator choosing a different trade-off for the same data, and it is worth citing
  rather than reinventing.
- This is **not** a defined rule. `FP-11` is not in the repository; see the frozen catalogue
  in [`rules.md`](rules.md).

### GreyNoise Community

- Responds whether an IP is `noise` (mass scanning) or `RIOT` (benign service, e.g. a
  crawler). This is exactly the distinction the project needs, and it is also a signal a
  rule consumes.
- Rate limit is severe. Budget a handful of lookups per run, cache aggressively, and
  never use it in a loop over a feed.
- Same circularity caveat as everyone else: RIOT is an input to FP-01, so RIOT alone
  cannot confirm a `benign` label.

### NVD / OSV

- Metadata only, for CVE → affected product mapping. Neither is an exploitation signal;
  that is what KEV is for. Keeping that distinction explicit prevents the classic
  "CVE published ⇒ threat" error.

## Verification checklist (per source, before its collector is written)

- [ ] Read the current terms of use and note the date read.
- [ ] Confirm the authentication requirement and how a key is provisioned.
- [ ] Confirm the documented rate limits and quotas for the free tier.
- [ ] Confirm the bulk/export endpoint exists and its format.
- [ ] Confirm whether derived data may be published, and under what attribution.
- [ ] Confirm the retention window the provider applies to its own data.
- [ ] Record: endpoint allowlist, page/size limits, fields actually available.
- [ ] Update the row above to `verified YYYY-MM-DD` and link the terms page.

## Collection principles (enforced in code, not by discipline)

- **Host allowlist per source.** Built from the provider's documented domain, not from a
  URL found in a feed. Redirects that leave the allowlist abort the request.
- **Timeout and size cap on every request.** A feed returning 2 GB is an incident, not a
  windfall.
- **Request budget per run** (`--max-requests`), so a bug cannot exhaust a quota.
- **TTL cache** for per-indicator lookups, keyed by indicator and lookup type.
- **Idempotent writes.** Re-running a collector for the same collection date overwrites
  the same bronze partition instead of appending duplicates.
- **`collected_at` in UTC**, distinct from the provider's `first_seen`/`last_seen`.
- **No credentials in logs, errors, or exception traces.** A provider key in a traceback
  is a leaked key.

## What this project will not do

- Scrape HTML pages that have no documented feed.
- Follow links found inside feed content.
- Use a key that is not the operator's own.
- Publish raw payloads, sample binaries, or full dumps.
- Assume a source is honest because it is popular.
