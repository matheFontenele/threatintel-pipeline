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
| 1 | **CISA KEV** | CVEs with known exploitation in the wild | none | public JSON/CSV | daily | public domain work product — verify | `unverified` |
| 2 | **abuse.ch — URLhaus** | malicious URLs, payload hashes | Auth-Key (free) | bulk export + API | daily | non-commercial, attribution required — verify | `unverified` |
| 3 | **abuse.ch — ThreatFox** | IOCs (IP/domain/URL/hash) with malware family | Auth-Key (free) | API + export; drops IOCs older than 6 months (from 2025-05-01) | daily | same as above | `unverified` |
| 4 | **abuse.ch — Feodo Tracker** | botnet C2 IPs | Auth-Key (free) | bulk export | daily | same as above | `unverified` |
| 5 | **abuse.ch — MalwareBazaar** | malware samples, hashes | Auth-Key (free) | API | weekly, metadata only | same as above | `unverified` |
| 6 | **AbuseIPDB** | crowd-sourced IP abuse reports, confidence score, usage type, blacklist | API key (free tier) | low daily quota; blacklist capped (~10k entries reported) | daily blacklist | restricted — check explicitly | `unverified` |
| 7 | **GreyNoise Community** | IP classification: `noise`, `RIOT` | API key | very low rate limit | on-demand, ≤ tens of IPs per run | check | `unverified` |
| 8 | **NVD** | CVE metadata, CVSS | optional key | 5 req/30 s without key, higher with | weekly, CVE metadata only | public domain | `unverified` |
| 9 | **OSV** | package vulnerabilities | none | query API | on-demand | CC-BY-4.0 style — verify | `unverified` |

Ingestion order is deliberate: 1 → 2/3/4 → 6 → 7. KEV first because it is small,
authoritative, credential-free and immediately useful for a demo. GreyNoise last because
its limits make it enrichment, never bulk scoring.

## Per-source notes

### CISA KEV

- Catalogue of CVEs with confirmed exploitation. Small (order of 10^3), stable identifiers,
  public JSON and CSV.
- **What it means**: exploitation observed *somewhere*, published. Not "affects you" and
  not "is being exploited right now". The scoring must say which of the two it claims.
- Used as a priority signal (FP-10 in the plan), and — because that makes it a rule input —
  it cannot serve as a label source for its own stratum (see `methodology.md` §7).

### abuse.ch

- One Auth-Key covers URLhaus, ThreatFox, MalwareBazaar and Feodo Tracker. Key is free and
  mandatory for API use.
- **ThreatFox retention**: IOCs older than 6 months are no longer served (policy from
  2025-05-01). This is a hard freshness floor — the pipeline cannot assume a stable
  history, and aging rules must not be calibrated against data the source silently drops.
- The Hunting API publishes a **false-positive list**. It is a useful rule input (FP-03)
  and, for that reason, not a valid label for items that rule touches.
- Terms are non-commercial with attribution. Verify before publishing anything derived.

### AbuseIPDB

- Crowd-sourced: confidence score is a function of reports, not of ground truth. A single
  reporter can move an IP; a shared VPN egress accumulates reports from many unrelated
  incidents.
- Free tier is small. Use the **blacklist** endpoint (one request, many indicators), not
  per-IP checks, for anything resembling bulk.
- `usage_type` (residential / datacenter / VPN) is genuinely useful for FP-07 and is not
  available from most other free sources.
- **Redistribution is the open question.** The score may be publishable; the report list
  probably is not. Decide by reading the terms, record the date and the conclusion.

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
