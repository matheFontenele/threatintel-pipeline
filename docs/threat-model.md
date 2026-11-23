# Threat model

What this project protects, from whom, and — just as important — what it does not
protect at all.

## First, the honest scope statement

This project is **not** a runtime defence. It does not sit in a network path, it does
not block traffic, and it does not claim any coverage of a real environment. It
produces a prioritized list of indicators, each with the reasons behind its score.

The thing that can actually be damaged is therefore not a user's network. It is:

- the **correctness of the output** (a wrong ranking wastes an analyst's morning), and
- the **credibility of the published evaluation** (a metric that cannot be reproduced
  is worse than no metric).

Most of the threats below are about those two, not about intrusion.

## Assets

| Asset | Why it matters if compromised |
|---|---|
| Hand-labeled evaluation set (`eval/labeled_sample/`) | It is the only ground truth; tampering or leakage invalidates every published metric |
| Published metrics and methodology | The portfolio claim. If it cannot be reproduced, the project argues against itself |
| Source credentials (`.env`, environment) | Abuse of the operator's quota and identity against the feed providers; possible ToS termination |
| Integrity of bronze data | Everything downstream is derived from it; silent corruption breaks reproducibility |
| The operator's local machine | Collectors fetch and parse third-party payloads |
| Third-party data handling obligations | Each feed has redistribution terms; breaching them is a legal problem, not a technical one |

## Actors

| Actor | Capability | Motivation |
|---|---|---|
| Feed poisoning / spam submitter | Can get arbitrary values into a collaborative feed (AbuseIPDB reports, URLhaus submissions) | Make a competitor's IP look malicious; bury a real one under noise |
| Opportunistic scanner of public repos | Reads everything published, greps for keys, credentials, internal hostnames | Free access, easy targets |
| Supply-chain attacker | Compromises a Python dependency or a feed's TLS endpoint | Code execution on the operator's machine |
| The operator, tired | Runs a collector with a stale allowlist, commits `.env`, samples labels non-randomly | Convenience over rigour |
| A future contributor | Adds a rule, changes weights, does not re-run the evaluation | Good intentions, invalid metric |

Note the last two. In a solo project the most likely source of a wrong result is not an
adversary — it is an unreviewed shortcut.

## Trust boundaries

```
 untrusted                      semi-trusted                    trusted
┌──────────────┐   B1   ┌────────────────┐   B2   ┌───────────────┐   B3   ┌────────┐
│ public feeds │ ─────► │ bronze (raw)   │ ─────► │ silver / gold │ ─────► │  API   │
└──────────────┘        └────────────────┘        └───────────────┘        └────────┘
                                                                             │ B4
                                                                             ▼
                                                                     consumers
```

- **B1 — feed → bronze.** Every byte is attacker-controlled. Validation, size limits,
  domain allowlist, no redirects off-allowlist, no interpretation of content.
- **B2 — raw → normalized.** Parsing defects become data defects here. Schema
  validation is the only thing standing between a malformed feed and a wrong score.
- **B3 — store → API.** Read-only. The API never queries bronze, and consumers never
  query the store.
- **B4 — API → consumer.** Output is data too: an indicator value that renders as
  HTML/CSV is an injection vector for whoever consumes it.

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | **Malicious payload in a feed field** — oversized values, control characters, CSV/HTML formula injection, values crafted to break a parser | Strict per-field validation (type, length, charset), never `eval`/`exec`, never build shell commands from feed data, escape on output, reject rather than coerce | A novel encoding slips past validation and lands in a dashboard |
| T2 | **SSRF via a feed-provided URL** — a URL field points at `169.254.169.254` or an internal host, and a collector follows it | Fixed per-source base URLs; host allowlist; redirects only to allowlisted hosts; enrichment lookups never follow attacker-supplied links | Allowlisted provider itself is compromised |
| T3 | **Poisoned source skews the ranking** — a single submitter floods reports, or one feed is wrong about many IPs | Corroboration requires *independent* sources (different operator, not a mirror); single-source indicators cannot reach the top class; source-level precision tracked over time | Coordinated poisoning across two providers is out of reach at this scale, and is stated as a limitation |
| T4 | **Stale indicator presented as current** — a 2-year-old IP reported once still scores high | Age decay per indicator type; `last_seen` and `collected_at` always published; indicators past TTL cannot be `active_exploitation` | Age decay weights are initial hypotheses until calibrated |
| T5 | **Credential leak** — `.env` committed, key in a fixture, key in a log line | `.env` gitignored, `.env.example` empty, secrets scan before every push, collectors never log headers, no real key in any test | A key pasted into a commit message or an issue |
| T6 | **Restricted data redistributed** — raw payloads or full feed dumps committed, violating ToS | `data/` and `snapshots/` gitignored; the repo publishes code, schema and *labels*; `docs/sources.md` records each source's terms and status; no collector ships before its row is verified | Label files may reveal indicator values — reviewed per source before publishing |
| T7 | **Dependency compromise** | Pinned lockfile, `pip-audit` in CI, minimal dependency set, no dependency for something 20 lines can do | Transitive dependency compromise inside the trust window |
| T8 | **Metric inflation / circular evaluation** — rules validated by the very signal they consume | Hand-labeled set is the only truth for metrics; rules that use a signal are evaluated against labels, not against the signal; per-rule ablation; failure cases published | Labeler bias — mitigated by double-labeling a subset, not eliminated |
| T9 | **Quota burn / cost** — a bug loops a collector and exhausts a free tier or gets the key blocked | Batch endpoints first, request budget per run, TTL cache for per-IP lookups, dry-run mode, explicit `--max-requests` | Provider lowers a quota without notice |
| T10 | **Privacy of IP data** — public indicators, or honeypot logs, expose personal data | Only public indicator values are published; no honeypot in the current scope; if it ever lands: isolation, minimum retention, documented retention period, no payload capture | IP addresses can be personal data under LGPD even when public |
| T11 | **Silent behaviour change** — weights or rules edited without re-running the evaluation, so the published metric no longer describes the code | Evaluation config hashed and published with results; `run_eval.py` fails if the hash does not match the reported one | Requires discipline until CI enforces it |

## Non-goals

Explicitly out of scope, so that silence is not read as coverage:

- detecting attacks in network traffic, endpoints or logs;
- attribution;
- protecting any real environment, including the operator's;
- guaranteeing freshness of a third-party feed;
- malware analysis beyond metadata;
- storing or redistributing feed payloads;
- acting as a general CVE database.

## Assumptions

1. Public feeds are wrong sometimes, and wrong in correlated ways. The design assumes
   this rather than trying to fix it.
2. Volume is small (tens of thousands of indicators per day), so batch processing with
   a single writer is sufficient. If that assumption breaks, the storage decision is
   revisited (see `decisions/0003`).
3. The operator is the only writer. Multi-user operation would change both the storage
   and the review model.
4. No output of this project is safe to act on without a human decision when it is
   classed `needs_review`. The class exists precisely because the system does not know.
