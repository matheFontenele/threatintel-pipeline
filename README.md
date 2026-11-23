# Threat Intel Pipeline

Turns public threat feeds into a small, ranked set of indicators worth acting on —
with every decision explained.

Public feeds are noisy by design: they report scanning, botnets, shared VPN egress and
legitimate crawlers with the same vocabulary they use for real attacks. This project
normalizes indicators from several feeds, applies **explainable false-positive rules**,
and produces a score that always ships with its reasons.

It is built as a portfolio project in detection / threat-intel engineering. The
interesting part is not the ingestion — it is the evaluation: knowing where the filter
works, where it does not, and being able to prove it.

> **Status: Week 0 — scaffold only.** The repository currently contains the design:
> threat model, source inventory, evaluation protocol and decision records. No
> collectors, no scoring, no API yet. Metrics below are intentionally empty until they
> are measured.

## Architecture

```mermaid
flowchart LR
    A[Public feeds] --> B[Collectors]
    B --> C[(Bronze<br/>raw, immutable)]
    C --> D[Normalize + dedupe]
    D --> E[(Silver<br/>indicators + FP reasons)]
    E --> F[Enrichment<br/>rDNS, ASN/CDN, noise]
    F --> G[(Gold<br/>scored + explained)]
    G --> H[API FastAPI]
    G --> I[Dashboard Streamlit]
    G --> J[Snapshot export]
    H --> K[Manual review]
    K --> L[Labeled set]
    L --> M[Evaluation]
```

## Design principles

1. **Mark, never discard.** False-positive rules annotate; they do not delete evidence.
2. **Explain or do not score.** Every score carries the codes that produced it.
3. **Evaluate against hand labels, not against the rules.** A filter validated only by
   the signal it was built from proves nothing.
4. **Public feeds are untrusted input.** Data, never instructions.
5. **No feed data in the repository.** Code and schema are public; each operator brings
   their own key.

## Evaluation

The central artifact. Protocol in [`docs/methodology.md`](docs/methodology.md).

| Metric | Value |
|---|---|
| Precision (test set) | not measured yet |
| Recall (test set) | not measured yet |
| False-positive rate per rule | not measured yet |
| Share of indicators sent to review | not measured yet |

These numbers will be published with the configuration that produced them, including
the cases where the filter fails.

## Documents

| Document | Contents |
|---|---|
| [`docs/threat-model.md`](docs/threat-model.md) | What this project protects, from whom, and what is out of scope |
| [`docs/methodology.md`](docs/methodology.md) | Labeling protocol, metrics, ablation, limitations |
| [`docs/sources.md`](docs/sources.md) | Feeds used, terms, limits, collection cadence |
| [`docs/decisions/`](docs/decisions/) | Short decision records with rationale |

## Stack

Python, DuckDB + Parquet for the analytical store, FastAPI for the read API,
Streamlit for the dashboard, pytest for tests. No server to operate; the whole
pipeline runs from a checkout.

Deliberate choice: no streaming infrastructure. Volume is measured in tens of
thousands of indicators per day, which a single-process batch job handles comfortably.
Kafka/Spark here would be engineering theater.

## Repository layout

```text
.
├── docs/               # threat model, methodology, sources, decisions
├── src/
│   └── threatintel/
│       ├── collectors/ # one module per source
│       ├── normalize/  # common indicator schema
│       ├── fp_rules/   # one rule per file, with a reason code
│       ├── enrich/
│       ├── scoring/
│       ├── api/
│       └── dashboard/
├── eval/
│   ├── labeled_sample/ # hand-labeled items (no restricted feed data)
│   └── run_eval.py
├── snapshots/          # generated exports (not versioned)
└── tests/
```

## Getting started

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # add your own feed credentials
```

Collectors, API and dashboard are not implemented yet. Commands will be documented as
each one lands.

## Scope

In scope: batch ingestion of a few public feeds, normalization, explainable
false-positive filtering, scoring with reasons, evaluation on a hand-labeled set,
read API, dashboard, review queue.

Out of scope for now: real-time streaming, network-traffic detection, paid feeds,
commercial product decisions.

## License

MIT — see [LICENSE](LICENSE). The separate tooling this project feeds into has its own
licensing discussion, tracked in the decision records.
