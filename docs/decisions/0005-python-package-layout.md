# 0005 — Python package layout under `src/threatintel/`

- Status: accepted
- Date: 2026-11-23
- Supersedes: —

## Context

The initial layout sketch put modules directly under `src/`: `src/collectors/`,
`src/api/`, `src/normalize/`, and so on. That produces top-level import names — `api`,
`normalize`, `scoring` — which are generic enough to collide with any dependency that
happens to use the same name, and it is not installable as a package without fighting
setuptools.

## Decision

Use a standard src layout with a single distribution package:

```
src/threatintel/
├── collectors/
├── normalize/
├── fp_rules/
├── enrich/
├── scoring/
├── api/
└── dashboard/
```

Imports are `from threatintel.fp_rules import ...`; tests import the installed package.
`pyproject.toml` declares `package-dir = {"" = "src"}` and discovers packages there.

## Consequences

### Positive

- No namespace collision, which matters the moment `httpx` or `pydantic` grows a module
  called `api`.
- `pip install -e ".[dev]"` works, so tests run against the same import path a user gets.
- Rule files stay one-per-file, one-per-rule, without needing a package `__init__` export
  list to keep them discoverable.

### Negative

- One extra path segment in every import; negligible.
- Diverges from the layout sketch in the original plan document. Recorded here so the
  difference is deliberate rather than drift.

### Accepted cost

None worth noting.

## Revisit if

The API is split into its own distribution (e.g. to keep the FastAPI dependency out of
collector installs). The package would then become `threatintel-core` + `threatintel-api`,
which is a real boundary and not a layout preference.
