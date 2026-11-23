# eval/

The only directory whose *data* may be versioned — and, for restricted sources, it is not.
See `docs/decisions/0007-publication-boundary.md` before adding anything here.

Rules:

- **Labels only.** No raw feed payloads, no source dumps, no binaries.
- **CSV, not Parquet.** Labels are reviewed in a diff; a binary format hides the change.
- One file per label-set version (`v1.csv`), never edited in place after a test run
  (see `docs/methodology.md` §6).
- Columns: `type`, `value`, `snapshot_id`, `label`, `evidence`, `justification`,
  `labeler`, `labeled_at`, plus `second_label` / `second_labeled_at` on the
  double-labeled subset.
- **Restricted-source labels stay local.** A row whose `value` came from ThreatFox,
  URLhaus or another source that forbids derivative works is not committed. The local
  file is kept out of git by `.gitignore`; the published artifact is the metric table plus
  the sampling rule and config hash, not the labelled indicators. KEV-derived rows may be
  published: KEV is a public-domain government work product and CVE ids are public.
- Fixtures anywhere in the repository use documentation values only (RFC 5737 / RFC 3849
  addresses, RFC 2606 domains), enforced by `tests/test_publication_boundary.py`.

`run_eval.py` lives here too and is the only supported way to produce a published number.
