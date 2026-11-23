# eval/

The only directory whose *data* is versioned, because it is the only data this project
owns: hand-made labels, one row per `(type, value, snapshot_id)`.

Rules for what lands here:

- **Labels only.** No raw feed payloads, no source dumps, no binaries. If a source's
  terms restrict redistribution, the label file holds the indicator value and the
  human's decision — not the provider's record.
- **CSV, not Parquet.** Labels are reviewed in a diff; a binary format hides the change.
- One file per label-set version (`v1.csv`), never edited in place after a test run
  (see `docs/methodology.md` §6).
- Columns: `type`, `value`, `snapshot_id`, `label`, `evidence`, `justification`,
  `labeler`, `labeled_at`, plus `second_label` / `second_labeled_at` on the
  double-labeled subset.

`run_eval.py` lives here too and is the only supported way to produce a published
number.
