"""Read-only HTTP API over the scored gold table.

The API is the only read path for consumers: they never open the Parquet file or a database
handle (threat model B3, `docs/decisions/0009`). It is JSON only, serves one scored run per
process, and carries the run clock and both configuration hashes in every response.

Run it with `make api` or `python -m threatintel.api`; the contract is in `docs/api.md`, and
the generated OpenAPI document is at `/openapi.json`.
"""

from threatintel.api.app import ApiError, create_app

__all__ = ["ApiError", "create_app"]
