"""Read-only HTTP API over the gold table (`decisions/0009`).

The contract is the product: consumers read indicators and aggregates over JSON, and never
open the Parquet file or a database handle (threat model B3). The service is deliberately
small — five endpoints over two tables, one store each, no writes — because every capability
added here is a capability a consumer will depend on.

Two choices keep the output honest:

- every indicator and aggregate response carries the run metadata (`as_of` and both config
  hashes), so a result can be tied to the snapshot that produced it;
- errors are an envelope with a stable code, not a prose `detail`, so a consumer can branch
  on `invalid_cursor` without parsing English.

The API is JSON only. It does not render HTML, does not set CORS, and binds to loopback by
default; the threat model's B4 boundary is an escaping obligation on the consumer, and the
security headers state that the body is not a document.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, Query, Request
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from threatintel.api.models import (
    Detail,
    Health,
    Page,
    Stats,
    VulnPage,
)
from threatintel.api.store import (
    Cursor,
    GoldStore,
    GoldStoreError,
    InvalidCursor,
)
from threatintel.api.vuln_store import VulnCursor, VulnStore

logger = logging.getLogger(__name__)

IndicatorTypeName = Literal["ip", "domain", "url", "hash"]
BandName = Literal["high", "medium", "low"]

API_VERSION = "1.0.0"


class ApiError(Exception):
    """An error with a stable machine code and an HTTP status."""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def _error(status_code: int, code: str, message: str, **extra: Any) -> JSONResponse:
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    body["error"].update(extra)
    return JSONResponse(status_code=status_code, content=body)


def create_app(gold_path: Path, vuln_path: Path | None = None) -> FastAPI:
    """Build the app around one run of both tables. Missing data fails at startup.

    `vuln_path` defaults to `vulnerabilities.parquet` next to the gold file: the two outputs
    are written by one scoring run and served by one process, so splitting them across
    directories would make it possible to serve mismatched clocks.
    """
    store = GoldStore(gold_path)
    if vuln_path is None:
        vuln_path = gold_path.with_name("vulnerabilities.parquet")
    vuln_store = VulnStore(vuln_path)

    app = FastAPI(
        title="Threat Intel API",
        version=API_VERSION,
        summary="Explainable, scored threat indicators, plus a vulnerability catalogue.",
        description=(
            "Read-only API over two tables from one run: ranked indicators (score, band, "
            "reason codes) and the KEV catalogue (facts, no score). Every response carries "
            "the run clock and, for indicators, both configuration hashes; see "
            "`docs/api.md` for the contract and the security posture. Consumers never read "
            "the store directly."
        ),
    )
    app.state.store = store
    app.state.vuln_store = vuln_store

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
        return _error(exc.status_code, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        fields = [
            {
                "location": ".".join(str(part) for part in error["loc"]),
                "message": error["msg"],
            }
            for error in exc.errors()
        ]
        return _error(422, "validation_error", "request validation failed", fields=fields)

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(
            exc.status_code, "http_error"
        )
        return _error(exc.status_code, code, str(exc.detail))

    @app.exception_handler(GoldStoreError)
    async def gold_error_handler(request: Request, exc: GoldStoreError) -> JSONResponse:
        logger.error("gold read failed: %s", exc)
        return _error(503, "gold_unavailable", "the scored table is not readable")

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {
            "name": "Threat Intel API",
            "version": API_VERSION,
            "docs": "/docs",
            "openapi": "/openapi.json",
            "health": "/health",
        }

    @app.get("/health", response_model=Health, tags=["meta"])
    def health() -> dict[str, Any]:
        """Liveness plus the number of rows the process has pinned, per track."""
        payload = store.health()
        payload.update(vuln_store.health())
        return payload

    @app.get("/v1/indicators", response_model=Page, tags=["indicators"])
    def list_indicators(
        indicator_type: Annotated[IndicatorTypeName | None, Query(alias="type")] = None,
        band: Annotated[BandName | None, Query()] = None,
        min_score: Annotated[int | None, Query(ge=0, le=100)] = None,
        max_score: Annotated[int | None, Query(ge=0, le=100)] = None,
        reason: Annotated[str | None, Query(pattern=r"^[A-Z0-9_]{3,40}$")] = None,
        source: Annotated[str | None, Query(pattern=r"^[a-z0-9_]{2,40}$")] = None,
        needs_review: Annotated[bool | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
    ) -> dict[str, Any]:
        """One page of scored indicators, highest score first.

        Ordering is `(score DESC, id ASC)`. The id tiebreaker is what makes the cursor stable
        without putting an indicator value in the URL.
        """
        key = None
        if cursor is not None:
            try:
                key = Cursor.decode(cursor)
            except InvalidCursor as exc:
                raise ApiError(400, "invalid_cursor", str(exc)) from exc

        items, next_cursor = store.list_indicators(
            indicator_type=indicator_type,
            band=band,
            min_score=min_score,
            max_score=max_score,
            reason=reason,
            source=source,
            needs_review=needs_review,
            limit=limit,
            cursor=key,
        )
        return {
            "run": store.run_meta(),
            "items": items,
            "next_cursor": next_cursor,
            "limit": limit,
        }

    @app.get("/v1/indicators/{indicator_id}", response_model=Detail, tags=["indicators"])
    def get_indicator(
        indicator_id: Annotated[str, ApiPath(min_length=1, max_length=64)],
    ) -> dict[str, Any]:
        """One indicator with its full reason list, source references and attributes."""
        indicator = store.get_indicator(indicator_id)
        if indicator is None:
            raise ApiError(404, "not_found", "indicator not found")
        return {"run": store.run_meta(), "indicator": indicator}

    @app.get("/v1/vulnerabilities", response_model=VulnPage, tags=["vulnerabilities"])
    def list_vulnerabilities(
        ransomware: Annotated[bool | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
    ) -> dict[str, Any]:
        """One page of the KEV catalogue, `date_added DESC` then `cve_id ASC`.

        There is no score here on purpose. A vulnerability's priority is a function of an
        estate this service knows nothing about, so the row carries the catalogue's facts
        and stops; a consumer with asset context ranks them itself.
        """
        key = None
        if cursor is not None:
            try:
                key = VulnCursor.decode(cursor)
            except InvalidCursor as exc:
                raise ApiError(400, "invalid_cursor", str(exc)) from exc

        items, next_cursor = vuln_store.list_vulnerabilities(
            ransomware=ransomware,
            limit=limit,
            cursor=key,
        )
        return {
            "run": vuln_store.run_meta(),
            "items": items,
            "next_cursor": next_cursor,
            "limit": limit,
        }

    @app.get("/v1/stats", response_model=Stats, tags=["meta"])
    def stats() -> dict[str, Any]:
        """Band distribution, review count and reason-code counts for the whole run."""
        aggregates = store.stats()
        aggregates["vulnerabilities"] = vuln_store.stats()
        return {"run": store.run_meta(), **aggregates}

    return app


__all__ = ["ApiError", "create_app"]
