"""CLI: serve the read-only API.

There is no authentication in Phase 1, so the default bind is loopback and exposing the
service is an explicit act with a warning. The warning is not a control — an operator who
needs remote access should put the service behind an authenticating proxy
(`docs/api.md`).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from threatintel.api.app import create_app
from threatintel.api.store import GoldStoreError

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the read-only threat-intel API.")
    parser.add_argument(
        "--gold",
        type=Path,
        default=Path("data/gold/indicators.parquet"),
        help="scored table to serve (copied into memory at startup)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not args.gold.is_file():
        print(f"gold table not found: {args.gold}", file=sys.stderr)
        print("run `make gold AS_OF=...` first", file=sys.stderr)
        return 1
    if args.host not in LOOPBACK_HOSTS:
        print(
            f"warning: no authentication in Phase 1; binding {args.host} puts every "
            "indicator on the network. Use an authenticating proxy.",
            file=sys.stderr,
        )

    try:
        app = create_app(args.gold)
    except GoldStoreError as exc:
        print(f"cannot serve gold: {exc}", file=sys.stderr)
        return 1

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
