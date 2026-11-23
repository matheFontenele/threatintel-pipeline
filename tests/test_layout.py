"""Smoke test for the package layout (see docs/decisions/0005).

Proves the installed distribution exposes the subpackages the pipeline will fill in,
so an import-path mistake is caught here rather than in the first collector.
"""

import importlib

import pytest

SUBPACKAGES = [
    "collectors",
    "normalize",
    "fp_rules",
    "enrich",
    "scoring",
    "api",
    "dashboard",
]


@pytest.mark.parametrize("name", SUBPACKAGES)
def test_subpackage_importable(name: str) -> None:
    module = importlib.import_module(f"threatintel.{name}")
    assert module.__name__ == f"threatintel.{name}"
