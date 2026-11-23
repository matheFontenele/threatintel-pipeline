"""Shared test fixtures. Nothing here touches the network or the real data directory."""

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def kev_payload_bytes() -> bytes:
    return (FIXTURES / "kev_sample.json").read_bytes()


@pytest.fixture
def kev_payload(kev_payload_bytes: bytes) -> dict:
    import json

    return json.loads(kev_payload_bytes)


@pytest.fixture
def threatfox_payload_bytes() -> bytes:
    return (FIXTURES / "threatfox_sample.json").read_bytes()


@pytest.fixture
def threatfox_payload(threatfox_payload_bytes: bytes) -> dict:
    import json

    return json.loads(threatfox_payload_bytes)
