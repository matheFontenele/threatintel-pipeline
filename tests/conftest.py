"""Shared test fixtures. Nothing here touches the network or the real data directory."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def kev_payload_bytes() -> bytes:
    return (FIXTURES / "kev_sample.json").read_bytes()


@pytest.fixture
def kev_payload(kev_payload_bytes: bytes) -> dict:
    return json.loads(kev_payload_bytes)


@pytest.fixture
def threatfox_payload_bytes() -> bytes:
    return (FIXTURES / "threatfox_sample.json").read_bytes()


@pytest.fixture
def threatfox_payload(threatfox_payload_bytes: bytes) -> dict:
    return json.loads(threatfox_payload_bytes)


@pytest.fixture
def feodo_payload_bytes() -> bytes:
    return (FIXTURES / "feodo_sample.json").read_bytes()


@pytest.fixture
def feodo_payload(feodo_payload_bytes: bytes) -> list[dict]:
    return json.loads(feodo_payload_bytes)


@pytest.fixture
def urlhaus_payload_bytes() -> bytes:
    return (FIXTURES / "urlhaus_sample.csv").read_bytes()
