"""Enforces the publication boundary in `docs/decisions/0007`.

The policy "no feed-derived indicator values in the repository" is only real if a build
fails when someone pastes one into a fixture. This test scans the *indicator fields* of
every fixture — not free text, not documentation URLs — and requires documentation ranges.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from threatintel.normalize.threatfox import split_ip_port

FIXTURES = Path(__file__).parent / "fixtures"

# RFC 5737 / RFC 3849: the only numeric ranges a fixture may contain.
DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]
# RFC 2606: the only domain suffixes a fixture may contain.
DOC_SUFFIXES = (".example", ".test", ".invalid", ".example.com", ".example.org", ".example.net")

HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _check_ip(value: str) -> None:
    address = ipaddress.ip_address(value)
    if not any(address in network for network in DOC_NETWORKS):
        pytest.fail(f"fixture contains a real-looking IP, not a documentation range: {value!r}")


def _check_indicator(value: str) -> None:
    """Every fixture indicator must be a documentation value or a synthetic hash/CVE."""
    raw = value.strip()
    if HASH_RE.match(raw) or CVE_RE.match(raw):
        return
    if raw.startswith(("http://", "https://")):
        host = urlsplit(raw).hostname or ""
        _check_indicator(host)
        return
    host, _port = split_ip_port(raw)
    try:
        _check_ip(host)
        return
    except ValueError:
        pass
    lowered = host.lower().rstrip(".")
    if not lowered.endswith(DOC_SUFFIXES):
        pytest.fail(f"fixture contains a real-looking domain, not an RFC 2606 name: {value!r}")


def _threatfox_iocs() -> list[str]:
    payload = json.loads((FIXTURES / "threatfox_sample.json").read_text())
    return [entry["ioc"] for entry in payload["data"]]


def _kev_cve_ids() -> list[str]:
    payload = json.loads((FIXTURES / "kev_sample.json").read_text())
    return [entry["cveID"] for entry in payload["vulnerabilities"]]


def test_threatfox_fixture_values_are_documentation_only():
    iocs = _threatfox_iocs()
    assert iocs, "guard must not pass vacuously if the fixture loses its entries"
    for ioc in iocs:
        _check_indicator(ioc)


def test_kev_fixture_uses_public_cve_identifiers():
    cve_ids = _kev_cve_ids()
    assert cve_ids
    # CVE identifiers are public, and KEV is a public-domain government work product, so
    # these are the one category allowed to name a real entry (see decisions/0007).
    assert all(CVE_RE.match(cve_id) for cve_id in cve_ids)


def test_guard_rejects_a_live_ip():
    with pytest.raises(pytest.fail.Exception):
        _check_indicator("45.155.205.233")


def test_guard_rejects_a_live_domain():
    with pytest.raises(pytest.fail.Exception):
        _check_indicator("cdn-update-service.top")
