"""Cipher enumeration and risk scores against the nginx TLS targets."""

from datetime import datetime, timezone

import pytest

from quantum_tool.crypto_scanner import CryptoScanner
from quantum_tool.vulnerability_assessor import assess_endpoint

pytestmark = pytest.mark.integration

NOW = datetime(2020, 6, 30, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def endpoints():
    scanner = CryptoScanner({"targets": [], "ports": [443], "timeout": 5})
    return {name: scanner.scan_host(name, 443) for name in ("tls-rsa", "tls-ecdsa", "tls-legacy")}


def test_tls_rsa_offers_static_rsa_and_dhe_suites(endpoints):
    ep = endpoints["tls-rsa"]

    assert ep["status"] == "ok"
    assert ep["tls13"] is True
    assert "AES128-SHA" in ep["offered_suites"]
    assert "DHE-RSA-AES256-GCM-SHA384" in ep["offered_suites"]
    assert "ECDHE-RSA-AES128-GCM-SHA256" in ep["offered_suites"]


def test_tls_ecdsa_offers_only_ecdsa_suites(endpoints):
    ep = endpoints["tls-ecdsa"]

    assert ep["tls13"] is True
    assert ep["offered_suites"]
    assert all("-ECDSA-" in name for name in ep["offered_suites"])


def test_tls_legacy_offers_only_static_rsa_aes128_sha_and_no_tls13(endpoints):
    # Debian's OpenSSL 1.1.1d is built without 3DES suites on both client and
    # server, so DES-CBC3-SHA in the nginx policy can never be negotiated.
    ep = endpoints["tls-legacy"]

    assert ep["tls13"] is False
    assert ep["negotiated_suite"] == "AES128-SHA"
    assert ep["offered_suites"] == ["AES128-SHA"]


def test_risk_scores_follow_spec_worked_examples(endpoints):
    scores = {name: assess_endpoint(ep, now=NOW)["risk_score"]
              for name, ep in endpoints.items()}

    assert scores == {"tls-legacy": 85, "tls-rsa": 70, "tls-ecdsa": 60}
