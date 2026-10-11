"""scan_host against the nginx TLS targets on the compose network."""

import pytest

from quantum_tool.crypto_scanner import CryptoScanner

pytestmark = pytest.mark.integration


@pytest.fixture
def scanner():
    return CryptoScanner({"targets": [], "ports": [443], "timeout": 5})


def test_tls_rsa_negotiates_tls13_with_rsa_2048_certificate(scanner):
    ep = scanner.scan_host("tls-rsa", 443)

    assert ep["status"] == "ok"
    assert ep["protocol"] == "TLSv1.3"
    assert ep["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    cert = ep["certificate"]
    assert (cert["key_type"], cert["key_bits"], cert["signature_hash"]) == ("RSA", 2048, "sha256")


def test_tls_ecdsa_certificate_is_ec_p256(scanner):
    ep = scanner.scan_host("tls-ecdsa", 443)

    assert ep["status"] == "ok"
    assert ep["protocol"] == "TLSv1.3"
    cert = ep["certificate"]
    assert cert["key_type"] == "EC"
    assert cert["key_bits"] == 256
    assert cert["curve"] == "secp256r1"


def test_tls_legacy_negotiates_tls12_aes128_sha_with_sha1_certificate(scanner):
    ep = scanner.scan_host("tls-legacy", 443)

    assert ep["status"] == "ok"
    assert ep["protocol"] == "TLSv1.2"
    assert ep["cipher_suite"] == "AES128-SHA"
    assert ep["key_exchange"] == "RSA"
    cert = ep["certificate"]
    assert (cert["key_type"], cert["signature_hash"]) == ("RSA", "sha1")


def test_closed_port_on_live_host_is_unreachable(scanner):
    ep = scanner.scan_host("tls-rsa", 9)

    assert ep["status"] == "unreachable"
    assert (ep["host"], ep["port"]) == ("tls-rsa", 9)
    assert ep["protocol"] is None
    assert ep["certificate"] is None


def test_scan_all_counts_ok_and_unreachable_endpoints():
    scanner = CryptoScanner({"targets": ["tls-rsa", "tls-legacy"], "ports": [443, 9],
                             "timeout": 5, "max_workers": 4})
    report = scanner.scan_all()

    assert report["total_endpoints"] == 2
    assert report["unreachable"] == 2
    assert {(r["host"], r["port"]) for r in report["results"]} == {
        ("tls-rsa", 443), ("tls-legacy", 443)}
