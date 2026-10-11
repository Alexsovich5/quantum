"""Characterisation tests for the scanner as it behaves before refactoring."""

import socket

from quantum_tool.crypto_scanner import CryptoScanner

from tests.unit.fakes import FakeSSLSocket, failing_connection, fake_connection

RESULT_KEYS = {
    "host", "port", "protocol", "cipher_suite", "key_exchange", "auth_algorithm",
    "key_bits", "certificate", "scan_time", "vulnerabilities",
}


def make_scanner():
    return CryptoScanner({"targets": ["192.0.2.10"], "ports": [443], "timeout": 3})


def test_scan_host_returns_documented_keys():
    fake = FakeSSLSocket(cipher=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256),
                         version="TLSv1.2", cert=b"x" * 812)
    with fake_connection(fake) as patched:
        result = make_scanner().scan_host("192.0.2.10", 443)

    assert set(result) == RESULT_KEYS
    assert result["host"] == "192.0.2.10"
    assert result["port"] == 443
    assert result["protocol"] == "TLSv1.2"
    assert result["cipher_suite"] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert result["key_bits"] == 256
    assert result["certificate"] == {"size_bytes": 812, "needs_migration": True}
    patched.connect.assert_called_once_with(("192.0.2.10", 443), timeout=3)
    assert patched.wrap.call_args[1]["server_hostname"] == "192.0.2.10"
    assert fake.closed and patched.raw.closed


def test_ecdhe_rsa_suite_yields_ecdh_rsa_and_two_critical_findings():
    fake = FakeSSLSocket(cipher=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256))
    with fake_connection(fake):
        result = make_scanner().scan_host("192.0.2.10", 443)

    assert result["key_exchange"] == "ECDH"
    assert result["auth_algorithm"] == "RSA"
    assert result["vulnerabilities"] == [
        {"type": "key_exchange", "algorithm": "ECDH", "threat_level": "critical",
         "recommendation": "Migrate to CRYSTALS-Kyber"},
        {"type": "authentication", "algorithm": "RSA", "threat_level": "critical",
         "recommendation": "Migrate to CRYSTALS-Dilithium"},
    ]


def test_tls13_suite_name_has_no_recognised_algorithms():
    fake = FakeSSLSocket(cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), version="TLSv1.3")
    with fake_connection(fake):
        result = make_scanner().scan_host("192.0.2.10", 443)

    assert result["key_exchange"] == "unknown"
    assert result["auth_algorithm"] == "unknown"
    assert result["vulnerabilities"] == []


def test_missing_cipher_and_certificate_fall_back_to_defaults():
    fake = FakeSSLSocket(cipher=None, cert=None)
    with fake_connection(fake):
        result = make_scanner().scan_host("192.0.2.10", 443)

    assert result["cipher_suite"] == "unknown"
    assert result["key_bits"] == 0
    assert result["certificate"] == {}


def test_connection_refused_returns_none():
    with failing_connection(ConnectionRefusedError(111, "Connection refused")):
        assert make_scanner().scan_host("192.0.2.10", 443) is None


def test_timeout_returns_none():
    with failing_connection(socket.timeout("timed out")):
        assert make_scanner().scan_host("192.0.2.10", 443) is None


def _result(vulns):
    return {"vulnerabilities": vulns}


CRITICAL = {"type": "key_exchange", "algorithm": "RSA", "threat_level": "critical",
            "recommendation": "Migrate to CRYSTALS-Dilithium"}


def test_generate_report_computes_risk_percentage():
    results = [_result([CRITICAL, CRITICAL]), _result([]), _result([CRITICAL])]
    report = make_scanner()._generate_report(results)

    assert report["total_endpoints"] == 3
    assert report["vulnerable_endpoints"] == 2
    assert report["risk_percentage"] == 66.7
    assert report["summary"] == {"critical": 3, "quantum_safe": 1}
    assert report["results"] is results
    assert "scan_date" in report


def test_generate_report_with_no_results_is_zero_risk():
    report = make_scanner()._generate_report([])

    assert report["total_endpoints"] == 0
    assert report["vulnerable_endpoints"] == 0
    assert report["risk_percentage"] == 0
    assert report["results"] == []
    assert report["summary"] == {"critical": 0, "quantum_safe": 0}


def test_scan_all_skips_unreachable_endpoints():
    scanner = CryptoScanner({"targets": ["192.0.2.10", "192.0.2.11"], "ports": [443],
                             "max_workers": 1})
    with failing_connection(ConnectionRefusedError(111, "Connection refused")) as connect:
        report = scanner.scan_all()

    assert connect.call_count == 2
    assert report["total_endpoints"] == 0
    assert report["results"] == []
