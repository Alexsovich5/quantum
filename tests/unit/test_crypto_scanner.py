"""Behaviour tests for CryptoScanner.scan_host and report generation."""

import os
import socket
import ssl
from unittest import mock

import pytest

from quantum_tool.crypto_scanner import CryptoScanner

from tests.unit.fakes import (FakeRawSocket, FakeSSLSocket, failing_connection,
                              fake_connection)

DER_CERT_PATH = os.path.join(os.path.dirname(__file__), os.pardir, "fixtures", "tls",
                             "rsa2048-sha256-cert.der")

RESULT_KEYS = {
    "host", "port", "status", "protocol", "cipher_suite", "key_exchange", "auth_algorithm",
    "key_bits", "certificate", "scan_time", "vulnerabilities", "tls13", "negotiated_suite",
    "offered_suites",
}


def make_scanner():
    return CryptoScanner({"targets": ["192.0.2.10"], "ports": [443], "timeout": 3,
                          "enumerate_ciphers": False})


def test_scan_host_returns_documented_keys():
    with open(DER_CERT_PATH, "rb") as fh:
        der = fh.read()
    fake = FakeSSLSocket(cipher=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256),
                         version="TLSv1.2", cert=der)
    with fake_connection(fake) as patched:
        result = make_scanner().scan_host("192.0.2.10", 443)

    assert set(result) == RESULT_KEYS
    assert result["status"] == "ok"
    assert result["host"] == "192.0.2.10"
    assert result["port"] == 443
    assert result["protocol"] == "TLSv1.2"
    assert result["cipher_suite"] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert result["key_bits"] == 256
    assert result["negotiated_suite"] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert result["offered_suites"] == [] and result["tls13"] is False
    cert = result["certificate"]
    assert (cert["key_type"], cert["key_bits"], cert["signature_hash"]) == ("RSA", 2048, "sha256")
    assert cert["source"] == "network"
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


def test_tls13_suite_is_ecdh_with_certificate_auth():
    fake = FakeSSLSocket(cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), version="TLSv1.3")
    with fake_connection(fake):
        result = make_scanner().scan_host("192.0.2.10", 443)

    assert result["key_exchange"] == "ECDH"
    assert result["auth_algorithm"] == "cert"
    assert result["vulnerabilities"] == [
        {"type": "key_exchange", "algorithm": "ECDH", "threat_level": "critical",
         "recommendation": "Migrate to CRYSTALS-Kyber"},
    ]


@pytest.mark.parametrize("suite,kex,auth", [
    ("DHE-RSA-AES128-SHA", "DH", "RSA"),
    ("AES128-SHA", "RSA", "RSA"),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDH", "ECDSA"),
    ("PSK-AES128-CBC-SHA", "PSK", "PSK"),
])
def test_scanner_delegates_suite_parsing(suite, kex, auth):
    fake = FakeSSLSocket(cipher=(suite, "TLSv1.2", 128))
    with fake_connection(fake):
        result = make_scanner().scan_host("192.0.2.10", 443)

    assert (result["key_exchange"], result["auth_algorithm"]) == (kex, auth)


def test_missing_cipher_and_certificate_fall_back_to_defaults():
    fake = FakeSSLSocket(cipher=None, cert=None)
    with fake_connection(fake):
        result = make_scanner().scan_host("192.0.2.10", 443)

    assert result["cipher_suite"] == "unknown"
    assert result["key_bits"] == 0
    assert result["certificate"] is None


def test_unparsable_peer_certificate_is_recorded_as_none():
    fake = FakeSSLSocket(cipher=("AES128-SHA", "TLSv1.2", 128), cert=b"x" * 812)
    with fake_connection(fake):
        result = make_scanner().scan_host("192.0.2.10", 443)

    assert result["certificate"] is None
    assert result["cipher_suite"] == "AES128-SHA"


UNREACHABLE_KEYS = {
    "host", "port", "status", "protocol", "tls13", "negotiated_suite", "offered_suites",
    "key_bits", "certificate", "scan_time",
}


def test_connection_refused_yields_unreachable_endpoint():
    with failing_connection(ConnectionRefusedError(111, "Connection refused")):
        ep = make_scanner().scan_host("192.0.2.10", 443)

    assert set(ep) == UNREACHABLE_KEYS
    assert ep["status"] == "unreachable"
    assert (ep["host"], ep["port"]) == ("192.0.2.10", 443)
    assert ep["protocol"] is None and ep["negotiated_suite"] is None
    assert ep["tls13"] is False and ep["offered_suites"] == []
    assert ep["key_bits"] is None and ep["certificate"] is None


def test_timeout_yields_unreachable_endpoint():
    with failing_connection(socket.timeout("timed out")):
        assert make_scanner().scan_host("192.0.2.10", 443)["status"] == "unreachable"


def test_failed_tls_handshake_yields_no_tls_endpoint():
    raw = FakeRawSocket()
    with mock.patch.object(socket, "create_connection", return_value=raw), \
            mock.patch.object(ssl.SSLContext, "wrap_socket", autospec=True,
                              side_effect=ssl.SSLError(1, "wrong version number")):
        ep = make_scanner().scan_host("192.0.2.10", 80)

    assert set(ep) == UNREACHABLE_KEYS
    assert ep["status"] == "no_tls"
    assert raw.closed


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
    assert report["results"] == results
    assert "scan_date" in report


def test_generate_report_with_no_results_is_zero_risk():
    report = make_scanner()._generate_report([])

    assert report["total_endpoints"] == 0
    assert report["vulnerable_endpoints"] == 0
    assert report["risk_percentage"] == 0
    assert report["results"] == []
    assert report["summary"] == {"critical": 0, "quantum_safe": 0}


def test_generate_report_adds_one_assessment_per_result():
    result = {"host": "192.0.2.10", "port": 443, "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
              "certificate": None, "vulnerabilities": [CRITICAL]}
    report = make_scanner()._generate_report([result])

    [assessment] = report["assessments"]
    assert assessment["target"] == "192.0.2.10:443"
    assert assessment["risk_score"] == 55


def test_scan_all_counts_unreachable_endpoints_outside_totals():
    scanner = CryptoScanner({"targets": ["192.0.2.10", "192.0.2.11"], "ports": [443],
                             "max_workers": 1})
    with failing_connection(ConnectionRefusedError(111, "Connection refused")) as connect:
        report = scanner.scan_all()

    assert connect.call_count == 2
    assert report["total_endpoints"] == 0
    assert report["unreachable"] == 2
    assert report["results"] == []
    assert report["assessments"] == []


def test_generate_report_counts_only_ok_endpoints():
    ok = {"host": "192.0.2.10", "port": 443, "status": "ok", "cipher_suite": "AES128-SHA",
          "certificate": None, "vulnerabilities": [CRITICAL]}
    down = {"host": "192.0.2.11", "port": 443, "status": "unreachable", "certificate": None}
    no_tls = {"host": "192.0.2.12", "port": 443, "status": "no_tls", "certificate": None}
    report = make_scanner()._generate_report([ok, down, no_tls])

    assert report["total_endpoints"] == 1
    assert report["vulnerable_endpoints"] == 1
    assert report["unreachable"] == 1
    assert report["results"] == [ok]
    assert [a["target"] for a in report["assessments"]] == ["192.0.2.10:443"]
