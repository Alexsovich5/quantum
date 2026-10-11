"""Per-suite TLS 1.2 enumeration against an in-process TLS server."""

import socket
import ssl
from unittest import mock

from quantum_tool.crypto_scanner import CryptoScanner

from tests.unit.tls_server import tls_server  # noqa: F401  (pytest fixture)

ONLY_SUITE = "ECDHE-RSA-AES128-GCM-SHA256"


def make_scanner(**overrides):
    config = {"targets": [], "ports": [443], "timeout": 3}
    config.update(overrides)
    return CryptoScanner(config)


def _handshake_ok(host, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=3) as sock:
        with context.wrap_socket(sock) as tls:
            return tls.cipher()[0]


def test_restricted_server_offers_exactly_its_one_suite(tls_server):  # noqa: F811
    server = tls_server(ONLY_SUITE)

    offered = make_scanner().enumerate_ciphers(server.host, server.port)

    assert offered == [ONLY_SUITE]


def test_server_keeps_accepting_after_full_candidate_loop(tls_server):  # noqa: F811
    server = tls_server(ONLY_SUITE)
    scanner = make_scanner()

    offered = scanner.enumerate_ciphers(server.host, server.port)

    assert offered == [ONLY_SUITE]
    assert len(scanner.candidate_suites()) > 20
    assert _handshake_ok(server.host, server.port) == ONLY_SUITE


def test_candidates_exclude_psk_srp_and_anonymous_suites():
    candidates = make_scanner().candidate_suites()

    assert len(candidates) > 20
    assert "AES128-SHA" in candidates
    assert "ECDHE-ECDSA-AES256-GCM-SHA384" in candidates
    for name in candidates:
        assert "PSK" not in name
        assert "SRP" not in name
        assert not name.startswith(("ADH-", "AECDH-"))
        assert not name.startswith("TLS_")


def test_unreachable_port_offers_nothing():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    assert make_scanner().enumerate_ciphers("127.0.0.1", port) == []


def test_tls12_only_server_has_no_tls13(tls_server):  # noqa: F811
    server = tls_server(ONLY_SUITE)

    assert make_scanner().supports_tls13(server.host, server.port) is False


def test_scan_host_records_offered_suites_when_enabled(tls_server):  # noqa: F811
    server = tls_server(ONLY_SUITE)

    ep = make_scanner().scan_host(server.host, server.port)

    assert ep["status"] == "ok"
    assert ep["negotiated_suite"] == ONLY_SUITE
    assert ep["offered_suites"] == [ONLY_SUITE]
    assert ep["tls13"] is False


def test_disabled_enumeration_leaves_offered_suites_empty(tls_server):  # noqa: F811
    server = tls_server(ONLY_SUITE)

    scanner = make_scanner(enumerate_ciphers=False)
    with mock.patch.object(CryptoScanner, "enumerate_ciphers",
                           side_effect=AssertionError("enumeration disabled")), \
            mock.patch.object(CryptoScanner, "supports_tls13",
                              side_effect=AssertionError("enumeration disabled")):
        ep = scanner.scan_host(server.host, server.port)

    assert ep["status"] == "ok"
    assert ep["negotiated_suite"] == ONLY_SUITE
    assert ep["offered_suites"] == []
    assert ep["tls13"] is False
