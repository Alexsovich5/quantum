"""Table-driven tests for decomposing cipher-suite names."""

import pytest

from quantum_tool.cipher_suites import parse_suite

# name, kex, auth, cipher, cipher_bits, mac
CASES = [
    # forward-secret ECDHE suites
    ("ECDHE-RSA-AES256-GCM-SHA384", "ECDH", "RSA", "AES-256-GCM", 256, "AEAD"),
    ("ECDHE-RSA-AES128-GCM-SHA256", "ECDH", "RSA", "AES-128-GCM", 128, "AEAD"),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDH", "ECDSA", "AES-256-GCM", 256, "AEAD"),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDH", "ECDSA", "CHACHA20-POLY1305", 256, "AEAD"),
    ("ECDHE-RSA-CHACHA20-POLY1305", "ECDH", "RSA", "CHACHA20-POLY1305", 256, "AEAD"),
    ("ECDHE-RSA-AES128-SHA", "ECDH", "RSA", "AES-128-CBC", 128, "SHA1"),
    ("ECDHE-ECDSA-AES256-SHA384", "ECDH", "ECDSA", "AES-256-CBC", 256, "SHA384"),
    ("ECDHE-ECDSA-AES128-CCM8", "ECDH", "ECDSA", "AES-128-CCM8", 128, "AEAD"),
    ("ECDHE-RSA-DES-CBC3-SHA", "ECDH", "RSA", "3DES-CBC", 168, "SHA1"),
    # finite-field DHE, including the EDH alias
    ("DHE-RSA-AES256-GCM-SHA384", "DH", "RSA", "AES-256-GCM", 256, "AEAD"),
    ("DHE-RSA-AES128-SHA256", "DH", "RSA", "AES-128-CBC", 128, "SHA256"),
    ("DHE-DSS-AES128-SHA", "DH", "DSS", "AES-128-CBC", 128, "SHA1"),
    ("DHE-RSA-CAMELLIA256-SHA", "DH", "RSA", "CAMELLIA-256-CBC", 256, "SHA1"),
    ("EDH-RSA-DES-CBC3-SHA", "DH", "RSA", "3DES-CBC", 168, "SHA1"),
    ("EDH-DSS-DES-CBC3-SHA", "DH", "DSS", "3DES-CBC", 168, "SHA1"),
    # static (EC)DH with certificate-held keys
    ("ECDH-RSA-AES128-SHA", "ECDH", "RSA", "AES-128-CBC", 128, "SHA1"),
    ("ECDH-ECDSA-AES256-GCM-SHA384", "ECDH", "ECDSA", "AES-256-GCM", 256, "AEAD"),
    ("DH-RSA-AES256-SHA", "DH", "RSA", "AES-256-CBC", 256, "SHA1"),
    ("DH-DSS-AES128-GCM-SHA256", "DH", "DSS", "AES-128-GCM", 128, "AEAD"),
    # static RSA key exchange (no prefix)
    ("AES128-SHA", "RSA", "RSA", "AES-128-CBC", 128, "SHA1"),
    ("AES256-GCM-SHA384", "RSA", "RSA", "AES-256-GCM", 256, "AEAD"),
    ("AES128-SHA256", "RSA", "RSA", "AES-128-CBC", 128, "SHA256"),
    ("DES-CBC3-SHA", "RSA", "RSA", "3DES-CBC", 168, "SHA1"),
    ("RC4-MD5", "RSA", "RSA", "RC4", 128, "MD5"),
    ("RC4-SHA", "RSA", "RSA", "RC4", 128, "SHA1"),
    ("CAMELLIA128-SHA", "RSA", "RSA", "CAMELLIA-128-CBC", 128, "SHA1"),
    ("SEED-SHA", "RSA", "RSA", "SEED-CBC", 128, "SHA1"),
    ("AES256-CCM", "RSA", "RSA", "AES-256-CCM", 256, "AEAD"),
    # PSK and SRP
    ("PSK-AES128-CBC-SHA", "PSK", "PSK", "AES-128-CBC", 128, "SHA1"),
    ("ECDHE-PSK-CHACHA20-POLY1305", "PSK", "PSK", "CHACHA20-POLY1305", 256, "AEAD"),
    ("PSK-3DES-EDE-CBC-SHA", "PSK", "PSK", "3DES-CBC", 168, "SHA1"),
    ("SRP-AES-256-CBC-SHA", "SRP", "SRP", "AES-256-CBC", 256, "SHA1"),
    ("SRP-RSA-AES-128-CBC-SHA", "SRP", "RSA", "AES-128-CBC", 128, "SHA1"),
    # recognised but outside the enum: anonymous DH
    ("ADH-AES256-GCM-SHA384", "DH", "other", "AES-256-GCM", 256, "AEAD"),
    ("AECDH-AES128-SHA", "ECDH", "other", "AES-128-CBC", 128, "SHA1"),
    # TLS 1.3 IANA names
    ("TLS_AES_256_GCM_SHA384", "ECDH", "cert", "AES-256-GCM", 256, "AEAD"),
    ("TLS_AES_128_GCM_SHA256", "ECDH", "cert", "AES-128-GCM", 128, "AEAD"),
    ("TLS_CHACHA20_POLY1305_SHA256", "ECDH", "cert", "CHACHA20-POLY1305", 256, "AEAD"),
    ("TLS_AES_128_CCM_8_SHA256", "ECDH", "cert", "AES-128-CCM8", 128, "AEAD"),
]


@pytest.mark.parametrize("name,kex,auth,cipher,bits,mac", CASES, ids=[c[0] for c in CASES])
def test_parse_suite(name, kex, auth, cipher, bits, mac):
    assert parse_suite(name) == {
        "name": name, "kex": kex, "auth": auth,
        "cipher": cipher, "cipher_bits": bits, "mac": mac,
    }


UNKNOWN = {"kex": "unknown", "auth": "unknown", "cipher": "unknown",
           "cipher_bits": None, "mac": "unknown"}


@pytest.mark.parametrize("name", [
    "FOO-BAR-BAZ",
    "",
    "TLS_FAKE_CIPHER_SHA256",
    "ECDHE-RSA-WIBBLE-SHA",
    "ECDHE-RSA-AES128",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
])
def test_unknown_name_returns_unknown_fields(name):
    result = parse_suite(name)
    assert result == dict(UNKNOWN, name=name)


def test_none_is_treated_as_unknown():
    assert parse_suite(None) == dict(UNKNOWN, name=None)


def test_lowercase_names_are_parsed():
    result = parse_suite("dhe-rsa-aes128-sha")
    assert (result["kex"], result["auth"], result["cipher"]) == ("DH", "RSA", "AES-128-CBC")
    assert result["name"] == "dhe-rsa-aes128-sha"


def test_static_rsa_and_dhe_are_no_longer_confused():
    """The old substring checks read DHE-RSA as plain DH and AES128-SHA as unknown."""
    assert parse_suite("DHE-RSA-AES128-SHA")["kex"] == "DH"
    assert parse_suite("DHE-RSA-AES128-SHA")["auth"] == "RSA"
    assert parse_suite("AES128-SHA")["kex"] == "RSA"
