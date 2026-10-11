"""Certificate and private-key inventory against the committed test fixtures."""

import logging
import os

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from quantum_tool import certificate_manager as cm

FIXTURES = os.path.join(os.path.dirname(__file__), os.pardir, "fixtures", "tls")
CERT_KEYS = {
    "subject", "issuer", "serial", "fingerprint_sha256", "key_type", "key_bits", "curve",
    "signature_hash", "not_before", "not_after", "source",
}
KEY_KEYS = {"source", "key_type", "key_bits", "curve"}


def fixture(name):
    with open(os.path.join(FIXTURES, name), "rb") as fh:
        return fh.read()


def test_rsa_sha256_certificate():
    info = cm.parse_certificate(fixture("rsa2048-sha256-cert.pem"))

    assert set(info) == CERT_KEYS
    assert info["key_type"] == "RSA"
    assert info["key_bits"] == 2048
    assert info["curve"] is None
    assert info["signature_hash"] == "sha256"
    assert info["source"] == "network"
    assert "CN=rsa2048-sha256.test" in info["subject"]
    assert info["subject"] == info["issuer"]
    assert info["not_before"] == "2020-06-01T00:00:00Z"
    assert info["not_after"] == "2030-06-01T00:00:00Z"
    assert len(info["fingerprint_sha256"]) == 64


def test_ec_certificate_reports_curve():
    info = cm.parse_certificate(fixture("ec-p256-sha256-cert.pem"), source="ec.pem")

    assert info["key_type"] == "EC"
    assert info["curve"] == "secp256r1"
    assert info["key_bits"] == 256
    assert info["signature_hash"] == "sha256"
    assert info["source"] == "ec.pem"


def test_sha1_signed_certificate():
    assert cm.parse_certificate(fixture("rsa2048-sha1-cert.pem"))["signature_hash"] == "sha1"


def test_der_and_pem_of_same_certificate_share_fingerprint():
    der = cm.parse_certificate(fixture("rsa2048-sha256-cert.der"))
    pem = cm.parse_certificate(fixture("rsa2048-sha256-cert.pem"))

    assert der["fingerprint_sha256"] == pem["fingerprint_sha256"]
    assert der["serial"] == pem["serial"]


def test_garbage_certificate_raises_value_error():
    with pytest.raises(ValueError):
        cm.parse_certificate(b"\x30\x82\x01\x00not a certificate")


def test_private_keys_are_typed_and_sized():
    rsa_key = cm.parse_private_key(fixture("rsa2048-sha256-key.pem"), "rsa.pem")
    ec_key = cm.parse_private_key(fixture("ec-p256-sha256-key.pem"), "ec.pem")

    assert rsa_key == {"source": "rsa.pem", "key_type": "RSA", "key_bits": 2048, "curve": None}
    assert ec_key == {"source": "ec.pem", "key_type": "EC", "key_bits": 256,
                      "curve": "secp256r1"}


def test_der_private_key_is_parsed():
    key = serialization.load_pem_private_key(
        fixture("ec-p256-sha256-key.pem"), password=None, backend=default_backend())
    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())

    assert cm.parse_private_key(der, "ec.der")["curve"] == "secp256r1"


def test_encrypted_key_is_listed_without_details(tmp_path):
    key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(b"fixture-pass"))
    path = tmp_path / "locked.key"
    path.write_bytes(pem)

    result = cm.scan_directory(str(tmp_path))

    assert result["certificates"] == []
    assert result["keys"] == [{"source": str(path), "key_type": "encrypted",
                               "key_bits": None, "curve": None}]


def test_load_file_reads_certificate_and_key_from_one_pem(tmp_path):
    path = tmp_path / "bundle.pem"
    path.write_bytes(fixture("ec-p256-sha256-cert.pem") + fixture("ec-p256-sha256-key.pem"))

    result = cm.load_file(str(path))

    assert [c["key_type"] for c in result["certificates"]] == ["EC"]
    assert [k["key_type"] for k in result["keys"]] == ["EC"]
    assert result["certificates"][0]["source"] == str(path)


def test_load_file_rejects_files_with_nothing_parsable():
    with pytest.raises(ValueError):
        cm.load_file(os.path.join(FIXTURES, "dhparam-2048.pem"))


def test_scan_directory_inventories_fixtures(caplog):
    with caplog.at_level(logging.WARNING):
        result = cm.scan_directory(FIXTURES)

    certs = result["certificates"]
    keys = result["keys"]
    assert len(certs) == 3
    assert len({c["fingerprint_sha256"] for c in certs}) == 3
    rsa256 = [c for c in certs if "rsa2048-sha256" in c["subject"]]
    assert len(rsa256) == 1
    assert rsa256[0]["source"].endswith("rsa2048-sha256-cert.der")
    assert sorted((c["key_type"], c["signature_hash"]) for c in certs) == [
        ("EC", "sha256"), ("RSA", "sha1"), ("RSA", "sha256")]

    assert sorted((k["key_type"], k["key_bits"], k["curve"]) for k in keys) == sorted([
        ("RSA", 2048, None), ("EC", 256, "secp256r1"), ("RSA", 2048, None)])
    assert [os.path.basename(k["source"]) for k in keys] == [
        "ec-p256-sha256-key.pem", "rsa2048-sha1-key.pem", "rsa2048-sha256-key.pem"]

    sources = [c["source"] for c in certs] + [k["source"] for k in keys]
    assert not any(s.endswith("dhparam-2048.pem") for s in sources)
    assert any("dhparam-2048.pem" in r.getMessage() for r in caplog.records)


def test_key_info_never_contains_key_material():
    keys = cm.scan_directory(FIXTURES)["keys"]
    material = [fixture(n) for n in ("rsa2048-sha256-key.pem", "rsa2048-sha1-key.pem",
                                     "ec-p256-sha256-key.pem")]

    for info in keys:
        assert set(info) == KEY_KEYS
        for value in info.values():
            assert not isinstance(value, (bytes, bytearray))
            text = str(value)
            assert "BEGIN" not in text and "PRIVATE" not in text
            for pem in material:
                body = b"".join(pem.splitlines()[1:-1]).decode()
                assert body[:32] not in text


def test_scan_directory_recurses_and_ignores_other_extensions(tmp_path):
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    (nested / "server.crt").write_bytes(fixture("rsa2048-sha1-cert.pem"))
    (tmp_path / "notes.txt").write_bytes(fixture("ec-p256-sha256-cert.pem"))

    result = cm.scan_directory(str(tmp_path))

    assert [c["source"] for c in result["certificates"]] == [str(nested / "server.crt")]
