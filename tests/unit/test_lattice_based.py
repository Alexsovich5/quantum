import oqs
import pytest

from quantum_tool.algorithms import SafeKeyEncapsulation, SafeSignature, available
from quantum_tool.algorithms.lattice_based import DilithiumSigner, KyberKEM


def test_liboqs_enables_kyber512():
    assert "Kyber512" in oqs.get_enabled_KEM_mechanisms()


def test_available_lists_enabled_kems_and_signatures():
    mechanisms = available()
    assert "Kyber768" in mechanisms["kem"]
    assert "DILITHIUM_3" in mechanisms["sig"]


@pytest.mark.parametrize("level", [512, 768, 1024])
def test_kyber_shared_secrets_match(level):
    with KyberKEM(level) as receiver, KyberKEM(level) as sender:
        public_key = receiver.keypair()
        ciphertext, sent_secret = sender.encapsulate(public_key)
        received_secret = receiver.decapsulate(ciphertext)

        assert sent_secret == received_secret
        details = receiver.details
        assert details["name"] == "Kyber{}".format(level)
        assert len(public_key) == details["length_public_key"]
        assert len(ciphertext) == details["length_ciphertext"]
        assert len(sent_secret) == details["length_shared_secret"]


def test_kyber_rejects_unknown_level():
    with pytest.raises(ValueError):
        KyberKEM(256)


@pytest.mark.parametrize("level", [2, 3, 4])
def test_dilithium_sign_verify_round_trip(level):
    message = b"migration roadmap"
    with DilithiumSigner(level) as signer:
        public_key = signer.keypair()
        signature = signer.sign(message)

        assert signer.details["name"] == "DILITHIUM_{}".format(level)
        assert len(public_key) == signer.details["length_public_key"]
        assert 0 < len(signature) <= signer.details["length_signature"]
        assert signer.verify(message, signature, public_key) is True


def test_dilithium_rejects_tampered_message():
    message = b"migration roadmap"
    with DilithiumSigner(2) as signer:
        public_key = signer.keypair()
        signature = signer.sign(message)
        tampered = bytes([message[0] ^ 0x01]) + message[1:]

        assert signer.verify(tampered, signature, public_key) is False


def test_dilithium_rejects_wrong_public_key():
    message = b"migration roadmap"
    with DilithiumSigner(2) as signer, DilithiumSigner(2) as other:
        signer.keypair()
        other_public_key = other.keypair()
        signature = signer.sign(message)

        assert signer.verify(message, signature, other_public_key) is False


def test_dilithium_rejects_unknown_level():
    with pytest.raises(ValueError):
        DilithiumSigner(5)


def test_safe_kem_free_cleanses_secret_key_and_is_idempotent():
    kem = SafeKeyEncapsulation("Kyber512")
    kem.generate_keypair()
    assert any(kem.export_secret_key())

    kem.free()
    assert not any(kem.export_secret_key())
    kem.free()


def test_many_safe_kem_objects_free_without_crashing():
    for i in range(1000):
        if i % 2:
            with SafeKeyEncapsulation("Kyber512") as kem:
                kem.generate_keypair()
        else:
            kem = SafeKeyEncapsulation("Kyber512")
            kem.generate_keypair()
            kem.free()
        if i % 7 == 0:
            kem.free()


def test_many_safe_signature_objects_free_without_crashing():
    for i in range(100):
        if i % 2:
            with SafeSignature("DILITHIUM_2") as sig:
                sig.generate_keypair()
        else:
            sig = SafeSignature("DILITHIUM_2")
            sig.generate_keypair()
            sig.free()
        if i % 7 == 0:
            sig.free()
