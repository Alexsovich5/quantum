import pytest

from quantum_tool.algorithms.hash_based import SPHINCS_VARIANTS, SphincsSigner

VARIANTS = ["SPHINCS+-SHA256-128f-simple", "SPHINCS+-SHA256-128s-simple"]


def test_supported_variants_are_the_sha256_128_simple_sets():
    assert sorted(SPHINCS_VARIANTS) == sorted(VARIANTS)


@pytest.mark.parametrize("variant", VARIANTS)
def test_sphincs_sign_verify_round_trip(variant):
    message = b"conservative signature fallback"
    with SphincsSigner(variant) as signer:
        public_key = signer.keypair()
        signature = signer.sign(message)

        assert signer.name == variant
        assert len(public_key) == signer.details["length_public_key"]
        assert len(signature) <= signer.details["length_signature"]
        assert signer.verify(message, signature, public_key) is True


@pytest.mark.parametrize("variant", VARIANTS)
def test_sphincs_rejects_tampered_message(variant):
    message = b"conservative signature fallback"
    with SphincsSigner(variant) as signer:
        public_key = signer.keypair()
        signature = signer.sign(message)
        tampered = bytes([message[0] ^ 0x01]) + message[1:]

        assert signer.verify(tampered, signature, public_key) is False


def test_small_variant_signature_is_shorter_than_fast_variant():
    message = b"size comparison"
    with SphincsSigner("SPHINCS+-SHA256-128s-simple") as small, \
            SphincsSigner("SPHINCS+-SHA256-128f-simple") as fast:
        small.keypair()
        fast.keypair()

        assert len(small.sign(message)) < len(fast.sign(message))
        assert small.details["length_signature"] < fast.details["length_signature"]


@pytest.mark.parametrize("variant", ["SPHINCS+-SHA256-256f-simple", "sphincs", None, 128])
def test_sphincs_rejects_unknown_variant(variant):
    with pytest.raises(ValueError):
        SphincsSigner(variant)


def test_context_manager_then_explicit_free_does_not_crash():
    with SphincsSigner("SPHINCS+-SHA256-128f-simple") as signer:
        signer.keypair()
    signer.free()
    signer.free()
