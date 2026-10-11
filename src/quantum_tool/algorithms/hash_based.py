"""
SPHINCS+ hash-based signatures.

SPHINCS+ relies only on the security of its hash function, which makes it the
conservative alternative to the lattice-based Dilithium signer. The "f"
parameter set signs faster, the "s" set produces smaller signatures.
"""

from quantum_tool.algorithms import SafeSignature
from quantum_tool.algorithms.lattice_based import _checked, _Wrapper

SPHINCS_VARIANTS = (
    'SPHINCS+-SHA256-128f-simple',
    'SPHINCS+-SHA256-128s-simple',
)


class SphincsSigner(_Wrapper):
    """SPHINCS+ signer for the SHA-256 128-bit simple parameter sets."""

    def __init__(self, variant='SPHINCS+-SHA256-128f-simple'):
        if variant not in SPHINCS_VARIANTS:
            raise ValueError('unsupported SPHINCS+ variant {!r}; expected one of {}'.format(
                variant, list(SPHINCS_VARIANTS)))
        super().__init__(SafeSignature(variant))
        self.variant = variant

    def keypair(self):
        """Generate a keypair, keep the secret key and return the public key."""
        return _checked(self._native.generate_keypair(), 'keypair')

    def sign(self, message):
        return _checked(self._native.sign(message), 'sign')

    def verify(self, message, signature, public_key):
        return self._native.verify(message, signature, public_key)
