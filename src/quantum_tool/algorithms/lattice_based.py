"""
CRYSTALS-Kyber key encapsulation and CRYSTALS-Dilithium signatures.

Thin wrappers over the liboqs NIST round-2 parameter sets, built on the
Safe* classes so the native objects are released without a use-after-free.
"""

from quantum_tool.algorithms import SafeKeyEncapsulation, SafeSignature

KYBER_LEVELS = {512: 'Kyber512', 768: 'Kyber768', 1024: 'Kyber1024'}
DILITHIUM_LEVELS = {2: 'DILITHIUM_2', 3: 'DILITHIUM_3', 4: 'DILITHIUM_4'}


def _mechanism(levels, level, family):
    try:
        return levels[level]
    except (KeyError, TypeError):
        raise ValueError('unsupported {} level {!r}; expected one of {}'.format(
            family, level, sorted(levels)))


def _checked(result, operation):
    if result == 0:
        raise RuntimeError('liboqs {} failed'.format(operation))
    return result


class _Wrapper(object):
    def __init__(self, native):
        self._native = native

    @property
    def name(self):
        return self._native.details['name']

    @property
    def details(self):
        return dict(self._native.details)

    def free(self):
        self._native.free()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.free()


class KyberKEM(_Wrapper):
    """Kyber KEM at security level 512, 768 or 1024."""

    def __init__(self, level=768):
        super().__init__(SafeKeyEncapsulation(_mechanism(KYBER_LEVELS, level, 'Kyber')))
        self.level = level

    def keypair(self):
        """Generate a keypair, keep the secret key and return the public key."""
        return _checked(self._native.generate_keypair(), 'keypair')

    def encapsulate(self, public_key):
        """Return (ciphertext, shared_secret) for the given public key."""
        ciphertext, shared_secret = self._native.encap_secret(public_key)
        return ciphertext, _checked(shared_secret, 'encapsulate')

    def decapsulate(self, ciphertext):
        """Return the shared secret recovered with this object's secret key."""
        return _checked(self._native.decap_secret(ciphertext), 'decapsulate')


class DilithiumSigner(_Wrapper):
    """Dilithium signatures at level 2, 3 or 4."""

    def __init__(self, level=3):
        super().__init__(SafeSignature(_mechanism(DILITHIUM_LEVELS, level, 'Dilithium')))
        self.level = level

    def keypair(self):
        """Generate a keypair, keep the secret key and return the public key."""
        return _checked(self._native.generate_keypair(), 'keypair')

    def sign(self, message):
        return _checked(self._native.sign(message), 'sign')

    def verify(self, message, signature, public_key):
        return self._native.verify(message, signature, public_key)
