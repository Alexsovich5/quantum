"""
Cost figures for the post-quantum replacements quoted by the roadmap.

``run`` times key generation, encapsulation / decapsulation or signing /
verification for each named liboqs mechanism on the local machine and
returns ``BenchResult`` dicts (docs/SPEC.md section 5.2) with object sizes
and mean operation times in milliseconds. Nothing is persisted.
"""

import time

import oqs

from quantum_tool.algorithms import SafeKeyEncapsulation, SafeSignature

DEFAULT_ALGORITHMS = (
    'Kyber512',
    'Kyber768',
    'DILITHIUM_2',
    'DILITHIUM_3',
    'SPHINCS+-SHA256-128f-simple',
)

_MESSAGE = b'quantum migration cost benchmark'


def _mean_ms(operation, iterations):
    """Call ``operation`` ``iterations`` times; return (mean ms, last result)."""
    result = None
    total = 0.0
    for _ in range(iterations):
        start = time.perf_counter()
        result = operation()
        total += time.perf_counter() - start
    return total * 1000.0 / iterations, result


def _bench_kem(name, iterations):
    with SafeKeyEncapsulation(name) as kem:
        details = kem.details
        keygen_ms, public_key = _mean_ms(kem.generate_keypair, iterations)
        encap_ms, (ciphertext, shared_secret) = _mean_ms(
            lambda: kem.encap_secret(public_key), iterations)
        decap_ms, recovered = _mean_ms(lambda: kem.decap_secret(ciphertext), iterations)
    if recovered != shared_secret:
        raise RuntimeError('{} decapsulation did not recover the shared secret'.format(name))
    return {
        'algorithm': name,
        'kind': 'kem',
        'public_key_len': details['length_public_key'],
        'secret_key_len': details['length_secret_key'],
        'ciphertext_len': details['length_ciphertext'],
        'keygen_ms': keygen_ms,
        'encap_ms': encap_ms,
        'decap_ms': decap_ms,
    }


def _bench_sig(name, iterations):
    with SafeSignature(name) as signer:
        details = signer.details
        keygen_ms, public_key = _mean_ms(signer.generate_keypair, iterations)
        sign_ms, signature = _mean_ms(lambda: signer.sign(_MESSAGE), iterations)
        verify_ms, valid = _mean_ms(
            lambda: signer.verify(_MESSAGE, signature, public_key), iterations)
    if not valid:
        raise RuntimeError('{} failed to verify its own signature'.format(name))
    return {
        'algorithm': name,
        'kind': 'sig',
        'public_key_len': details['length_public_key'],
        'secret_key_len': details['length_secret_key'],
        'signature_len': details['length_signature'],
        'keygen_ms': keygen_ms,
        'sign_ms': sign_ms,
        'verify_ms': verify_ms,
    }


def run(names=DEFAULT_ALGORITHMS, iterations=10):
    """Benchmark each mechanism in ``names`` and return a list of BenchResult dicts."""
    if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1:
        raise ValueError('iterations must be a positive integer, got {!r}'.format(iterations))
    kems = set(oqs.get_enabled_KEM_mechanisms())
    sigs = set(oqs.get_enabled_sig_mechanisms())
    unknown = [name for name in names if name not in kems and name not in sigs]
    if unknown:
        raise ValueError('unknown or disabled liboqs mechanism(s): {}'.format(
            ', '.join(unknown)))
    return [
        _bench_kem(name, iterations) if name in kems else _bench_sig(name, iterations)
        for name in names
    ]
