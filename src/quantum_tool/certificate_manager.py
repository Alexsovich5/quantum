"""
Inventory X.509 certificates and private-key files.

Certificates (PEM or DER) are reduced to CertInfo records and private keys to
KeyInfo records as described in docs/SPEC.md section 5.2. A KeyInfo carries
only the key's type, size, curve and source path, never key material.
"""

import logging
import os
import re

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

logger = logging.getLogger('certificate_manager')

FILE_EXTENSIONS = ('.pem', '.crt', '.cer', '.der', '.key')

PEM_BLOCK = re.compile(
    rb'-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----', re.DOTALL)
CERT_LABELS = (b'CERTIFICATE', b'X509 CERTIFICATE')
TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def _key_details(key):
    """Return (key_type, key_bits, curve) for a public or private key object."""
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return 'RSA', key.key_size, None
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return 'EC', key.curve.key_size, key.curve.name
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return 'DSA', key.key_size, None
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return 'Ed25519', 256, None
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return 'Ed448', 456, None
    raise ValueError('unsupported key type: %s' % type(key).__name__)


def _is_pem(data):
    return b'-----BEGIN ' in data


def _signature_hash(cert):
    try:
        algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        return 'unknown'
    # Ed25519 / Ed448 signatures do not use a separate hash.
    return algorithm.name if algorithm is not None else 'none'


def parse_certificate(data, source='network'):
    """Parse a PEM or DER certificate into a CertInfo dict.

    Raises ValueError if data is not a certificate.
    """
    backend = default_backend()
    try:
        if _is_pem(data):
            cert = x509.load_pem_x509_certificate(data, backend)
        else:
            cert = x509.load_der_x509_certificate(data, backend)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError('not a certificate: %s' % exc)

    key_type, key_bits, curve = _key_details(cert.public_key())
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial': format(cert.serial_number, 'x'),
        'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex(),
        'key_type': key_type,
        'key_bits': key_bits,
        'curve': curve,
        'signature_hash': _signature_hash(cert),
        'not_before': cert.not_valid_before.strftime(TIME_FORMAT),
        'not_after': cert.not_valid_after.strftime(TIME_FORMAT),
        'source': source,
    }


def parse_private_key(data, source):
    """Describe a PEM or DER private key as a KeyInfo dict.

    The key is loaded with no password; an encrypted key is reported with
    key_type "encrypted". Raises ValueError if data is not a private key.
    """
    backend = default_backend()
    try:
        if _is_pem(data):
            key = serialization.load_pem_private_key(data, password=None, backend=backend)
        else:
            key = serialization.load_der_private_key(data, password=None, backend=backend)
    except TypeError:
        # cryptography raises TypeError when a key needs a password that was not given.
        return {'source': source, 'key_type': 'encrypted', 'key_bits': None, 'curve': None}
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError('not a private key: %s' % exc)

    key_type, key_bits, curve = _key_details(key)
    return {'source': source, 'key_type': key_type, 'key_bits': key_bits, 'curve': curve}


def load_file(path):
    """Parse every certificate and private key in one file.

    PEM files may hold several blocks (for example a certificate followed by
    its key); blocks of other types are ignored. DER files hold one object.
    Raises ValueError if the file contains no certificate or private key.
    """
    with open(path, 'rb') as fh:
        data = fh.read()

    result = {'certificates': [], 'keys': []}
    if _is_pem(data):
        for match in PEM_BLOCK.finditer(data):
            label, block = match.group(1), match.group(0)
            try:
                if label in CERT_LABELS:
                    result['certificates'].append(parse_certificate(block, path))
                elif label.endswith(b'PRIVATE KEY'):
                    result['keys'].append(parse_private_key(block, path))
            except ValueError as exc:
                logger.debug("Skipping %s block in %s: %s", label.decode(), path, exc)
    else:
        try:
            result['certificates'].append(parse_certificate(data, path))
        except ValueError:
            try:
                result['keys'].append(parse_private_key(data, path))
            except ValueError:
                pass

    if not result['certificates'] and not result['keys']:
        raise ValueError('no certificate or private key found in %s' % path)
    return result


def _candidate_files(path):
    found = []
    for root, _dirs, files in os.walk(path):
        for name in files:
            if name.lower().endswith(FILE_EXTENSIONS):
                found.append(os.path.join(root, name))
    return sorted(found)


def scan_directory(path):
    """Inventory certificate and key files below path, recursively.

    Files are visited in sorted path order. Certificates are deduplicated by
    SHA-256 fingerprint, keeping the first file as source. Unparsable files
    are skipped with a warning.
    """
    if not os.path.isdir(path):
        raise ValueError('not a directory: %s' % path)

    certificates, keys, seen = [], [], set()
    for file_path in _candidate_files(path):
        try:
            found = load_file(file_path)
        except (OSError, ValueError) as exc:
            logger.warning("Skipping %s: %s", file_path, exc)
            continue
        for cert in found['certificates']:
            if cert['fingerprint_sha256'] not in seen:
                seen.add(cert['fingerprint_sha256'])
                certificates.append(cert)
        keys.extend(found['keys'])

    return {'certificates': certificates, 'keys': keys}
