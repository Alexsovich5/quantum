"""
Decompose OpenSSL (TLS 1.2 and earlier) and IANA (TLS 1.3) cipher-suite names
into key exchange, authentication, bulk cipher, cipher key size and MAC hash.

Field values follow the CipherSuite record in docs/SPEC.md section 5.2.
"""

UNKNOWN = 'unknown'

# TLS 1.3 suites do not name key exchange or authentication: the key
# exchange is always (EC)DHE and authentication comes from the certificate.
TLS13_SUITES = {
    'TLS_AES_128_GCM_SHA256': ('AES-128-GCM', 128),
    'TLS_AES_256_GCM_SHA384': ('AES-256-GCM', 256),
    'TLS_CHACHA20_POLY1305_SHA256': ('CHACHA20-POLY1305', 256),
    'TLS_AES_128_CCM_SHA256': ('AES-128-CCM', 128),
    'TLS_AES_128_CCM_8_SHA256': ('AES-128-CCM8', 128),
}

# OpenSSL name prefixes -> (kex, auth); longest prefixes are tried first.
# A name without any of these prefixes uses static RSA key exchange.
PREFIXES = {
    'ECDHE-ECDSA': ('ECDH', 'ECDSA'),
    'ECDHE-RSA': ('ECDH', 'RSA'),
    'ECDH-ECDSA': ('ECDH', 'ECDSA'),
    'ECDH-RSA': ('ECDH', 'RSA'),
    # OpenSSL names the ECDHE-RSA ARIA suites ECDHE-ARIA128-GCM-SHA256 and so on.
    'ECDHE': ('ECDH', 'RSA'),
    'DHE-RSA': ('DH', 'RSA'),
    'DHE-DSS': ('DH', 'DSS'),
    'EDH-RSA': ('DH', 'RSA'),
    'EDH-DSS': ('DH', 'DSS'),
    'DH-RSA': ('DH', 'RSA'),
    'DH-DSS': ('DH', 'DSS'),
    'ECDHE-PSK': ('PSK', 'PSK'),
    'DHE-PSK': ('PSK', 'PSK'),
    'RSA-PSK': ('PSK', 'PSK'),
    'PSK': ('PSK', 'PSK'),
    'SRP-RSA': ('SRP', 'RSA'),
    'SRP-DSS': ('SRP', 'DSS'),
    'SRP': ('SRP', 'SRP'),
    'AECDH': ('ECDH', 'other'),
    'ADH': ('DH', 'other'),
    'EXP1024': ('other', 'other'),
    'EXP': ('other', 'other'),
}

MAC_SUFFIXES = {
    'SHA': 'SHA1',
    'SHA256': 'SHA256',
    'SHA384': 'SHA384',
    'MD5': 'MD5',
}

AEAD_MODES = ('GCM', 'CCM', 'CCM8')

# Bulk-cipher spellings (the part between the prefix and the MAC suffix)
# that are not of the form <ALG><BITS>[-<MODE>].
FIXED_CIPHERS = {
    'CHACHA20-POLY1305': ('CHACHA20-POLY1305', 256),
    'DES-CBC3': ('3DES-CBC', 168),
    '3DES-EDE-CBC': ('3DES-CBC', 168),
    'DES-CBC': ('DES-CBC', 56),
    'RC4': ('RC4', 128),
    'SEED': ('SEED-CBC', 128),
    'IDEA-CBC': ('IDEA-CBC', 128),
    'IDEA': ('IDEA-CBC', 128),
    'NULL': ('NULL', 0),
}

BLOCK_ALGORITHMS = ('AES', 'CAMELLIA', 'ARIA')
KEY_SIZES = ('128', '256')


def _unknown(name):
    return {
        'name': name,
        'kex': UNKNOWN,
        'auth': UNKNOWN,
        'cipher': UNKNOWN,
        'cipher_bits': None,
        'mac': UNKNOWN,
    }


def _parse_block_cipher(tokens):
    """Parse AES128, AES128-GCM, AES-128-CBC, CAMELLIA256, ARIA128-GCM ..."""
    if not tokens:
        return None
    head, rest = tokens[0], list(tokens[1:])
    algorithm = next((a for a in BLOCK_ALGORITHMS if head.startswith(a)), None)
    if algorithm is None:
        return None
    bits = head[len(algorithm):]
    if not bits and rest:
        # SRP/PSK spelling: AES-128-CBC
        bits = rest.pop(0)
    if bits not in KEY_SIZES:
        return None
    if not rest:
        mode = 'CBC'
    elif rest == ['CBC'] or (len(rest) == 1 and rest[0] in AEAD_MODES):
        mode = rest[0]
    else:
        return None
    return '%s-%s-%s' % (algorithm, bits, mode), int(bits)


def _parse_cipher(tokens):
    fixed = FIXED_CIPHERS.get('-'.join(tokens))
    if fixed:
        return fixed
    return _parse_block_cipher(tokens)


def _parse_tls13(name, upper):
    entry = TLS13_SUITES.get(upper)
    if entry is None:
        return _unknown(name)
    cipher, bits = entry
    return {
        'name': name,
        'kex': 'ECDH',
        'auth': 'cert',
        'cipher': cipher,
        'cipher_bits': bits,
        'mac': 'AEAD',
    }


def _split_prefix(tokens):
    for prefix in sorted(PREFIXES, key=lambda p: -p.count('-')):
        parts = prefix.split('-')
        if tokens[:len(parts)] == parts:
            return PREFIXES[prefix], tokens[len(parts):]
    return ('RSA', 'RSA'), tokens


def parse_suite(name):
    """Return a CipherSuite dict for an OpenSSL or TLS 1.3 IANA suite name.

    Names that cannot be decomposed give 'unknown' fields; this never raises.
    """
    if not isinstance(name, str) or not name.strip():
        return _unknown(name)
    upper = name.strip().upper()
    if upper.startswith('TLS_'):
        return _parse_tls13(name, upper)

    tokens = upper.split('-')
    (kex, auth), tokens = _split_prefix(tokens)

    mac = None
    if tokens and tokens[-1] in MAC_SUFFIXES:
        mac = MAC_SUFFIXES[tokens[-1]]
        tokens = tokens[:-1]

    parsed = _parse_cipher(tokens)
    if parsed is None:
        return _unknown(name)
    cipher, bits = parsed

    if cipher.endswith(AEAD_MODES) or cipher == 'CHACHA20-POLY1305':
        mac = 'AEAD'
    elif mac is None:
        return _unknown(name)

    return {
        'name': name,
        'kex': kex,
        'auth': auth,
        'cipher': cipher,
        'cipher_bits': bits,
        'mac': mac,
    }
