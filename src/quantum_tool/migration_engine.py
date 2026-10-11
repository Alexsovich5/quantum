"""
Turn assessments into an ordered post-quantum migration roadmap.

``build_roadmap`` groups every actionable finding (threat class other than
``none``) by ``(component, algorithm)``, so each phase covers one algorithm
in one role across all targets that use it. Phases are ordered by the highest
risk score among their targets, then by threat class (``shor`` before
``classical`` before ``grover``), then by how many targets they cover.

Each phase names a replacement, a hybrid interim step for public-key
algorithms and, when benchmark results are supplied, the measured cost of
the replacement (docs/SPEC.md section 5.2, ``Roadmap``).
"""

from datetime import datetime

KEM_REPLACEMENT = 'Kyber768'
SIGNATURE_REPLACEMENT = 'DILITHIUM_3'
SIGNATURE_ALTERNATIVE = 'SPHINCS+-SHA256-128f-simple'
CIPHER_REPLACEMENT = 'AES-256-GCM'
MAC_REPLACEMENT = 'AEAD suite (AES-256-GCM or CHACHA20-POLY1305)'
HASH_REPLACEMENT = 'SHA-384'

HYBRID_NOTE = ('Keep ECDHE/RSA alongside Kyber/Dilithium until PQC TLS is standardised; '
               'deploy the replacement in hybrid mode first')

# component -> {algorithm -> (replacement, alternative)}; '*' matches any algorithm.
REPLACEMENTS = {
    'key_exchange': {'*': (KEM_REPLACEMENT, None)},
    'authentication': {'*': (SIGNATURE_REPLACEMENT, SIGNATURE_ALTERNATIVE)},
    'certificate_key': {'*': (SIGNATURE_REPLACEMENT, SIGNATURE_ALTERNATIVE)},
    'cipher': {
        '3DES': (CIPHER_REPLACEMENT, None),
        'DES': (CIPHER_REPLACEMENT, None),
        'RC4': (CIPHER_REPLACEMENT, None),
        'NULL': (CIPHER_REPLACEMENT, None),
        'AES-128': (CIPHER_REPLACEMENT, None),
        'CAMELLIA-128': (CIPHER_REPLACEMENT, None),
        'ARIA-128': (CIPHER_REPLACEMENT, None),
        'SEED': (CIPHER_REPLACEMENT, None),
        'IDEA': (CIPHER_REPLACEMENT, None),
    },
    'mac': {
        'HMAC-SHA1': (MAC_REPLACEMENT, None),
        'HMAC-MD5': (MAC_REPLACEMENT, None),
        'HMAC-SHA256': (MAC_REPLACEMENT, None),
    },
    'certificate_signature': {
        'SHA-1': (HASH_REPLACEMENT, None),
        'MD5': (HASH_REPLACEMENT, None),
        'SHA-224': (HASH_REPLACEMENT, None),
        'SHA-256': (HASH_REPLACEMENT, None),
    },
}

THREAT_ORDER = {'shor': 0, 'classical': 1, 'grover': 2}
TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def replacement_for(component, algorithm, recommendation=None):
    """Return (replacement, alternative) for one finding.

    Algorithms without an entry fall back to the finding's own recommendation.
    """
    table = REPLACEMENTS.get(component, {})
    entry = table.get(algorithm) or table.get('*')
    if entry:
        return entry
    return (recommendation, None)


def _timestamp(now):
    if now is None:
        now = datetime.utcnow()
    elif now.tzinfo is not None:
        now = (now - now.utcoffset()).replace(tzinfo=None)
    return now.strftime(TIME_FORMAT)


def _bench_index(bench):
    return {result['algorithm']: result for result in (bench or [])}


def _collect(assessments):
    """Group actionable findings by (component, algorithm)."""
    groups = {}
    for assessment in assessments:
        risk = assessment.get('risk_score', 0)
        for finding in assessment.get('findings') or []:
            threat_class = finding.get('threat_class')
            if threat_class not in THREAT_ORDER:
                continue
            key = (finding['component'], finding['algorithm'])
            group = groups.get(key)
            if group is None:
                group = groups[key] = {
                    'threat_class': threat_class,
                    'recommendation': finding.get('recommendation'),
                    'targets': set(),
                    'max_risk': risk,
                }
            elif THREAT_ORDER[threat_class] < THREAT_ORDER[group['threat_class']]:
                group['threat_class'] = threat_class
            group['targets'].add(finding.get('target') or assessment.get('target'))
            group['max_risk'] = max(group['max_risk'], risk)
    return groups


def _sort_key(item):
    (component, algorithm), group = item
    return (-group['max_risk'], THREAT_ORDER[group['threat_class']],
            -len(group['targets']), component, algorithm)


def build_roadmap(assessments, bench=None, now=None):
    """Return a Roadmap dict built from ``assessments`` and optional BenchResults."""
    bench_by_algorithm = _bench_index(bench)
    phases = []
    for (component, algorithm), group in sorted(_collect(assessments).items(), key=_sort_key):
        replacement, alternative = replacement_for(component, algorithm,
                                                   group['recommendation'])
        result = bench_by_algorithm.get(replacement)
        phases.append({
            'priority': len(phases) + 1,
            'component': component,
            'algorithm': algorithm,
            'threat_class': group['threat_class'],
            'replacement': replacement,
            'alternative': alternative,
            'hybrid': HYBRID_NOTE if group['threat_class'] == 'shor' else None,
            'targets': sorted(group['targets']),
            'max_risk': group['max_risk'],
            'bench': dict(result) if result else None,
        })
    return {'generated_at': _timestamp(now), 'phases': phases}
