"""
Cryptographic Scanner
IT Operations Specialist - ACORIA (2020)

Scans infrastructure for cryptographic implementations,
identifies quantum-vulnerable algorithms, and generates
migration recommendations.
"""

import ssl
import socket
import logging
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger('crypto_scanner')

# Algorithms vulnerable to quantum attacks
QUANTUM_VULNERABLE = {
    'RSA': {'threat': 'critical', 'alternative': 'CRYSTALS-Dilithium'},
    'ECDSA': {'threat': 'critical', 'alternative': 'CRYSTALS-Dilithium'},
    'ECDH': {'threat': 'critical', 'alternative': 'CRYSTALS-Kyber'},
    'DSA': {'threat': 'critical', 'alternative': 'CRYSTALS-Dilithium'},
    'DH': {'threat': 'critical', 'alternative': 'CRYSTALS-Kyber'},
}

QUANTUM_SAFE = ['AES-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-512']


class CryptoScanner:
    """Scans network hosts for cryptographic implementations."""

    def __init__(self, config):
        self.targets = config.get('targets', [])
        self.ports = config.get('ports', [443, 8443, 993, 995])
        self.timeout = config.get('timeout', 10)
        self.max_workers = config.get('max_workers', 20)

    def scan_all(self):
        """Scan all configured targets."""
        logger.info("Starting crypto scan on %d targets", len(self.targets))
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for target in self.targets:
                for port in self.ports:
                    futures.append(executor.submit(self.scan_host, target, port))

            for future in futures:
                result = future.result()
                if result:
                    results.append(result)

        return self._generate_report(results)

    def scan_host(self, host, port):
        """Scan a single host:port for TLS/crypto configuration."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    result = {
                        'host': host,
                        'port': port,
                        'protocol': protocol,
                        'cipher_suite': cipher[0] if cipher else 'unknown',
                        'key_exchange': self._extract_key_exchange(cipher),
                        'auth_algorithm': self._extract_auth(cipher),
                        'key_bits': cipher[2] if cipher else 0,
                        'certificate': self._analyze_cert(cert),
                        'scan_time': datetime.utcnow().isoformat(),
                        'vulnerabilities': []
                    }

                    result['vulnerabilities'] = self._assess_vulnerabilities(result)
                    return result

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug("Cannot connect to %s:%d - %s", host, port, e)
            return None

    def _extract_key_exchange(self, cipher):
        if not cipher:
            return 'unknown'
        name = cipher[0]
        if 'ECDH' in name:
            return 'ECDH'
        elif 'DHE' in name or 'DH' in name:
            return 'DH'
        elif 'RSA' in name:
            return 'RSA'
        return 'unknown'

    def _extract_auth(self, cipher):
        if not cipher:
            return 'unknown'
        name = cipher[0]
        if 'ECDSA' in name:
            return 'ECDSA'
        elif 'RSA' in name:
            return 'RSA'
        return 'unknown'

    def _analyze_cert(self, cert_binary):
        """Basic certificate analysis."""
        if not cert_binary:
            return {}
        return {
            'size_bytes': len(cert_binary),
            'needs_migration': True  # All current PKI certs need PQC migration
        }

    def _assess_vulnerabilities(self, scan_result):
        """Assess quantum vulnerabilities in scan results."""
        vulns = []
        kex = scan_result.get('key_exchange', '')
        auth = scan_result.get('auth_algorithm', '')

        if kex in QUANTUM_VULNERABLE:
            info = QUANTUM_VULNERABLE[kex]
            vulns.append({
                'type': 'key_exchange',
                'algorithm': kex,
                'threat_level': info['threat'],
                'recommendation': f"Migrate to {info['alternative']}"
            })

        if auth in QUANTUM_VULNERABLE:
            info = QUANTUM_VULNERABLE[auth]
            vulns.append({
                'type': 'authentication',
                'algorithm': auth,
                'threat_level': info['threat'],
                'recommendation': f"Migrate to {info['alternative']}"
            })

        return vulns

    def _generate_report(self, results):
        """Generate scan summary report."""
        total = len(results)
        vulnerable = sum(1 for r in results if r['vulnerabilities'])

        return {
            'scan_date': datetime.utcnow().isoformat(),
            'total_endpoints': total,
            'vulnerable_endpoints': vulnerable,
            'risk_percentage': round(vulnerable / total * 100, 1) if total else 0,
            'results': results,
            'summary': {
                'critical': sum(1 for r in results for v in r['vulnerabilities'] if v['threat_level'] == 'critical'),
                'quantum_safe': total - vulnerable
            }
        }
