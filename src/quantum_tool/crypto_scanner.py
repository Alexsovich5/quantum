"""
Cryptographic Scanner

Scans infrastructure for cryptographic implementations,
identifies quantum-vulnerable algorithms, and generates
migration recommendations.
"""

import ipaddress
import select
import ssl
import socket
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from OpenSSL import SSL

from quantum_tool.certificate_manager import parse_certificate
from quantum_tool.cipher_suites import parse_suite
from quantum_tool.config import DEFAULTS, expand_targets
from quantum_tool.vulnerability_assessor import (  # noqa: F401  (re-exported)
    QUANTUM_SAFE, QUANTUM_VULNERABLE, assess_endpoint, assess_suite)

logger = logging.getLogger('crypto_scanner')

# Every TLS 1.2 suite the local OpenSSL can offer, minus PSK, SRP and anonymous
# suites (which never authenticate a server). SECLEVEL=0 overrides the system
# policy so weak suites such as 3DES can still be probed.
CANDIDATE_CIPHERS = b"ALL:COMPLEMENTOFALL:!PSK:!SRP:!aNULL:@SECLEVEL=0"


class CryptoScanner:
    """Scans network hosts for cryptographic implementations."""

    def __init__(self, config):
        self.targets = config.get('targets', [])
        self.ports = config.get('ports', [443, 8443, 993, 995])
        self.timeout = config.get('timeout', 10)
        self.max_workers = config.get('max_workers', 20)
        self.max_hosts = config.get('max_hosts', DEFAULTS['max_hosts'])
        self.enumerate = config.get('enumerate_ciphers', DEFAULTS['enumerate_ciphers'])

    def scan_all(self):
        """Scan all configured targets."""
        hosts = expand_targets(self.targets, self.max_hosts)
        logger.info("Starting crypto scan on %d hosts from %d targets",
                    len(hosts), len(self.targets))
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for host in hosts:
                for port in self.ports:
                    futures.append(executor.submit(self.scan_host, host, port))

            for future in futures:
                results.append(future.result())

        return self._generate_report(results)

    def scan_host(self, host, port):
        """Scan a single host:port for TLS/crypto configuration.

        Returns the scan result with ``status: ok``, or an Endpoint with
        ``status: unreachable`` (TCP connect failed) or ``no_tls`` (TCP connected
        but no TLS 1.2+ handshake completed). With ``enumerate_ciphers`` on,
        ``offered_suites`` lists every TLS 1.2 suite the server accepts and
        ``tls13`` comes from a dedicated TLS 1.3-only handshake.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
        except OSError as e:
            logger.debug("Cannot connect to %s:%d - %s", host, port, e)
            return self._failed_endpoint(host, port, 'unreachable')

        with sock:
            try:
                ssock = context.wrap_socket(sock, server_hostname=host)
            except OSError as e:
                logger.debug("No TLS handshake with %s:%d - %s", host, port, e)
                return self._failed_endpoint(host, port, 'no_tls')

            with ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                protocol = ssock.version()

                result = {
                    'host': host,
                    'port': port,
                    'status': 'ok',
                    'protocol': protocol,
                    'tls13': protocol == 'TLSv1.3',
                    'negotiated_suite': cipher[0] if cipher else None,
                    'offered_suites': [],
                    'cipher_suite': cipher[0] if cipher else 'unknown',
                    'key_exchange': self._extract_key_exchange(cipher),
                    'auth_algorithm': self._extract_auth(cipher),
                    'key_bits': cipher[2] if cipher else 0,
                    'certificate': self._analyze_cert(cert),
                    'scan_time': datetime.utcnow().isoformat(),
                    'vulnerabilities': []
                }

                result['vulnerabilities'] = self._assess_vulnerabilities(result)

        if self.enumerate:
            result['offered_suites'] = self.enumerate_ciphers(host, port)
            result['tls13'] = self.supports_tls13(host, port)
        return result

    @staticmethod
    def candidate_suites():
        """TLS 1.2 suite names the local OpenSSL can offer, in OpenSSL's order."""
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        context.set_cipher_list(CANDIDATE_CIPHERS)
        names = SSL.Connection(context, None).get_cipher_list()
        # OpenSSL 1.1.1 also lists the TLS 1.3 suites, which TLSv1_2_METHOD never offers.
        return [name for name in names if not name.startswith('TLS_')]

    def enumerate_ciphers(self, host, port):
        """Return the TLS 1.2 suites host:port accepts, one handshake per candidate."""
        return [name for name in self.candidate_suites()
                if self._accepts_suite(host, port, name)]

    def _accepts_suite(self, host, port, name):
        # TLSv1_2_METHOD is fixed-version, so TLS 1.3 is never offered.
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        try:
            context.set_cipher_list((name + ':@SECLEVEL=0').encode('ascii'))
        except SSL.Error:
            return False
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
        except OSError:
            return False
        with sock:
            conn = SSL.Connection(context, sock)
            if not _is_ip_address(host):
                conn.set_tlsext_host_name(host.encode('idna'))
            conn.set_connect_state()
            try:
                self._handshake(conn, sock)
            except (SSL.Error, OSError) as e:
                logger.debug("%s:%d rejects %s - %s", host, port, name, e)
                return False
            accepted = conn.get_cipher_name() == name
            try:
                conn.shutdown()
            except (SSL.Error, OSError):
                pass
            return accepted

    def _handshake(self, conn, sock):
        """Drive a pyOpenSSL handshake on a socket that has a timeout set."""
        while True:
            try:
                conn.do_handshake()
                return
            except SSL.WantReadError:
                ready = select.select([sock], [], [], self.timeout)[0]
            except SSL.WantWriteError:
                ready = select.select([], [sock], [], self.timeout)[1]
            if not ready:
                raise socket.timeout('TLS handshake timed out')

    def supports_tls13(self, host, port):
        """True when host:port completes a handshake restricted to TLS 1.3."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.version() == 'TLSv1.3'
        except OSError:
            return False

    @staticmethod
    def _failed_endpoint(host, port, status):
        """Endpoint record for a host:port where no TLS session was established."""
        return {
            'host': host,
            'port': port,
            'status': status,
            'protocol': None,
            'tls13': False,
            'negotiated_suite': None,
            'offered_suites': [],
            'key_bits': None,
            'certificate': None,
            'scan_time': datetime.utcnow().isoformat(),
        }

    def _extract_key_exchange(self, cipher):
        if not cipher:
            return 'unknown'
        return parse_suite(cipher[0])['kex']

    def _extract_auth(self, cipher):
        if not cipher:
            return 'unknown'
        return parse_suite(cipher[0])['auth']

    def _analyze_cert(self, cert_binary):
        """Parse the peer's DER certificate; None if absent or unparsable."""
        if not cert_binary:
            return None
        try:
            return parse_certificate(cert_binary, source='network')
        except ValueError as e:
            logger.warning("Cannot parse peer certificate: %s", e)
            return None

    def _assess_vulnerabilities(self, scan_result):
        """Summarise the Shor findings of the negotiated suite in the original shape."""
        vulns = []
        for finding in assess_suite(scan_result.get('cipher_suite')):
            if finding['threat_class'] != 'shor':
                continue
            algorithm = finding['algorithm']
            alternative = QUANTUM_VULNERABLE.get(algorithm, {}).get(
                'alternative', 'CRYSTALS-Dilithium')
            vulns.append({
                'type': finding['component'],
                'algorithm': algorithm,
                'threat_level': finding['threat_level'],
                'recommendation': f"Migrate to {alternative}"
            })
        return vulns

    def _generate_report(self, endpoints):
        """Generate scan summary report; totals cover only endpoints with a TLS session."""
        results = [r for r in endpoints if r.get('status', 'ok') == 'ok']
        unreachable = sum(1 for r in endpoints if r.get('status') == 'unreachable')
        total = len(results)
        vulnerable = sum(1 for r in results if r['vulnerabilities'])

        return {
            'scan_date': datetime.utcnow().isoformat(),
            'total_endpoints': total,
            'vulnerable_endpoints': vulnerable,
            'risk_percentage': round(vulnerable / total * 100, 1) if total else 0,
            'unreachable': unreachable,
            'results': results,
            'assessments': [assess_endpoint(r) for r in results],
            'summary': {
                'critical': sum(
                    1 for r in results for v in r['vulnerabilities']
                    if v['threat_level'] == 'critical'
                ),
                'quantum_safe': total - vulnerable
            }
        }


def _is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
