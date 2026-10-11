from quantum_tool import crypto_scanner
from quantum_tool.crypto_scanner import CryptoScanner, QUANTUM_VULNERABLE


def test_module_is_importable_from_src():
    assert crypto_scanner.__file__.endswith("src/quantum_tool/crypto_scanner.py")


def test_quantum_vulnerable_table_lists_public_key_algorithms():
    for name in ("RSA", "ECDH", "ECDSA", "DH", "DSA"):
        assert name in QUANTUM_VULNERABLE


def test_scanner_uses_default_ports_when_none_configured():
    scanner = CryptoScanner({})
    assert scanner.ports == [443, 8443, 993, 995]
