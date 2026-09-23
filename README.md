# Quantum-Ready Cryptography Migration Tool

Cryptographic assessment and migration tool for transitioning enterprise systems to quantum-resistant algorithms. Scans infrastructure for vulnerable cryptographic implementations and provides migration paths to post-quantum alternatives.

Personal project, built to explore detecting quantum-vulnerable TLS in practice. It is not production software — see **Status** below for exactly what is and isn't implemented.

## Status

**Implemented**

- Threaded TLS scanner over a host/port list
- Classification of negotiated key exchange and signature algorithms as quantum-vulnerable or quantum-safe
- Suggested post-quantum replacements per algorithm
- YAML scan configuration

**Not implemented / known limitations**

- Scanner only — there is no migration engine, certificate manager or PQC implementation (the earlier README claimed six source files; only one existed)
- Reads the negotiated cipher suite, not the full server-offered set
- No tests
- `pqcrypto` is listed as a dependency but is not yet used

## Built with

- **Python** — cryptography, pyOpenSSL, pqcrypto, PyYAML

## Running it

```bash
pip install -r requirements.txt
python src/crypto_scanner.py
```

## Layout

```
config/
  scan_config.yml
requirements.txt
src/
  crypto_scanner.py
```

