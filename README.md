# Quantum-Ready Cryptography Migration Tool

A Python command-line tool that inventories TLS endpoints, certificates and private-key files,
scores how exposed each one is to quantum attacks (Shor, Grover) and to already-broken classical
primitives, and writes a prioritised migration roadmap toward the NIST round-2 post-quantum
candidates CRYSTALS-Kyber, CRYSTALS-Dilithium and SPHINCS+. The post-quantum primitives come from
the Open Quantum Safe `liboqs` library, which the tool also uses to measure key, ciphertext and
signature sizes and operation times on the local machine so the roadmap can quote them.

Personal project built on the 2020-era stack (Python 3.8, pyOpenSSL, cryptography, liboqs 0.3.0).

## Status

**Implemented**

- Target expansion: hostnames, IPs and CIDR blocks, with a `max_hosts` guard (`src/quantum_tool/config.py`)
- Threaded TLS scanner recording protocol, negotiated suite, key bits and peer certificate; unreachable and non-TLS endpoints are reported as `unreachable` / `no_tls` (`src/quantum_tool/crypto_scanner.py`)
- Cipher-suite enumeration with pyOpenSSL: one TLS 1.2 handshake per candidate suite to record the server-offered set, plus a separate TLS 1.3 support check
- Cipher-suite parsing into key exchange, authentication, bulk cipher and MAC (`src/quantum_tool/cipher_suites.py`)
- Certificate and private-key inventory from the network and from `cert_paths` directories, deduplicated by SHA-256 fingerprint; key material is never emitted (`src/quantum_tool/certificate_manager.py`)
- Vulnerability assessor mapping each algorithm to a threat class and level, with a documented 0–100 risk score (`src/quantum_tool/vulnerability_assessor.py`)
- Kyber and Dilithium wrappers (`src/quantum_tool/algorithms/lattice_based.py`) and SPHINCS+ wrappers (`src/quantum_tool/algorithms/hash_based.py`) over liboqs-python
- Benchmark of key generation, encapsulation/decapsulation and sign/verify times and object sizes (`src/quantum_tool/algorithms/benchmark.py`)
- Migration engine grouping findings by vulnerable algorithm, ordered by risk, with PQC replacements, a hybrid interim recommendation and benchmark figures (`src/quantum_tool/migration_engine.py`)
- JSON scan reports and a Jinja2-rendered Markdown roadmap (`src/quantum_tool/report.py`)
- Click CLI: `scan`, `certs`, `bench` and `roadmap`, run as `python -m quantum_tool` (`src/quantum_tool/cli.py`)
- Validated YAML configuration (`config/scan_config.yml`, `config/scan_config.docker.yml`)

**Not implemented / known limitations**

- The "enterprise network" is simulated by three nginx 1.18 containers (`tls-rsa`, `tls-ecdsa`, `tls-legacy`) serving self-signed test certificates from `tests/fixtures/tls/`. The tool has never been run against real infrastructure; the 10.0.x.0/24 targets in `config/scan_config.yml` are example values only.
- Only TLS endpoints and PEM/DER certificate and private-key files are inventoried; no SSH, IPsec, code-signing, database or source-code scanning, and no agent-based discovery.
- Key management stops at inventory: no key generation, rotation, storage or HSM integration.
- Migrations are planned, never applied: the tool does not reconfigure servers, re-issue certificates or issue post-quantum X.509 certificates, and does not perform PQC TLS handshakes (stock OpenSSL 1.1.1 and pyOpenSSL 19.1 cannot).
- Protocols below TLS 1.2 are not detected; a TLS 1.0/1.1-only server is recorded as `no_tls`.
- TLS 1.3 cipher suites and key-exchange groups are not enumerated (no pyOpenSSL 19.1 API); TLS 1.3 is recorded as supported or not.
- Enumeration only covers suites known to Debian's OpenSSL 1.1.1d. That build has no 3DES suites, so `DES-CBC3-SHA` can never be detected and `tls-legacy` falls back to `AES128-SHA` plus a SHA-1 certificate.
- liboqs-python 0.3.0 has a use-after-free in `free()` (it reads the secret-key length after freeing the native object). The wrappers subclass `KeyEncapsulation` and `Signature` and override `free()` to cleanse the secret key first, then free, guarded against double free.
- liboqs 0.3.0 implements NIST round-2 parameter sets, which are not interoperable with the later standardised ML-KEM / ML-DSA / SLH-DSA.
- The risk score is a transparent heuristic, not a formal threat model.
- The `nginx:1.18.0` image on Docker Hub is a 2021 rebuild of the 1.18.0 release; it is pinned by digest.
- No web UI; output is JSON and Markdown only.

## Built with

- **Python 3.8.3** (`python:3.8.3-buster` image, Debian OpenSSL 1.1.1d) — cryptography 2.9.2 (built from source against the system OpenSSL), pyOpenSSL 19.1.0, PyYAML 5.3.1, click 7.1.2, Jinja2 2.11.2, MarkupSafe 1.1.1, cffi 1.14.0, pycparser 2.20, six 1.15.0
- **liboqs 0.3.0** (commit `f6ca3dc`, built with cmake 3.13.4 and ninja 1.8.2) and **liboqs-python 0.3.0** (commit `97e500c`), both verified by sha256
- **Test and lint** — pytest 5.4.3, pytest-cov 2.10.0, coverage 5.1, flake8 3.8.3
- **Test targets** — nginx 1.18.0; docker-compose 1.26.0 (or `make COMPOSE="docker compose"` with the Compose v2 plugin)

Exact pins are in `requirements.txt`, `requirements-dev.txt`, `requirements-build.txt`, the `Dockerfile` and `docker-compose.yml`.

## Running it

Everything runs in Docker images from the project's era, so nothing needs installing locally beyond Docker.

```bash
make build                                          # build the app image (compiles liboqs)
docker-compose up -d tls-rsa tls-ecdsa tls-legacy   # start the three simulated TLS endpoints
make demo                                           # scan them and write a roadmap to reports/
```

`make demo` runs `python -m quantum_tool roadmap -c config/scan_config.docker.yml` and writes
a JSON scan report and a Markdown roadmap into the `output_path` directory (default `reports`). Other commands:

```bash
docker-compose run --rm app python -m quantum_tool certs tests/fixtures/tls
docker-compose run --rm app python -m quantum_tool bench -n 5
docker-compose run --rm app python -m quantum_tool scan -c config/scan_config.docker.yml --fail-on critical
```

## Tests

```bash
make test                # runs the suite inside the period image
make unit                # unit tests only, no nginx containers
make lint                # flake8
```

Unit tests cover config validation, cipher-suite parsing, certificate and key parsing, threat
mapping and the risk-score arithmetic, the liboqs wrappers and benchmark, roadmap building, report
rendering and the CLI, using in-process fake TLS servers; integration tests scan the three nginx
containers and check offered suites and the exact risk scores (85 / 70 / 60). Nothing is tested
against real hosts, and benchmark tests only check that timings are positive, not how fast they are.

`python scripts/check_readme.py` checks that every path named in this README exists.

## Layout

The tree below is the output of `docker-compose run --rm app python scripts/check_readme.py --tree`.

```
.dockerignore
.gitignore
config/
  scan_config.docker.yml
  scan_config.yml
docker-compose.yml
docker/
  nginx/
    openssl-legacy.cnf
    tls-ecdsa.conf
    tls-legacy.conf
    tls-rsa.conf
Dockerfile
docs/
  IMPLEMENTATION_PLAN.md
  SPEC.md
Makefile
README.md
requirements-build.txt
requirements-dev.txt
requirements.txt
scripts/
  check_readme.py
  gen_test_certs.sh
setup.cfg
setup.py
src/
  quantum_tool/
    __init__.py
    __main__.py
    algorithms/
      __init__.py
      benchmark.py
      hash_based.py
      lattice_based.py
    certificate_manager.py
    cipher_suites.py
    cli.py
    config.py
    crypto_scanner.py
    migration_engine.py
    report.py
    templates/
      roadmap.md.j2
    vulnerability_assessor.py
tests/
  __init__.py
  fixtures/
    tls/
      dhparam-2048.pem
      ec-p256-sha256-cert.pem
      ec-p256-sha256-key.pem
      rsa2048-sha1-cert.pem
      rsa2048-sha1-key.pem
      rsa2048-sha256-cert.der
      rsa2048-sha256-cert.pem
      rsa2048-sha256-key.pem
  integration/
    __init__.py
    conftest.py
    test_cli_end_to_end.py
    test_enumeration.py
    test_scan_host.py
  unit/
    __init__.py
    fakes.py
    test_benchmark.py
    test_certificate_manager.py
    test_cipher_suites.py
    test_cli.py
    test_config.py
    test_crypto_scanner.py
    test_enumeration.py
    test_environment.py
    test_hash_based.py
    test_lattice_based.py
    test_migration_engine.py
    test_report.py
    test_smoke.py
    test_vulnerability_assessor.py
    tls_server.py
```
