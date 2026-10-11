# quantum — Specification

Rebuild target: a working, period-accurate (first half of 2020) Python 3.8 command-line tool that
inventories TLS endpoints, certificates and private-key files, scores their exposure to quantum
attacks, and produces a prioritised migration roadmap toward NIST PQC round-2 candidates
(CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+), using the Open Quantum Safe `liboqs` library for
the post-quantum primitives.

## 1. Problem

Public-key algorithms used across TLS today (RSA, finite-field DH, DSA, ECDH, ECDSA) are broken
by Shor's algorithm on a large quantum computer; symmetric ciphers and hashes are weakened by
Grover's algorithm (effective security roughly halved). Some primitives still in use (3DES, RC4,
MD5, SHA-1) are already broken or deprecated by classical attacks. An operator who wants to plan a
move to post-quantum cryptography first needs to know:

1. which endpoints speak TLS and which key-exchange / authentication / cipher / hash
   algorithms they actually offer;
2. what the certificates and private keys in use are built on (key type, size, signature hash,
   validity);
3. how exposed each endpoint is, as a comparable score;
4. what to migrate to, in what order, and what the replacement algorithms cost (key, ciphertext
   and signature sizes, operation time) on the operator's own hardware.

The tool answers these four questions from a YAML config and writes JSON and Markdown reports.

## 2. In scope

1. **Target expansion** — config `targets` accept hostnames, single IPs and CIDR blocks
   (`10.0.1.0/24`); CIDRs are expanded with the stdlib `ipaddress` module (network and broadcast
   addresses skipped). A `max_hosts` guard refuses expansions larger than the configured limit.
2. **Threaded TLS scanner** (existing `CryptoScanner`, refactored) — connects to every
   host×port with a `ThreadPoolExecutor`, records negotiated protocol, cipher suite, key bits and
   the peer certificate (DER). Unreachable endpoints are recorded with a `status` of
   `unreachable`, and endpoints that accept TCP but complete no TLS 1.2+ handshake with `no_tls`,
   rather than being dropped silently.
3. **Cipher-suite enumeration** — using pyOpenSSL, the scanner builds the candidate list from
   `SSL.Context(SSL.TLSv1_2_METHOD)` with
   `ALL:COMPLEMENTOFALL:!PSK:!SRP:!aNULL:@SECLEVEL=0`, then attempts one TLS 1.2 handshake per
   candidate (`TLSv1_2_METHOD` is a fixed-version method, so TLS 1.3 is never offered) and
   records every suite the server accepts, so the report reflects the server-offered set, not
   only the negotiated suite. TLS 1.3 support is detected with a separate stdlib `ssl` handshake.
4. **Cipher-suite parsing** — an OpenSSL/IANA cipher name is decomposed into key exchange,
   authentication, bulk cipher + key size and MAC hash (enum values in §5.2). Replaces the
   substring checks in the current `_extract_key_exchange` / `_extract_auth`.
5. **Certificate and key manager** (the README's "OpenSSL 1.1: certificate and key management",
   limited to inventory) — parses DER/PEM certificates with `cryptography` (OpenSSL 1.1 backend):
   subject, issuer, public-key algorithm and size / curve, signature hash, not-before /
   not-after, SHA-256 fingerprint. Also inventories files from local directories listed under
   `cert_paths`: certificates are deduplicated by `fingerprint_sha256` (the first file in sorted
   path order is kept as `source`); unencrypted PEM/DER private keys are recorded as `KeyInfo`
   (key type, size, curve and path only; key material is never emitted) and assessed as
   `certificate_key` findings. Encrypted keys are listed with `key_type: "encrypted"` and no
   assessment.
6. **Vulnerability assessor** — maps every algorithm found to a threat class (`shor` = broken by
   a quantum computer, `classical` = already broken or deprecated today, `grover` = weakened by a
   quantum computer, `none`) and a threat level (`critical`/`high`/`medium`/`low`), and computes a
   0–100 endpoint risk score with a documented formula (§5.4). Carries forward the existing
   `QUANTUM_VULNERABLE` / `QUANTUM_SAFE` tables.
7. **PQC algorithm wrappers** (`src/quantum_tool/algorithms/`) — thin, tested wrappers over
   `liboqs-python`: `lattice_based.py` (Kyber512/768/1024 KEM, DILITHIUM_2/3/4 signatures) and
   `hash_based.py` (SPHINCS+-SHA256-128f-simple and -128s-simple signatures). Each wrapper exposes
   keypair / encapsulate / decapsulate or keypair / sign / verify plus the algorithm's key,
   ciphertext and signature lengths. The wrappers use a patched `free()` that cleanses the secret
   key before releasing the native object (see §11, use-after-free in liboqs-python 0.3.0).
8. **PQC cost figures for the roadmap** — supports the README's "Migration Roadmap": to say what
   a replacement costs, `quantum bench` runs each wrapped algorithm N times on the local machine
   and reports mean keygen / encap / decap / sign / verify time and object sizes. It is kept
   minimal (one module, no persistence); the roadmap quotes these figures per phase.
9. **Migration engine** — turns assessed findings into a prioritised roadmap: groups endpoints by
   vulnerable algorithm, orders by risk score, and for each group gives the recommended PQC
   replacement (Kyber for key exchange, Dilithium for signatures, SPHINCS+ as the conservative
   hash-based alternative, AES-256 / SHA-384+ for Grover-weakened or classically broken symmetric
   primitives), the benchmark figures for the replacement, and an interim "hybrid" recommendation
   (classical + PQC) since no standard hybrid TLS existed in 2020.
10. **Reports** — JSON (full machine-readable scan + assessment) and Markdown roadmap rendered
    with Jinja2 into `output_path`.
11. **CLI** — `quantum scan`, `quantum certs`, `quantum bench`, `quantum roadmap` (Click),
    run in the container as `python -m quantum_tool` (the `quantum` console script is installed
    by `setup.py` for use outside Docker).
12. **YAML configuration** — existing `config/scan_config.yml`, validated on load with clear error
    messages; a second `config/scan_config.docker.yml` points at the local test TLS endpoints.

## 3. Out of scope

| Feature (from original README) | Reason |
|---|---|
| "Enterprise systems" coverage beyond TLS (SSH, IPsec, code-signing, databases, source-code crypto grep) | Solo-project core is TLS + certificate/key files; other protocols each need their own prober. |
| "Full cryptographic inventory … across infrastructure" as an agent-based discovery system | Replaced by config-driven network scanning plus local certificate/key directory inventory; no agents or CMDB. |
| Key management beyond inventory (key generation, rotation, storage, HSM integration) | Changing keys is an operational action on real systems; the tool only reports what exists. |
| Automatically *applying* migrations (reconfiguring servers, re-issuing certificates) | The tool plans migrations; changing production systems is out of scope for a scanner. |
| Issuing post-quantum X.509 certificates / PQC TLS handshakes | Needs the OQS-OpenSSL fork; stock OpenSSL 1.1.1 and pyOpenSSL 19.1 cannot encode or negotiate Dilithium/Kyber. PQC primitives are exercised standalone via liboqs instead. |
| Implementing CRYSTALS-Kyber / Dilithium / SPHINCS+ from scratch | liboqs provides reviewed implementations; wrappers only. |
| `pqcrypto` Python package (listed in the old requirements) | First released September 2020, after the period; liboqs-python 0.3.0 (June 2020) covers the same algorithms. |
| TLS 1.3 cipher-suite / group enumeration | pyOpenSSL 19.1 exposes no `set_ciphersuites` / groups API; TLS 1.3 is recorded as supported/not and its kex is always (EC)DHE. |
| `tests/test_migration.py` layout from the README | Tests are split into `tests/unit/` and `tests/integration/` (§10); migration logic is covered by `tests/unit/test_migration_engine.py`. |
| Business-impact claims (percentages, "future-proof", status badges) | Fabricated; not measurable by this code. |
| Web UI / dashboard | Not in the README's concept; reports are JSON + Markdown. |

## 4. Architecture

```
            config/scan_config.yml
                     |
                     v
   +-------------- config.py ---------------+
   | load + validate YAML, expand CIDRs     |
   +----------------------------------------+
          |                          |
          v                          v
  crypto_scanner.py            certificate_manager.py
  (stdlib ssl handshake,       (parse DER/PEM certs and private keys
   pyOpenSSL cipher enum,       via cryptography; scan cert_paths)
   ThreadPoolExecutor)                |
          |  Endpoint records         |  CertInfo / KeyInfo records
          +------------+--------------+
                       v
             vulnerability_assessor.py
             (cipher_suites.py parsing, threat tables, risk score)
                       |  Findings
                       v
   algorithms/ ---> migration_engine.py <--- bench results (algorithms/benchmark.py)
   (liboqs-python:   (group, prioritise, recommend, hybrid note)
    lattice_based,          |
    hash_based)             v
                       report.py  --> reports/scan-<ts>.json
                       (Jinja2)   --> reports/roadmap-<ts>.md
                       ^
                       cli.py (Click): scan | certs | bench | roadmap
```

Runtime: one Docker image (`python:3.8.3-buster`, pinned by digest, + liboqs 0.3.0 built from
source as a shared library + liboqs-python 0.3.0, both pinned by commit and sha256).
Integration tests run against three `nginx:1.18.0` containers in the same compose network, each
configured with a different certificate / cipher policy.

## 5. Data model & interfaces

### 5.1 Configuration (`config/scan_config.yml`)

```yaml
targets:            # list[str]  hostnames, IPs or CIDR blocks
  - 10.0.1.0/24
ports: [443, 8443, 993, 995]   # list[int] 1..65535
timeout: 10         # float seconds, > 0
max_workers: 20     # int 1..256
max_hosts: 1024     # int, refuse larger CIDR expansion
enumerate_ciphers: true        # bool, run pyOpenSSL per-cipher probing
cert_paths: []      # list[str] directories scanned recursively for *.pem/*.crt/*.cer/*.der/*.key
output_format: json # json | markdown | both
output_path: reports/
bench_iterations: 20           # int, used by `bench` and `roadmap`
```

Unknown keys raise `ConfigError`; missing keys take the defaults above.

`output_format` controls which files `scan` and `roadmap` write: `json` → only
`scan-<ts>.json`; `markdown` → only `roadmap-<ts>.md`; `both` → both. `scan` builds a roadmap
(without benchmark figures) when Markdown is requested; `roadmap` defaults to `both` when the
key is left at its default. `certs` and `bench` print to stdout and write nothing.

### 5.2 Records (plain dicts, JSON-serialisable)

```
Endpoint = {
  host: str, port: int, status: "ok" | "unreachable" | "no_tls",
  protocol: str|None,            # "TLSv1.2", "TLSv1.3"
  tls13: bool,
  negotiated_suite: str|None,
  offered_suites: [str],         # from enumeration; [] if disabled
  key_bits: int|None,
  certificate: CertInfo|None,
  scan_time: ISO-8601 UTC str
}
CipherSuite = {
  name: str,
  kex:  "RSA"|"DH"|"ECDH"|"PSK"|"SRP"|"other"|"unknown",
  auth: "RSA"|"DSS"|"ECDSA"|"cert"|"PSK"|"SRP"|"other"|"unknown",   # "cert" = TLS 1.3
  cipher: str,                   # "AES-128-GCM", "3DES-CBC", "CHACHA20-POLY1305", ... | "unknown"
  cipher_bits: int|None,
  mac: "SHA1"|"MD5"|"SHA256"|"SHA384"|"AEAD"|"unknown"
}
CertInfo = {
  subject, issuer, serial, fingerprint_sha256,
  key_type: "RSA"|"EC"|"DSA"|"Ed25519"|"Ed448", key_bits: int, curve: str|None,
  signature_hash: str, not_before, not_after, source: "network"|<file path>
}
KeyInfo = {
  source: <file path>, key_type: "RSA"|"EC"|"DSA"|"Ed25519"|"Ed448"|"encrypted",
  key_bits: int|None, curve: str|None           # never contains key material
}
Finding = {
  target: "host:port" | <file path>, component: "key_exchange"|"authentication"|
          "cipher"|"mac"|"certificate_key"|"certificate_signature",
  algorithm: str, threat_class: "shor"|"classical"|"grover"|"none",
  threat_level: "critical"|"high"|"medium"|"low",
  recommendation: str
}
Assessment = { target, findings: [Finding], risk_score: int 0..100 }
BenchResult = { algorithm, kind: "kem"|"sig", public_key_len, secret_key_len,
                ciphertext_len|signature_len, keygen_ms, encap_ms|sign_ms, decap_ms|verify_ms }
Roadmap = { generated_at, phases: [ { priority: int, algorithm, replacement, hybrid,
            targets: [str], max_risk: int, bench: BenchResult|None } ] }
```

The top-level JSON report keeps the existing `_generate_report` keys (`scan_date`,
`total_endpoints`, `vulnerable_endpoints`, `risk_percentage`, `results`, `summary`) and adds
`unreachable`, `assessments` and `roadmap`.

### 5.3 Python interfaces

```python
config.load_config(path: str) -> dict                          # raises ConfigError
config.expand_targets(targets: list, max_hosts: int) -> list[str]
cipher_suites.parse_suite(name: str) -> dict                     # CipherSuite
crypto_scanner.CryptoScanner(config).scan_host(host, port) -> Endpoint
crypto_scanner.CryptoScanner(config).enumerate_ciphers(host, port) -> list[str]
crypto_scanner.CryptoScanner(config).scan_all() -> dict          # report
certificate_manager.parse_certificate(data: bytes, source="network") -> CertInfo
certificate_manager.parse_private_key(data: bytes, source: str) -> KeyInfo
certificate_manager.scan_directory(path: str) -> {"certificates": [CertInfo], "keys": [KeyInfo]}
    # certificates deduplicated by fingerprint_sha256, first in sorted path order kept
vulnerability_assessor.assess_endpoint(ep: Endpoint, now=None) -> Assessment
vulnerability_assessor.assess_certificate(ci: CertInfo, now=None) -> Assessment
vulnerability_assessor.assess_key(ki: KeyInfo) -> Assessment
vulnerability_assessor.risk_score(findings, cert=None, now=None) -> int
    # now: datetime (UTC), defaults to datetime.utcnow(); tests pass a fixed value
algorithms.lattice_based.KyberKEM(level=512|768|1024)            # keypair/encapsulate/decapsulate
algorithms.lattice_based.DilithiumSigner(level=2|3|4)            # keypair/sign/verify
algorithms.hash_based.SphincsSigner(variant="128f"|"128s")       # keypair/sign/verify
algorithms.benchmark.run(names: list[str], iterations: int) -> list[BenchResult]
migration_engine.build_roadmap(assessments, bench=None) -> Roadmap
report.write_json(report, dir) -> path
report.write_markdown(roadmap, report, dir) -> path
```

### 5.4 Risk score

Findings are deduplicated by `(component, algorithm)` across the negotiated suite, every offered
suite and the certificate. Finding algorithms are normalised to the primitive, not the mode
(`AES-128-GCM` and `AES-128-CBC` both give cipher `AES-128`; a `-SHA` suffix gives mac
`HMAC-SHA1`; AEAD suites give no MAC finding). Then:

| Term | Points |
|---|---|
| Shor base: any finding with class `shor` (counted once, not per component) | 50 |
| Each `classical` / `high` finding (3DES, RC4, MD5, SHA-1 certificate signature) | 15 |
| Each `classical` / `medium` finding (HMAC-SHA1 / HMAC-MD5 MAC in CBC suites) | 5 |
| Each `grover` / `medium` finding (AES-128, CAMELLIA-128) | 5 |
| `grover` / `low` and `none` findings (SHA-256; AES-256, CHACHA20, SHA-384+) | 0 |
| Certificate `not_after` more than 2 years after `now` (long-lived keys, store-now-decrypt-later) | 10 |

`risk_score = min(100, sum)`. Threat mapping:

| Algorithm | Class | Level | Recommendation |
|---|---|---|---|
| RSA, DH, DSA/DSS, ECDH, ECDSA, Ed25519/Ed448 (kex, auth, cert key or private key) | shor | critical | Kyber (kex) / Dilithium (auth), SPHINCS+ alt |
| RSA static key exchange (no forward secrecy) | shor | critical (+ note) | as above; prefer (EC)DHE until Kyber |
| 3DES, RC4 | classical | high | AES-256-GCM |
| MD5 / SHA-1 certificate signature hash | classical | high | SHA-384 |
| HMAC-SHA1 / HMAC-MD5 MAC | classical | medium | AEAD suite (GCM / POLY1305) |
| AES-128, CAMELLIA-128 | grover | medium | AES-256-GCM |
| SHA-256 | grover | low | SHA-384 |
| AES-256, CHACHA20, SHA-384, SHA-512, SHA3-* | none | low | — |

Worked examples (fixed `now` = 2020-06-30T00:00:00Z, ten-year fixture certificates, suites as
configured in §8, TLS 1.3 negotiating `TLS_AES_256_GCM_SHA384`):

| Endpoint | Scoring findings | Score |
|---|---|---|
| `tls-legacy` | Shor base 50 (static RSA kex, RSA auth, RSA cert key) + SHA-1 cert signature 15 + HMAC-SHA1 5 + AES-128 5 + validity 10 (only `AES128-SHA` is offered, see §11) | **85** |
| `tls-rsa` | Shor base 50 (ECDH/DH/static RSA kex, RSA auth, RSA cert key) + AES-128 5 + HMAC-SHA1 5 (from `AES128-SHA`) + validity 10; SHA-256 0 | **70** |
| `tls-ecdsa` | Shor base 50 (ECDH kex, ECDSA auth, EC cert key) + validity 10; AES-256, CHACHA20, SHA-384, SHA-256 0 | **60** |

Strict order: `tls-legacy` (85) > `tls-rsa` (70) > `tls-ecdsa` (60). A server that also accepted
`DES-CBC3-SHA` would add 3DES 15 and score 100; Debian's OpenSSL 1.1.1d (used by both nginx and
the scanner) has no 3DES suites, so `tls-legacy` cannot offer it (§11).

### 5.5 CLI

```
quantum scan    [-c CONFIG] [--no-enum] [-o DIR] [--fail-on LEVEL] [-v]
quantum certs   [-c CONFIG] [--fail-on LEVEL] [-v] [PATH ...]
quantum bench   [-n ITER] [--alg NAME ...] [-v]
quantum roadmap [-c CONFIG] [--from-json FILE] [--no-enum] [-o DIR] [--fail-on LEVEL] [-v]
```

`-o DIR` overrides `output_path`; `--fail-on LEVEL` (`critical|high|medium|low`) makes the
command exit 1 when any finding is at or above that level; `-v` sets logging to DEBUG (default
WARNING). Exit codes: 0 success, 1 `--fail-on` threshold reached, 2 config error.

## 6. Stack & pinned versions

All versions verified released on or before 2020-06-30 (PyPI dates checked with
`tools/check_period.py`; non-registry tools from their official release pages / commit history).

| Component | Version | Released | Why it was the popular choice then |
|---|---|---|---|
| Python | 3.8.3 | 2020-05-13 | Current stable CPython in mid-2020; `python:3.8` was the default image. |
| OpenSSL (Debian buster system lib, `1.1.1d-0+deb10u3`) | 1.1.1d | 2019-09-10 | LTS OpenSSL shipped by buster, TLS 1.3 capable; what stdlib `ssl`, liboqs and (built with `--no-binary cryptography`) `cryptography`/pyOpenSSL link against in the image. |
| liboqs (C) | 0.3.0 = commit `f6ca3dca5e95e77267dd0d7f5480c512cd6a4d6d` | 2020-06-10 | Open Quantum Safe's reference PQC library; the de-facto way to use NIST round-2 candidates; first CMake-based release. |
| liboqs-python | 0.3.0 = commit `97e500c7eb74ec8acd14910b4d4a7e7b65dbeb5b` (not on PyPI) | 2020-06-10 | Official OQS Python wrapper matching liboqs 0.3.0. The `0.3.0` git tag was later moved (annotated tag created 2020-07-14, pointing at `8af801e0`, which includes three July 2020 commits), so the tag is **not** used; the commit is. |
| cryptography | 2.9.2 | 2020-04-22 | Standard Python X.509/crypto library of the time. Installed with `--no-binary cryptography` (see note below). |
| pyOpenSSL | 19.1.0 | 2019-11-18 | Latest pyOpenSSL; gives cipher-list control and peer chain access that stdlib `ssl` lacks. |
| setuptools | 47.1.1 | 2020-05-29 | Build backend for the cryptography sdist; pinned in `requirements-build.txt` and installed before cryptography (see note below). |
| wheel | 0.34.2 | 2020-01-30 | Builds the cryptography wheel locally; pinned in `requirements-build.txt`. |
| pip (shipped in `python:3.8.3-buster`) | 20.1.1 | 2020-05-19 | Installer in the base image; not upgraded. |
| cffi | 1.14.0 | 2020-02-07 | cryptography dependency (build- and run-time; also in `requirements-build.txt`). |
| pycparser | 2.20 | 2020-03-04 | cffi dependency (also in `requirements-build.txt`). |
| six | 1.15.0 | 2020-05-21 | cryptography 2.9 dependency. |
| PyYAML | 5.3.1 | 2020-03-18 | Standard YAML parser (already used). |
| click | 7.1.2 | 2020-04-27 | Most popular Python CLI framework in 2020. |
| Jinja2 | 2.11.2 | 2020-04-13 | Standard templating for the Markdown roadmap. |
| MarkupSafe | 1.1.1 | 2019-02-24 | Jinja2 dependency. |
| pytest | 5.4.3 | 2020-06-02 | Dominant Python test runner. |
| pytest-cov | 2.10.0 | 2020-06-12 | Coverage plugin for pytest. |
| coverage | 5.1 | 2020-04-12 | pytest-cov dependency. |
| flake8 | 3.8.3 | 2020-06-08 | Standard linter. |
| pyflakes / pycodestyle / mccabe | 2.2.0 / 2.6.0 / 0.6.1 | 2020-04-10 / 2020-05-11 / 2017-01-26 | flake8 3.8 dependencies. |
| attrs / more-itertools / packaging / pluggy / py / wcwidth / pyparsing | 19.3.0 / 8.4.0 / 20.4 / 0.13.1 / 1.8.2 / 0.2.4 / 2.4.7 | 2019-10-15 / 2020-06-14 / 2020-05-19 / 2019-11-21 / 2020-06-15 / 2020-06-08 / 2020-04-05 | pytest 5.4 dependencies, pinned for reproducibility. |
| cmake (Debian buster package `3.13.4-1`) | 3.13.4 | 2019-02-01 | Build system required by liboqs 0.3.0; installed from the 2020-06-15 Debian snapshot. |
| ninja (Debian buster package `ninja-build 1.8.2-1`) | 1.8.2 | 2017-09-13 | Generator used by the liboqs build instructions; same snapshot. |
| nginx (test targets) | 1.18.0 | 2020-04-21 | Then-current stable nginx branch. |
| docker-compose | 1.26.0 | 2020-06-03 | Compose CLI of the period; the Makefile calls `$(COMPOSE)`, default `docker-compose`; `make COMPOSE="docker compose"` works with the later v2 plugin. |
| Compose file format | 3.8 | Docker Engine 19.03.0, 2019-07-22 | Latest compose schema in mid-2020. |

`requirements.txt` holds runtime pins; `requirements-dev.txt` holds test/lint pins;
`requirements-build.txt` holds the build tools needed to compile cryptography (setuptools, wheel,
cffi, pycparser).

**OpenSSL split and `--no-binary cryptography`.** On x86_64 the cryptography 2.9.2
`manylinux2010` abi3 wheel bundles its own OpenSSL 1.1.1g, so pyOpenSSL/cryptography would use
1.1.1g's cipher list while stdlib `ssl` uses Debian's 1.1.1d; on arm64 there is no 2.9.2 wheel at
all and it builds from source against the system library, so behaviour would differ by
architecture. The Dockerfile therefore installs with `pip install --no-binary cryptography`, so
on every architecture stdlib `ssl`, cryptography and pyOpenSSL all link Debian's 1.1.1d (the full
buster image ships `libssl-dev` and `libffi-dev`). A test asserts both report
`OpenSSL 1.1.1d`.

cryptography 2.9.2's sdist declares unpinned build requirements in `pyproject.toml`
(`setuptools>=40.6.0`, `wheel`, `cffi>=1.8,!=1.11.3`). With pip 20.1.1's default build isolation
these would be fetched at their newest versions (2024-era releases), breaking the period pins and
reproducibility. The Dockerfile therefore first runs
`pip install -r requirements-build.txt` (setuptools 47.1.1, wheel 0.34.2, cffi 1.14.0,
pycparser 2.20), then
`pip install --no-build-isolation --no-binary cryptography -r requirements.txt -r requirements-dev.txt`,
so the extension is compiled with the same pinned cffi that runs it. The liboqs-python directory
install also uses `--no-build-isolation`.

liboqs and liboqs-python are built in the Dockerfile from commit tarballs, each verified with
`sha256sum -c` before extraction:

| Source | sha256 |
|---|---|
| `https://github.com/open-quantum-safe/liboqs/archive/f6ca3dca5e95e77267dd0d7f5480c512cd6a4d6d.tar.gz` | `bae2ec508c9a7c8d25ab873c91cc31682536209a1a324d56afae5a5e6bcf11c6` |
| `https://github.com/open-quantum-safe/liboqs-python/archive/97e500c7eb74ec8acd14910b4d4a7e7b65dbeb5b.tar.gz` | `6a31d0aad459bad134840cff45fa7b08e12b918f20dbce0555ee889c5957ada6` |

liboqs is configured with `cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON`.

## 7. Docker images (verified on Docker Hub, HTTP 200)

| Image | Tag | Last pushed | Pinned digest (manifest list) | Use |
|---|---|---|---|---|
| `python` | `3.8.3-buster` | 2020-06-09 | `sha256:0919808810c11f09713ac50bd0c428f34a34029028f0b535020165659e39ec6a` | App/test image; full buster variant has gcc/make, `libssl-dev` and `libffi-dev` (cmake + ninja-build added via apt). |
| `nginx` | `1.18.0` | 2021-04-10 | `sha256:e90ac5331fe095cea01b121a3627174b2e33e06e83720e9a934c7b8ccc9c55a0` | Three local TLS targets for integration tests. |

`nginx:1.18.0` as served by Docker Hub is a 2021 rebuild of the 2020 release (same nginx 1.18.0,
still on Debian buster's OpenSSL 1.1.1d); no 2020 build of the tag is retrievable. Both images
are referenced as `name:tag@sha256:<digest>` in the Dockerfile and `docker-compose.yml`.

apt in the app image is pointed at the period snapshot, not the current archive, so installing
cmake/ninja cannot upgrade OpenSSL or other libraries to post-2020 builds:

```
deb http://snapshot.debian.org/archive/debian/20200615T000000Z buster main
deb http://snapshot.debian.org/archive/debian-security/20200615T000000Z buster/updates main
```

with `Acquire::Check-Valid-Until "false";`. Only `cmake ninja-build` are installed;
`libssl-dev` is already present in the base image (1.1.1d-0+deb10u3, the same version as the
snapshot).

## 8. Simulated / mocked integrations

- **Enterprise network / "infrastructure"** — replaced by a docker compose network of three
  `nginx:1.18.0` containers (all with `ssl_prefer_server_ciphers off`, nginx's default, so the
  TLS 1.3 suite follows the client's preference, `TLS_AES_256_GCM_SHA384`):
  - `tls-rsa`: RSA-2048 cert signed with SHA-256, TLS 1.2 + 1.3, ciphers
    `ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:AES128-SHA` (the last is static RSA
    kex), with `ssl_dhparam /etc/nginx/tls/dhparam-2048.pem` (nginx has no default DH
    parameters since 1.11.0, so without this file the DHE suite would never be accepted);
  - `tls-ecdsa`: P-256 ECDSA cert, `ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305`
    only, TLS 1.2 + 1.3;
  - `tls-legacy`: RSA-2048 cert signed with SHA-1, TLS 1.2 only,
    `DES-CBC3-SHA:AES128-SHA:@SECLEVEL=0`. Python 3.8's `create_default_context` excludes 3DES,
    so the stdlib `scan_host` handshake negotiates `AES128-SHA`. Debian's OpenSSL 1.1.1d is
    built without 3DES suites (OpenSSL's 1.1.0+ default), so nginx keeps only `AES128-SHA` from
    this list and the pyOpenSSL enumeration finds exactly that suite. This container runs with `OPENSSL_CONF` pointing at
    `docker/nginx/openssl-legacy.cnf` (`CipherString = DEFAULT@SECLEVEL=0`), because Debian's
    default `SECLEVEL=2` makes nginx refuse to load the SHA-1-signed certificate.
  Certificates, keys and the 2048-bit DH parameter file (`dhparam-2048.pem`) are self-signed /
  test-only, generated by `scripts/gen_test_certs.sh` and committed under `tests/fixtures/tls/`
  (mounted read-only at `/etc/nginx/tls/` in each nginx container).
- **Unit tests** use in-process fakes: a stub `ssl` socket returning canned `cipher()` /
  `version()` / DER, and a Python `ssl`-based TLS server on `127.0.0.1` running a threaded accept
  loop that serves connections until stopped (enumeration makes one handshake per candidate
  cipher, and failed handshakes must not stop the server). No real hosts outside the compose
  network are ever contacted by tests.
- **Real 10.0.x.0/24 targets** in `scan_config.yml` are example values only; the README states
  the tool was only exercised against the local simulated endpoints.

## 9. Existing code inventory (`git ls-files`)

| File | Decision | Reason |
|---|---|---|
| `README.md` | refactor | Regenerated in the last task from `tools/readme_template.md`; current text contains fabricated claims (employer, role, dates, status badges) and describes files that do not exist. |
| `config/scan_config.yml` | refactor | Keep keys and values; add `max_hosts`, `enumerate_ciphers`, `cert_paths`, `bench_iterations`; comment that targets are examples. |
| `requirements.txt` | refactor | Bump cryptography 2.9→2.9.2 and PyYAML 5.3→5.3.1; keep pyOpenSSL 19.1.0; drop `pqcrypto` (released 2020-09, out of period, unused); add click, Jinja2 and transitive pins. |
| `src/crypto_scanner.py` | refactor | Keep `CryptoScanner`, threading, `QUANTUM_VULNERABLE`/`QUANTUM_SAFE` tables and report shape; in T1 drop the unused `json` import and wrap the 117-character line so flake8 passes; later fix the CIDR bug (CIDR strings were passed to `create_connection`), move parsing to `cipher_suites.py`, assessment to `vulnerability_assessor.py`, add pyOpenSSL enumeration and unreachable records. |

No files are deleted. Code moves into a `src/quantum_tool/` package (the existing
`src/crypto_scanner.py` is `git mv`-ed to `src/quantum_tool/crypto_scanner.py` in T2 to keep its
history).

## 10. Test strategy

- **Runner**: `make test` → `$(COMPOSE) run --rm app pytest` in the `python:3.8.3-buster`
  derived image; `make lint` → flake8. Coverage reported with `--cov=quantum_tool`. The source is
  bind-mounted and imported via `PYTHONPATH=/app/src`; nothing is pip-installed in editable mode,
  and the CLI is invoked as `python -m quantum_tool`.
- **Environment tests** (`tests/unit/test_environment.py`): `ssl.OPENSSL_VERSION` and
  cryptography's `backend.openssl_version_text()` both start with `OpenSSL 1.1.1d`.
- **Unit tests** (`tests/unit/`, no network): config validation and CIDR expansion; cipher-suite
  parsing table-driven over ~30 OpenSSL names; certificate and key parsing against the fixtures,
  including fingerprint deduplication; threat mapping and risk score arithmetic with a fixed
  `now`, including the three worked examples in §5.4; migration ordering and grouping;
  Markdown/JSON report rendering (golden-structure asserts); CLI via `click.testing.CliRunner`.
- **PQC tests** (`tests/unit/test_lattice_based.py`, `tests/unit/test_hash_based.py`,
  `tests/unit/test_benchmark.py`; need liboqs in the image): Kyber encapsulate/decapsulate
  round-trip yields equal shared secrets; Dilithium and SPHINCS+ sign/verify succeed and fail on
  a tampered message; reported lengths match liboqs' `details`; creating and freeing 1000 KEM
  objects with secret keys in a loop does not crash; benchmark returns positive timings for 2
  iterations.
- **Integration tests** (`tests/integration/`, marker `integration`): scan the three nginx
  targets through compose DNS names; assert negotiated protocol, offered-suite sets
  (e.g. `AES128-SHA` found on `tls-rsa`, only `AES128-SHA` on `tls-legacy`), certificate key types,
  exact risk scores 85 / 70 / 60 for `tls-legacy` / `tls-rsa` / `tls-ecdsa` at a fixed `now`, and
  that `python -m quantum_tool roadmap` writes a Markdown file listing Kyber/Dilithium phases. An
  unreachable port asserts `status: unreachable`.
- `make test` runs unit + integration; `make unit` runs unit only.

## 11. Known limitations that will remain

- Only TLS endpoints and PEM/DER certificate and private-key files are inventoried.
- Protocols below TLS 1.2 are not detected: Debian's client `openssl.cnf` sets
  `MinProtocol = TLSv1.2` and enumeration uses `TLSv1_2_METHOD`, so a TLS 1.0/1.1-only server is
  recorded as `no_tls`.
- TLS 1.3 suites and key-exchange groups are not enumerated (pyOpenSSL 19.1 API limit).
- Cipher enumeration only covers suites Debian's OpenSSL 1.1.1d build knows (stdlib `ssl`,
  cryptography and pyOpenSSL all use it); suites removed from OpenSSL (e.g. export ciphers) cannot
  be detected.
- 3DES suites cannot be detected: Debian's OpenSSL 1.1.1d (scanner and nginx image alike) is built
  without them, so `DES-CBC3-SHA` is never offered by the client or accepted by `tls-legacy`, which
  falls back to `AES128-SHA` plus the SHA-1 certificate (score 85).
- liboqs-python 0.3.0 (commit `97e500c`) has a use-after-free, fixed upstream on 2020-07-07:
  `KeyEncapsulation.free()` / `Signature.free()` call `OQS_KEM_free` / `OQS_SIG_free` and then read
  `length_secret_key` from the freed struct to cleanse the secret key. The wrappers subclass both
  classes and override `free()` to read the length and cleanse first, then free, guarded against
  double free; the upstream context manager is only used through these subclasses.
- Risk scoring is a transparent heuristic, not a formal threat model.
- liboqs 0.3.0 implements NIST round-2 parameter sets; these differ from the later
  standardised ML-KEM / ML-DSA / SLH-DSA and are not interoperable with them.
- The tool recommends migrations but never changes remote systems, rotates keys or issues PQC
  certificates.
- `nginx:1.18.0` is a 2021 rebuild of the 2020 release (§7).
- Only exercised against the simulated nginx endpoints in the compose file.
