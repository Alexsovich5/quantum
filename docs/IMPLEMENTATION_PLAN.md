# quantum — Implementation Plan

Companion to `docs/SPEC.md`. Each task is exactly one commit, is ordered by dependency, and
leaves `make test` green inside the `python:3.8.3-buster`-derived image. The only host
requirement is Docker with docker-compose 1.26.0 (the period tool) or the later `docker compose`
v2 plugin (`make COMPOSE="docker compose" ...`).

Conventions used in every task:

- `COMPOSE ?= docker-compose`. `make test` = `$(COMPOSE) run --rm app pytest $(PYTEST_ARGS)`
  (unit + integration once integration tests exist). `make unit` = unit tests only.
  `make lint` = flake8.
- `PYTEST_ARGS` lets you run one file first, e.g. `make test PYTEST_ARGS=tests/unit/test_config.py`.
- The repo is bind-mounted at `/app` and imported through `ENV PYTHONPATH=/app/src`. Nothing is
  pip-installed in editable mode (a build-time `pip install -e .` would be hidden by the bind
  mount); the CLI is always invoked as `python -m quantum_tool`.
- Tests that depend on certificate validity pass a fixed `now` (2020-06-30T00:00:00Z).
- Tests are written before the code they cover (red, then green) inside the same commit.
- Commit messages: imperative subject, 72 characters or fewer, 1–3 line body, no dates, no tool
  attribution, no employer names.

---

## T1 — Scaffold Docker image, Makefile and test harness

**Goal:** `make test` and `make lint` work from the first commit with period-pinned dependencies.

**Files**
- create `Dockerfile` — `FROM python:3.8.3-buster@sha256:0919808810c11f09713ac50bd0c428f34a34029028f0b535020165659e39ec6a`;
  replace `/etc/apt/sources.list` with the `snapshot.debian.org/archive/debian/20200615T000000Z`
  and `debian-security/20200615T000000Z` lines from SPEC §7 plus
  `Acquire::Check-Valid-Until "false";` (no packages installed yet); `WORKDIR /app`;
  `pip install -r requirements-build.txt` (period build tools first), then
  `pip install --no-build-isolation --no-binary cryptography -r requirements.txt -r requirements-dev.txt`
  (build isolation off so cryptography's unpinned `pyproject.toml` build requirements are not
  fetched at post-2020 versions; see SPEC §6);
  `ENV PYTHONPATH=/app/src`.
- create `docker-compose.yml` (format `3.8`) — service `app` built from `.` and tagged `image: quantum:dev`,
  bind-mounts `.:/app`; the `default` network is pinned to subnet `172.74.0.0/24` so the stack
  stays inside its allotted address range on a shared Docker host (any host ports published by
  later tasks use 22400–22499).
- create `Makefile` — `COMPOSE ?= docker-compose`; targets `build`, `test`, `unit`, `lint`,
  `shell`, `clean`; `PYTEST_ARGS` passthrough.
- create `requirements-build.txt` — setuptools 47.1.1, wheel 0.34.2, cffi 1.14.0, pycparser 2.20.
- create `requirements-dev.txt` — pytest 5.4.3, pytest-cov 2.10.0, coverage 5.1, flake8 3.8.3,
  pyflakes 2.2.0, pycodestyle 2.6.0, mccabe 0.6.1, attrs 19.3.0, more-itertools 8.4.0,
  packaging 20.4, pluggy 0.13.1, py 1.8.2, wcwidth 0.2.4, pyparsing 2.4.7.
- modify `requirements.txt` — cryptography 2.9.2, pyOpenSSL 19.1.0, PyYAML 5.3.1, cffi 1.14.0,
  pycparser 2.20, six 1.15.0; remove `pqcrypto` (first released 2020-09, never imported).
- modify `src/crypto_scanner.py` — remove the unused `import json` (flake8 F401) and wrap the
  117-character `'critical': sum(...)` line in `_generate_report` (E501). No behaviour change.
- create `setup.cfg` — `[tool:pytest]` testpaths, `integration` marker; `[flake8]`
  max-line-length 100.
- create `.gitignore` (`reports/`, `__pycache__/`, `.pytest_cache/`, `.coverage`),
  `.dockerignore`.
- create `tests/__init__.py`, `tests/unit/__init__.py`, `tests/unit/test_smoke.py`,
  `tests/unit/test_environment.py`.

**Tests to write first:** `test_smoke.py` — imports `crypto_scanner` from `src/`, asserts
`QUANTUM_VULNERABLE` contains RSA/ECDH/ECDSA/DH/DSA and that `CryptoScanner({})` picks the default
ports `[443, 8443, 993, 995]`. `test_environment.py` — `ssl.OPENSSL_VERSION` and
`cryptography.hazmat.backends.openssl.backend.openssl_version_text()` both start with
`OpenSSL 1.1.1d` (proves the `--no-binary` build and that no newer libssl was pulled in);
`setuptools.__version__ == "47.1.1"`, `wheel.__version__ == "0.34.2"` and `cffi.__version__ ==
"1.14.0"` (proves the pinned build tools, not newer ones, are in the image).

**Acceptance:** `make build && make test && make lint`

**Commit message**
```
Add Docker, Makefile and pytest harness with pinned dependencies

Build and test inside python:3.8.3-buster so `make test` runs from the start.
Drop the unused pqcrypto pin and fix the two lint errors in the scanner.
```

---

## T2 — Move scanner into a package and pin its current behaviour

**Goal:** Turn `src/` into a `quantum_tool` package without changing behaviour, and cover the
existing logic with characterisation tests before refactoring.

**Files**
- `git mv src/crypto_scanner.py src/quantum_tool/crypto_scanner.py`
- create `src/quantum_tool/__init__.py` (`__version__ = "0.1.0"`)
- create `setup.py` (setuptools, `package_dir={"": "src"}`) for installs outside Docker. The
  Dockerfile does **not** `pip install -e .`: the image imports the package via
  `PYTHONPATH=/app/src` from the bind mount.
- create `tests/unit/fakes.py` — `FakeSSLSocket` returning canned `cipher()`, `version()`,
  `getpeercert(binary_form=True)`; context-manager helpers to patch `socket.create_connection`
  and `ssl.SSLContext.wrap_socket`.
- create `tests/unit/test_crypto_scanner.py`
- modify `tests/unit/test_smoke.py` (import path `quantum_tool.crypto_scanner`)

**Tests to write first:** `scan_host` with the fake socket returns the documented keys;
`ECDHE-RSA-AES256-GCM-SHA384` yields `ECDH` + `RSA` and two critical vulnerabilities;
connection refused returns `None` (current behaviour); `_generate_report` computes
`risk_percentage` and the zero-results case.

**Acceptance:** `make build && make test PYTEST_ARGS=tests/unit/test_crypto_scanner.py && make test && make lint`

**Commit message**
```
Package the scanner as quantum_tool and cover existing behaviour

Move crypto_scanner.py under src/quantum_tool with a setup.py and add
characterisation tests using a fake TLS socket.
```

---

## T3 — Load and validate YAML config and expand CIDR targets

**Goal:** Fix the bug where CIDR strings were passed straight to `create_connection`; validate
config.

**Files**
- create `src/quantum_tool/config.py` — `ConfigError`, `DEFAULTS`, `load_config(path)`,
  `validate(dict)`, `expand_targets(targets, max_hosts)` using `ipaddress`; `output_format`
  restricted to `json|markdown|both`.
- modify `src/quantum_tool/crypto_scanner.py` — `scan_all` iterates over
  `expand_targets(...)`.
- modify `config/scan_config.yml` — add `max_hosts`, `enumerate_ciphers`, `cert_paths`,
  `bench_iterations`; comment that the 10.0.x.0/24 targets are examples.
- create `tests/unit/test_config.py`

**Tests to write first:** defaults filled in; unknown key, port 0, port 70000, negative timeout,
`output_format: xml` and a non-list `targets` raise `ConfigError`; `10.0.1.0/30` expands to
`10.0.1.1`, `10.0.1.2`; a hostname passes through unchanged and a `/32` yields its single address
(deviation: a literal `/32` string would still reach `create_connection`); `/16` with `max_hosts=1024`
raises; the shipped `config/scan_config.yml` validates.

**Acceptance:** `make test PYTEST_ARGS=tests/unit/test_config.py && make test && make lint`

**Commit message**
```
Validate scan config and expand CIDR targets into host lists

Adds config.py with defaults and error messages; the scanner now scans each
address in a CIDR block instead of passing the block to connect().
```

---

## T4 — Parse OpenSSL cipher-suite names into components

**Goal:** Replace substring checks with a real parser so that e.g. `DHE-RSA-...` is reported as DH
key exchange + RSA auth and `AES128-SHA` as static RSA key exchange.

**Files**
- create `src/quantum_tool/cipher_suites.py` — `parse_suite(name) -> CipherSuite` with the enum
  values of SPEC §5.2, covering OpenSSL TLS 1.2 names (`ECDHE-*`, `DHE-*`, `EDH-*`, `ECDH-*`,
  `DH-*`, bare static-RSA names, `PSK`/`SRP` flagged as `PSK`/`SRP`, anything else recognised but
  unmapped as `other`) and TLS 1.3 IANA names (`TLS_AES_256_GCM_SHA384` → kex `ECDH` / auth
  `cert` / mac `AEAD`). GCM/CCM/POLY1305 suites get mac `AEAD`; a `-SHA` suffix gives `SHA1`.
- modify `src/quantum_tool/crypto_scanner.py` — `_extract_key_exchange` / `_extract_auth` delegate
  to `parse_suite`.
- create `tests/unit/test_cipher_suites.py`

**Tests to write first:** table-driven, about 30 names, asserting `kex`, `auth`, `cipher`,
`cipher_bits`, `mac` (includes `DES-CBC3-SHA`, `ECDHE-ECDSA-CHACHA20-POLY1305`,
`DHE-DSS-AES128-SHA`, `PSK-AES128-CBC-SHA`, `TLS_CHACHA20_POLY1305_SHA256`); an unknown name
returns `unknown` fields and does not raise.

**Acceptance:** `make test PYTEST_ARGS=tests/unit/test_cipher_suites.py && make test && make lint`

**Commit message**
```
Parse cipher-suite names into kex, auth, cipher and MAC parts

Replaces substring matching in the scanner, which misread static-RSA and
DHE suites, with a table-tested parser for TLS 1.2 and 1.3 names.
```

---

## T5 — Add certificate and key manager with test fixtures

**Goal:** Parse network and on-disk certificates (key type/size/curve, signature hash, validity,
fingerprint), inventory private-key files without exposing key material, and inventory
directories with fingerprint deduplication.

**Files**
- create `scripts/gen_test_certs.sh` — uses `openssl` 1.1.1d in the app image to produce
  self-signed test-only material with ten-year validity (issued with `openssl ca -selfsign`
  and a fixed window 2020-06-01 to 2030-06-01, so the fixed test `now` falls inside it no matter
  when the script is rerun): for each of `rsa2048-sha256`,
  `ec-p256-sha256`, `rsa2048-sha1` a `<name>-cert.pem` and `<name>-key.pem`, plus
  `rsa2048-sha256-cert.der` (DER copy of the same certificate), and
  `openssl dhparam -out tests/fixtures/tls/dhparam-2048.pem 2048` (DH parameters for the
  `tls-rsa` DHE suite, T7).
- create `tests/fixtures/tls/*.pem` (including `dhparam-2048.pem`),
  `tests/fixtures/tls/rsa2048-sha256-cert.der` (output of the script, committed; test-only keys).
- create `src/quantum_tool/certificate_manager.py` — `parse_certificate(data, source)`,
  `parse_private_key(data, source)` (via `load_pem_private_key` / `load_der_private_key` with
  `password=None`; an encrypted key gives `key_type: "encrypted"`), `load_file(path)`,
  `scan_directory(path)` returning `{"certificates": [...], "keys": [...]}` (recursive
  `*.pem`/`*.crt`/`*.cer`/`*.der`/`*.key`, files visited in sorted path order, certificates
  deduplicated by `fingerprint_sha256` keeping the first source, unparsable files skipped with a
  logged warning).
- modify `src/quantum_tool/crypto_scanner.py` — `_analyze_cert` uses `parse_certificate`; a
  missing or unparsable peer certificate gives `certificate: None` (Endpoint `CertInfo|None`).
- modify `Makefile` — `certs` target runs the script inside the container.
- create `tests/unit/test_certificate_manager.py`

**Tests to write first:** RSA fixture → `key_type=RSA`, `key_bits=2048`, `signature_hash=sha256`;
EC fixture → `EC`, `secp256r1`; SHA-1 fixture → `sha1`; DER and PEM of the same cert give the
same fingerprint; `scan_directory(tests/fixtures/tls)` returns exactly three certificates (the
DER/PEM pair collapsed to one, `source` ending in `rsa2048-sha256-cert.der`) and three keys
(RSA 2048, EC secp256r1, RSA 2048), with `dhparam-2048.pem` skipped as unparsable; no
`KeyInfo` field contains PEM or key bytes; an encrypted
key written to `tmp_path` yields `key_type: "encrypted"`.

**Acceptance:** `make test PYTEST_ARGS=tests/unit/test_certificate_manager.py && make test && make lint`

**Commit message**
```
Add certificate and key inventory for network and on-disk files

Parses key type, size, curve, signature hash and validity with cryptography,
records private-key type and size without key material, and dedupes certs.
```

---

## T6 — Extract vulnerability assessor with threat classes and risk score

**Goal:** Move `QUANTUM_VULNERABLE` / `QUANTUM_SAFE` into a dedicated assessor that covers
Shor-broken public-key algorithms, classically broken primitives, Grover-weakened symmetric/hash
algorithms, certificate and private keys, and computes the SPEC §5.4 risk score.

**Files**
- create `src/quantum_tool/vulnerability_assessor.py` — threat tables (existing entries kept,
  extended per SPEC §5.4 with classes `shor`/`classical`/`grover`/`none`), `assess_suite`,
  `assess_certificate(ci, now=None)`, `assess_key(ki)`, `assess_endpoint(ep, now=None)`,
  `risk_score(findings, cert=None, now=None)`.
- modify `src/quantum_tool/crypto_scanner.py` — `_assess_vulnerabilities` delegates; tables are
  re-exported for compatibility; `_generate_report` adds `assessments`.
- create `tests/unit/test_vulnerability_assessor.py`

**Tests to write first:** RSA/ECDH/ECDSA/DH/DSA map to `shor`/`critical` with Kyber or Dilithium
recommendations; `DES-CBC3-SHA` gives `classical`/`high` for 3DES and `classical`/`medium` for
`HMAC-SHA1`; a SHA-1 certificate signature gives `classical`/`high`; AES-128 gives
`grover`/`medium`; AES-256-GCM/SHA384 gives no findings above `low`; score arithmetic with
`now=2020-06-30T00:00:00Z`: `ECDHE-RSA-AES128-GCM-SHA256` alone = 50 + 5 = 55; three Shor
components still add 50 once; duplicate `(component, algorithm)` findings count once; +10 for a
certificate expiring more than two years after `now`, 0 for one expiring within two years; cap
at 100; hand-built endpoint dicts matching the three nginx targets (SPEC §5.4 worked examples)
score exactly 100 / 70 / 60; a fallback `tls-legacy` without `DES-CBC3-SHA` scores 85;
`assess_key` on an EC key gives `certificate_key`/`shor`/`critical`; the T2 characterisation
tests still pass.

**Acceptance:** `make test PYTEST_ARGS=tests/unit/test_vulnerability_assessor.py && make test && make lint`

**Commit message**
```
Extract vulnerability assessor with threat classes and risk score

Separates Shor-broken public-key algorithms, classically broken ciphers and
hashes, and Grover-weakened primitives, and scores each endpoint 0 to 100.
```

---

## T7 — Add nginx TLS targets and scanner integration tests

**Goal:** Stand up the simulated infrastructure and prove `scan_host` against real TLS servers;
record unreachable endpoints.

**Files**
- create `docker/nginx/tls-rsa.conf`, `docker/nginx/tls-ecdsa.conf`, `docker/nginx/tls-legacy.conf`
  (cipher policies per SPEC §8; legacy uses `DES-CBC3-SHA:AES128-SHA:@SECLEVEL=0`,
  `ssl_protocols TLSv1.2`; `tls-rsa.conf` sets `ssl_dhparam /etc/nginx/tls/dhparam-2048.pem;`
  so `DHE-RSA-AES256-GCM-SHA384` is actually accepted; all leave
  `ssl_prefer_server_ciphers off`).
- modify `docker-compose.yml` — services `tls-rsa`, `tls-ecdsa`, `tls-legacy` from
  `nginx:1.18.0@sha256:e90ac5331fe095cea01b121a3627174b2e33e06e83720e9a934c7b8ccc9c55a0`,
  mounting configs and `tests/fixtures/tls` read-only at `/etc/nginx/tls`; `app` `depends_on` them.
- create `docker/nginx/openssl-legacy.cnf` — mounted into `tls-legacy` only and selected with
  `OPENSSL_CONF`; same as Debian's system default but `CipherString = DEFAULT@SECLEVEL=0`.
  Debian's `SECLEVEL=2` makes nginx reject the SHA-1-signed certificate at load time
  (`ca md too weak`) before `ssl_ciphers ...:@SECLEVEL=0` takes effect.
- modify `src/quantum_tool/crypto_scanner.py` — `scan_host` returns an `Endpoint` with
  `status: unreachable` (TCP connect fails) / `no_tls` (TCP ok, no TLS 1.2+ handshake) instead of
  `None`; `scan_all` counts only `ok` endpoints in the existing totals and adds an `unreachable`
  count.
- create `tests/integration/__init__.py`, `tests/integration/conftest.py` (waits up to 30 s
  for the three ports; fails clearly if they never open), `tests/integration/test_scan_host.py`
- modify `tests/unit/test_crypto_scanner.py` (refused connection now yields `unreachable`).
- modify `Makefile` — `unit` excludes `-m integration`; `test` runs everything. `unit` and `lint`
  use `run --no-deps` so they do not start the nginx targets.
- modify `tests/unit/test_config.py` — the CIDR-expansion test's `scan_host` mock returns an
  `unreachable` Endpoint instead of `None`, matching the new contract.

**Tests to write first:** `tls-rsa:443` negotiates TLSv1.3 and an RSA cert of 2048 bits;
`tls-ecdsa:443` cert is EC P-256; `tls-legacy:443` negotiates TLSv1.2 with suite `AES128-SHA`
(stdlib excludes 3DES) and a SHA-1 cert; `tls-rsa:9` is `unreachable`.

**Acceptance:** `make test PYTEST_ARGS="-m integration" && make test && make lint`

**Commit message**
```
Add simulated nginx TLS endpoints and scanner integration tests

Three nginx 1.18 containers with RSA, ECDSA and legacy policies stand in
for real infrastructure. Unreachable endpoints are now reported.
```

---

## T8 — Enumerate server-offered cipher suites with pyOpenSSL

**Goal:** Report every TLS 1.2 suite a server accepts, plus TLS 1.3 support, so assessment covers
the offered set rather than only the negotiated suite.

**Files**
- modify `src/quantum_tool/crypto_scanner.py` — `enumerate_ciphers(host, port)`: builds the
  candidate list from `Connection(SSL.Context(SSL.TLSv1_2_METHOD)).get_cipher_list()` after
  `set_cipher_list(b"ALL:COMPLEMENTOFALL:!PSK:!SRP:!aNULL:@SECLEVEL=0")`, then one handshake per
  candidate with a fresh `SSL.Context(SSL.TLSv1_2_METHOD)` and
  `set_cipher_list(name + ":@SECLEVEL=0")` (`TLSv1_2_METHOD` is fixed-version, so TLS 1.3 is
  never offered; pyOpenSSL 19.1 has no `set_max_proto_version`); collects accepted names.
  `tls13` detected with a stdlib `ssl` context with `minimum_version = TLSVersion.TLSv1_3`.
  Controlled by the `enumerate_ciphers` config key. `assess_endpoint` assesses every offered
  suite.
- create `tests/unit/tls_server.py` — threaded test server: stdlib `ssl` server context on
  `127.0.0.1:0` with the RSA fixture, a restricted cipher list and `maximum_version` TLS 1.2;
  an accept loop in a daemon thread that handshakes each connection, swallows `ssl.SSLError` on
  failed handshakes and keeps serving until a stop event is set; used as a pytest fixture.
- create `tests/unit/test_enumeration.py`
- create `tests/integration/test_enumeration.py`

**Tests to write first:** unit: local server restricted to `ECDHE-RSA-AES128-GCM-SHA256` →
exactly that suite, and the server is still accepting after the full candidate loop; no
candidate contains `PSK`, `SRP` or an `ADH`/`AECDH` name; `enumerate_ciphers: false` →
`offered_suites == []`. Integration (fixed `now`): `tls-rsa` offers include `AES128-SHA` and
`DHE-RSA-AES256-GCM-SHA384`; `tls-ecdsa` offers only ECDSA suites; `tls-legacy` offers
exactly `["AES128-SHA"]` (3DES fallback in effect, see Risks) and has `tls13 == False`; risk
scores are exactly `tls-legacy` 85, `tls-rsa` 70, `tls-ecdsa` 60 (SPEC §5.4).

**Acceptance:** `make test PYTEST_ARGS="tests/unit/test_enumeration.py tests/integration/test_enumeration.py" && make test && make lint`

**Commit message**
```
Enumerate server-offered TLS 1.2 cipher suites with pyOpenSSL

Probes each locally supported suite and detects TLS 1.3 separately, so
findings reflect everything a server accepts, not just the negotiated suite.
```

---

## T9 — Build liboqs 0.3.0 and add lattice-based PQC wrappers

**Goal:** Make CRYSTALS-Kyber and CRYSTALS-Dilithium available through liboqs-python, pinned to
the June 2020 commits and safe against the 0.3.0 use-after-free.

**Files**
- modify `Dockerfile` — `apt-get install -y --no-install-recommends cmake ninja-build` from the
  T1 snapshot sources (`libssl-dev` is already in the base image and must not be reinstalled or
  upgraded); download
  `https://github.com/open-quantum-safe/liboqs/archive/f6ca3dca5e95e77267dd0d7f5480c512cd6a4d6d.tar.gz`,
  check `sha256sum -c` against
  `bae2ec508c9a7c8d25ab873c91cc31682536209a1a324d56afae5a5e6bcf11c6`, build with
  `cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=/usr/local`,
  `ninja install`, `ldconfig`; download
  `https://github.com/open-quantum-safe/liboqs-python/archive/97e500c7eb74ec8acd14910b4d4a7e7b65dbeb5b.tar.gz`,
  check against `6a31d0aad459bad134840cff45fa7b08e12b918f20dbce0555ee889c5957ada6`, and
  `pip install --no-build-isolation` the extracted directory. Do not use the `0.3.0` tag URLs (the liboqs-python tag
  was moved to a July 2020 commit).
- create `src/quantum_tool/algorithms/__init__.py` — `available()` returns enabled mechanisms;
  `SafeKeyEncapsulation(oqs.KeyEncapsulation)` and `SafeSignature(oqs.Signature)` overriding
  `free()` to read `length_secret_key`, call `OQS_MEM_cleanse` on the secret key, then
  `OQS_KEM_free` / `OQS_SIG_free`, with a `_freed` flag so a second call is a no-op
  (`__exit__` calls the override).
- create `src/quantum_tool/algorithms/lattice_based.py` — `KyberKEM(level)` (Kyber512/768/1024),
  `DilithiumSigner(level)` (DILITHIUM_2/3/4), built only on the `Safe*` classes; both expose
  `details` lengths; invalid level raises `ValueError`.
- create `tests/unit/test_lattice_based.py`

**Tests to write first:** `oqs.get_enabled_KEM_mechanisms()` contains `Kyber512`; for each Kyber
level the encapsulated and decapsulated shared secrets match and lengths equal liboqs details;
Dilithium sign/verify succeeds and fails on a one-byte tampered message or wrong public key;
`KyberKEM(256)` raises `ValueError`; a loop creates 1000 `SafeKeyEncapsulation("Kyber512")`
objects, generates a keypair on each and frees it (half via `with`, half via `free()`, some
freed twice) without crashing; the same for 100 `SafeSignature("DILITHIUM_2")`;
`test_environment.py` still reports `OpenSSL 1.1.1d` after the apt step.

**Acceptance:** `make build && make test PYTEST_ARGS=tests/unit/test_lattice_based.py && make test && make lint`

**Commit message**
```
Build liboqs 0.3.0 and wrap Kyber and Dilithium

Compiles liboqs from a checksummed commit tarball, installs liboqs-python
0.3.0 and wraps it with a free() that cleanses keys before releasing them.
```

---

## T10 — Add hash-based SPHINCS+ signature wrapper

**Goal:** Provide the conservative hash-based alternative the roadmap recommends.

**Files**
- create `src/quantum_tool/algorithms/hash_based.py` — `SphincsSigner(variant)` for
  `SPHINCS+-SHA256-128f-simple` and `SPHINCS+-SHA256-128s-simple`, built on `SafeSignature`.
- create `tests/unit/test_hash_based.py`

**Tests to write first:** both variants round-trip sign/verify; tampered message fails;
128s signature is shorter than 128f; unknown variant raises `ValueError`; a signer used as a
context manager and then freed again does not crash.

**Acceptance:** `make test PYTEST_ARGS=tests/unit/test_hash_based.py && make test && make lint`

**Commit message**
```
Add SPHINCS+ hash-based signature wrapper

Wraps the SHA-256 128f and 128s simple parameter sets from liboqs as the
conservative alternative to lattice-based signatures.
```

---

## T11 — Measure PQC replacement costs for the roadmap

**Goal:** Measure key/ciphertext/signature sizes and operation times so roadmap phases can quote
the cost of each replacement (SPEC §2 item 8). Kept to one module.

**Files**
- create `src/quantum_tool/algorithms/benchmark.py` — `run(names, iterations)` returning
  `BenchResult` dicts (SPEC §5.2) using `time.perf_counter` and the `Safe*` classes; default set
  Kyber512/768, DILITHIUM_2/3, SPHINCS+-SHA256-128f-simple.
- create `tests/unit/test_benchmark.py`

**Tests to write first:** `run(["Kyber512"], 2)` returns one `kem` result with positive timings and
`ciphertext_len` equal to liboqs details; a signature algorithm returns `signature_len`; an
unknown name raises `ValueError`; `iterations < 1` raises.

**Acceptance:** `make test PYTEST_ARGS=tests/unit/test_benchmark.py && make test && make lint`

**Commit message**
```
Measure PQC key generation, encapsulation and signing costs

Records sizes and mean operation times for the wrapped liboqs algorithms
so the migration roadmap can quote costs from the local machine.
```

---

## T12 — Build prioritised migration roadmap from assessments

**Goal:** Turn findings into ordered migration phases with replacements, hybrid guidance and
benchmark figures.

**Files**
- create `src/quantum_tool/migration_engine.py` — `REPLACEMENTS` map (kex → Kyber768, auth/cert
  key/private key → DILITHIUM_3 with SPHINCS+ alternative, 3DES/RC4/AES-128 → AES-256-GCM,
  HMAC-SHA1 → AEAD suite, SHA-1/MD5/SHA-256 → SHA-384), `build_roadmap(assessments, bench=None)`
  grouping targets by (component, algorithm), ordered by max risk then threat class
  (`shor` before `classical` before `grover`) then target count; each Shor phase carries a hybrid
  note ("keep ECDHE/RSA alongside Kyber/Dilithium until PQC TLS is standardised").
  Phases also record `component`, `threat_class` and `alternative`; an optional `now` fixes
  `generated_at` for tests.
- create `tests/unit/test_migration_engine.py`

**Tests to write first:** given hand-built assessments, phases are ordered by risk; targets that
share an algorithm are grouped; `classical` and `grover` findings come after Shor findings with
the same score; bench data is attached to matching phases and absent otherwise; empty input
produces an empty roadmap.

**Acceptance:** `make test PYTEST_ARGS=tests/unit/test_migration_engine.py && make test && make lint`

**Commit message**
```
Build a prioritised PQC migration roadmap from findings

Groups targets by vulnerable algorithm, orders phases by risk and attaches
the recommended replacement, a hybrid interim step and benchmark costs.
```

---

## T13 — Write JSON reports and a Markdown roadmap

**Goal:** Persist results in the configured `output_path`.

**Files**
- modify `requirements.txt` — add `Jinja2==2.11.2`, `MarkupSafe==1.1.1`.
- create `src/quantum_tool/report.py` — `write_json(report, dir) -> path`,
  `write_markdown(roadmap, report, dir) -> path`; filenames `scan-<UTC ts>.json`,
  `roadmap-<UTC ts>.md`; creates the directory; `write_outputs(report, roadmap, dir, fmt)`
  applies `output_format` (SPEC §5.1).
- create `src/quantum_tool/templates/roadmap.md.j2` — summary table, per-endpoint findings,
  phases with replacement, hybrid note and benchmark table.
- modify `setup.py` — `package_data` for templates.
- create `tests/unit/test_report.py`

**Tests to write first:** JSON output round-trips via `json.load` and keeps the legacy keys
(`scan_date`, `total_endpoints`, `vulnerable_endpoints`, `risk_percentage`, `results`, `summary`);
Markdown contains one `##` section per phase, the endpoint table and the benchmark table when
bench data is given; writing into a missing directory creates it (`tmp_path`); `write_outputs`
with `json` / `markdown` / `both` writes exactly the matching files.

**Acceptance:** `make build && make test PYTEST_ARGS=tests/unit/test_report.py && make test && make lint`

**Commit message**
```
Write JSON scan reports and a Jinja2 Markdown roadmap

Reports keep the original summary keys and add assessments and roadmap
phases, rendered into the configured output directory.
```

---

## T14 — Add Click CLI with scan, certs, bench and roadmap commands

**Goal:** One entry point that runs the whole pipeline end to end against the simulated stack.

**Files**
- modify `requirements.txt` — add `click==7.1.2`.
- create `src/quantum_tool/cli.py` — `scan|certs|bench|roadmap` with exactly the options in
  SPEC §5.5: `-c`, `-o`, `--no-enum` (overrides `enumerate_ciphers`), `--fail-on LEVEL`
  (exit 1), `-v`; `ConfigError` → exit 2.
- create `src/quantum_tool/__main__.py` (`python -m quantum_tool` calls `cli.main`).
- modify `setup.py` — `console_scripts: quantum=quantum_tool.cli:main` (for installs outside
  Docker; not used by the Makefile or tests).
- create `config/scan_config.docker.yml` — targets `tls-rsa`, `tls-ecdsa`, `tls-legacy`,
  port 443, `cert_paths: [tests/fixtures/tls]`, `bench_iterations: 5`, `output_format: both`,
  `output_path: reports/`.
- modify `Makefile` — `demo` target: `$(COMPOSE) run --rm app python -m quantum_tool roadmap -c
  config/scan_config.docker.yml`.
- create `tests/unit/test_cli.py`, `tests/integration/test_cli_end_to_end.py`

**Tests to write first:** unit (`CliRunner`): `--help` for every command lists the SPEC §5.5
options; a bad config exits 2; `bench -n 1 --alg Kyber512` prints a table row;
`certs tests/fixtures/tls` lists three certificates and three keys with threat levels;
`scan --no-enum` with a patched scanner leaves `offered_suites` empty. Integration (subprocess
`python -m quantum_tool`): `roadmap -c config/scan_config.docker.yml -o <tmp>` exits 0 and writes
one JSON and one Markdown file; Markdown names Kyber and Dilithium phases and lists
`tls-legacy:443`; `scan -c config/scan_config.docker.yml -o <tmp> --fail-on critical` exits 1.

**Acceptance:** `make build && make test && make lint && make demo`

**Commit message**
```
Add quantum CLI for scan, certs, bench and roadmap

Click entry point wiring config, scanner, certificate manager, assessor,
benchmark and reports; includes a config for the simulated endpoints.
```

---

## T15 — Regenerate README from template with honest status

**Goal:** README describes exactly what the repo does, following
`tools/readme_template.md`.

**Files**
- create `scripts/check_readme.py` — `--tree` prints a layout tree built from
  `git ls-files --cached --others --exclude-standard` (so files added in this task appear before
  they are committed; plain Python, no `tree` binary); default mode extracts path-like tokens from README.md (every
  line of the Layout code block, plus inline-code spans containing `/` or ending in a file
  extension) and exits 1 listing any that do not exist (`os.path.exists`).
- modify `README.md` — fill the template: title, one-paragraph description, "Personal project
  built on the 2020-era stack (Python 3.8, pyOpenSSL, cryptography, liboqs 0.3.0)"; Status lists
  only features with code and tests (SPEC §2 items 1–12); limitations from SPEC §3 and §11,
  including the liboqs-python use-after-free workaround and the nginx 2021 rebuild; states that
  the network is simulated by three nginx 1.18 containers with self-signed test certs and that
  the tool has never been run against real infrastructure; Built with lists pinned versions;
  Running it uses `docker-compose up -d tls-rsa tls-ecdsa tls-legacy` and `make demo`; Tests
  section; Layout tree from `docker-compose run --rm app python scripts/check_readme.py --tree`
  pasted unedited. Template comment removed. No badges, employer, role, date-range or metric
  claims.

**Tests to write first:** none (docs only); the acceptance command runs the checker.

**Acceptance:** `make test && make lint && docker-compose run --rm app python scripts/check_readme.py && ! grep -Eiq 'ACORIA|Etech|Zambaiti|\bAEL\b|uptime|MTTR|Efrem|Career Portfolio|IT Operations|Timeline|shields.io|Developed during|Status-Complete' README.md`

**Commit message**
```
Regenerate README from template with honest status and layout

Describes implemented features, mocked TLS endpoints and known limits, with
a layout tree generated from the tracked files and a path check script.
```

---

## Risks and mitigations

- **Debian buster apt mirrors** — the live buster archive now serves final-release packages
  (e.g. libssl 1.1.1n from 2022). The Dockerfile points apt at
  `snapshot.debian.org/archive/debian/20200615T000000Z` and the matching `debian-security`
  snapshot with `Check-Valid-Until=false`, and installs only cmake 3.13.4 and ninja-build 1.8.2;
  `libssl-dev` is never reinstalled. `test_environment.py` fails if OpenSSL is not 1.1.1d.
- **cryptography wheels bundle OpenSSL 1.1.1g** — installing with `--no-binary cryptography` builds
  it against Debian's 1.1.1d on every architecture, so stdlib `ssl` and pyOpenSSL agree on the
  cipher list; no arm64 wheel for 2.9.2 exists anyway.
- **Build isolation would fetch post-2020 build tools** — cryptography 2.9.2's `pyproject.toml`
  lists unpinned `setuptools`/`wheel`/`cffi`, which pip 20.1.1 would resolve to 2024 releases in an
  isolated build env. `requirements-build.txt` is installed first and cryptography (and
  liboqs-python) are installed with `--no-build-isolation`; `test_environment.py` asserts the
  pinned setuptools/wheel/cffi versions.
- **nginx has no default DH parameters** — since 1.11.0, DHE suites are silently disabled without
  `ssl_dhparam`. `tls-rsa.conf` points at the committed `dhparam-2048.pem`; the T8 integration
  test asserting `DHE-RSA-AES256-GCM-SHA384` is offered catches a missing file.
- **liboqs-python `0.3.0` tag was moved** — the tag now points at `8af801e0` (2020-07-14) and its
  tarball contains three July 2020 commits. The real "Version 0.3.0" commit is `97e500c`
  (2020-06-10); it and liboqs 0.3.0 commit `f6ca3dc` (2020-06-10) are fetched by commit and
  verified by sha256.
- **Use-after-free in liboqs-python 0.3.0** — `free()` reads the secret-key length after
  `OQS_KEM_free`/`OQS_SIG_free` (fixed upstream on 2020-07-07). All wrappers use the
  `SafeKeyEncapsulation`/`SafeSignature` overrides from T9, and the 1000-object loop test catches
  regressions.
- **3DES availability in nginx:1.18.0's OpenSSL 1.1.1** — confirmed in T8: Debian's 1.1.1d build
  (in both the nginx image and the app image) has no 3DES suites, so `DES-CBC3-SHA` cannot be
  enabled even with `@SECLEVEL=0`. `tls-legacy` falls back to `AES128-SHA` plus the SHA-1
  certificate; its score is 85 and stays the highest, and the T8 assertions match.
- **nginx:1.18.0 is a 2021 rebuild** — last pushed 2021-04-10; pinned by digest so every run uses
  the same image.
- **Client-side OpenSSL policy** — buster's `openssl.cnf` sets `MinProtocol=TLSv1.2` and
  `SECLEVEL=2`; the enumeration context sets `@SECLEVEL=0` explicitly so weak suites can still be
  probed. TLS 1.0/1.1-only servers are reported as `no_tls` (SPEC §11).
- **Bind mount hides build-time package metadata** — no editable install; code is imported via
  `PYTHONPATH=/app/src` and the CLI runs as `python -m quantum_tool`.
- **Time-dependent certificate checks** — `risk_score` / `assess_*` take `now`; tests fix it.
- **Timing-based benchmark tests** — only assert positive timings, never absolute speeds.

---

## T16 — Security and hygiene hardening

**Goal:** Review the whole repository for security, fail-open and hygiene problems and fix them,
including the batch-wide required items for this repo (published ports, bounded work, strict
parsing, fail closed, no secret leaks, exact-match lookups, escaping, ambiguity needs an admin).

**Found and changed**
- **Unassessed endpoints passed the `--fail-on` gate (fail open).** `no_tls` endpoints (which
  include TLS 1.0/1.1-only servers) were dropped from the report without a count, and a scan in
  which every endpoint was unreachable exited 0 with a roadmap saying no vulnerable algorithms
  were found. The report now carries `no_tls`, `errors` and an `unassessed` list; the CLI always
  warns about them, and with `--fail-on` exits 1 when anything answered but was not assessed, a
  certificate file could not be read, or nothing was assessed. The Markdown roadmap lists the
  unassessed endpoints and says the assessment is incomplete instead of claiming safety.
- **Unclassified cipher suites scored as safe.** A name the parser could not decompose gave no
  findings and risk 0. Two suites the scanner itself can negotiate (`ECDHE-ARIA128-GCM-SHA256`,
  `ECDHE-ARIA256-GCM-SHA384`) hit this. The parser now knows OpenSSL's `ECDHE-ARIA…` spelling,
  a test checks every candidate suite of the local OpenSSL is classified, and any remaining
  unparsable suite gives an `unknown` / `high` finding (15 points, its own review phase in the
  roadmap).
- **One bad endpoint aborted the whole scan; config accepted values that crashed it.** An
  exception in any worker (for example `UnicodeError` from `encode('idna')` on a malformed host
  name) propagated out of `scan_all`. Each endpoint is now isolated (`status: error`, counted),
  submission is bounded to `2 * max_workers` queued endpoints, and the config rejects malformed
  targets, NaN/infinite or > 300 s timeouts, repeated ports, `bench_iterations` > 10000 and
  duplicate YAML keys (PyYAML otherwise keeps the last one silently).
- **pyOpenSSL enumeration handshakes had only a per-read timeout.** A server trickling one byte
  per read kept the scan open indefinitely. `_handshake` now enforces one deadline for the whole
  handshake. (The stdlib `ssl` handshake already applies its timeout to the whole handshake; tests
  cover all three handshake paths against a trickling server.)
- **Certificate inventory could hang or exhaust memory.** A FIFO named `*.pem` blocked `open()`
  forever and every file was read whole. Files are opened non-blocking, must be regular files of
  at most 4 MiB, and unreadable files/directories (including `os.walk` errors, previously ignored)
  are returned as `unreadable` and reported; an explicitly named unreadable file is an error
  (exit 2) instead of a traceback.
- **`roadmap --from-json` trusted the file.** Invalid JSON raised a traceback, a structure without
  `results` silently gave an empty "safe" roadmap, and `assessments` were taken as-is.
  `report.read_json` refuses non-regular files (a FIFO blocked `open()`), caps the size (50 MiB),
  rejects invalid JSON, duplicate keys, NaN/Infinity and
  non-report structures (exit 2), and recomputes totals, summary and assessments from `results`.
- **Markdown injection.** File paths and host names were rendered unescaped into Markdown tables;
  a `|` broke the table and `<…>` passed HTML through. Every rendered value is now escaped via
  the Jinja2 `finalize` hook.
- **Report write errors** (unwritable output directory) now exit 2 with a message, not a traceback.
- **Published ports check (required item 33).** `scripts/check_ports.py` and `make ports-check`
  fail if the rendered compose config publishes a port beyond `127.0.0.1` (short and long syntax)
  or uses `network_mode: host`; a unit test runs it on `docker-compose.yml`. The stack publishes
  no ports.
- **apt sources over HTTPS.** The snapshot sources used `http://`; they now use `https://`
  (signature checking was and stays on), and a test fails on `http://` or any unauthenticated-
  install option in the Dockerfile.
- `make lint` also checks `scripts/`.

**Checked, no change needed**
- No credentials, tokens or connection URLs exist in the tool; KeyInfo never carries key material
  and errors name only paths. Committed keys under `tests/fixtures/tls/` are documented test-only
  material served by the local nginx containers.
- No user accounts, directory or IdP integration, so the "ambiguity requires an authenticated
  admin" rule has nothing to apply to; no HTTP endpoints, so no CSRF/auth surface.
- Name lookups that select work (`bench --alg`, Kyber/Dilithium/SPHINCS+ levels) are exact-match.
- No era-performing comments, @author tags, AI mentions or debug leftovers were found.

**Not changed:** a peer certificate that cannot be parsed still yields `certificate: None`; the
endpoint is scored from its suites only (listed in the README limitations).

**Tests to write first:** `test_config.py` (NaN/inf/301 timeouts, duplicate keys, malformed and
well-formed targets, repeated ports, iterations cap); `test_cipher_suites.py` (ARIA cases, every
local candidate classified); `test_vulnerability_assessor.py` / `test_migration_engine.py`
(`unknown` finding, score and phase); `test_crypto_scanner.py` (trickling server against all three
handshake paths, error isolation, `no_tls` counts, bounded submission keeps order);
`test_certificate_manager.py` (FIFO, oversized file, non-regular `load_file`); `test_report.py`
(escaping, unassessed section, incomplete wording, `read_json` validation and recomputation);
`test_cli.py` (fail-on with `no_tls`, all unreachable, unreadable files, malformed `--from-json`,
recomputed assessments); `test_container_config.py` (ports check, Dockerfile apt sources).

**Acceptance:** `make build && make test && make lint && make ports-check && docker-compose run --rm app python scripts/check_readme.py`

**Commit message**
```
Fail closed on unassessed endpoints and harden input handling

Report and gate on endpoints that could not be assessed, flag unclassified
suites, bound handshakes and file reads, validate config and JSON reports.
```

---

## T17 — Security and hygiene hardening

**Goal:** Second whole-repository review, covering the batch-wide required items for this repo:
report escaping of scanned values (item 44), least privilege and credential scoping in the
compose stack (item 45), and a re-check of the general batch 4 rules (item 33).

**Found and changed**
- **Markdown injection was only partly closed (item 44).** T16 escaped `\`, `|`, backticks,
  `<`, `>`, `&` and line breaks. Brackets, parentheses, `*`, `_`, `#`, `!`, `~`, `$` and a
  leading `-`/`+`/`1.` still had Markdown meaning, bare `http://…`, `www.…` and e-mail values
  became autolinks, ANSI sequences, bidi overrides and zero-width characters passed through, a
  lone surrogate from a `--from-json` report crashed the UTF-8 write, a non-string value (for
  example a dict in place of a suite name) was rendered unescaped, and values had no length cap.
  New `quantum_tool/escaping.py` holds the one helper used by every writer: `clean_text`
  (strips control, ANSI, bidi/zero-width and surrogate characters, line breaks to spaces,
  truncates to 256 characters), `markdown_text` (entities for `& < >`, backslash-escapes every
  Markdown special character, escapes block starts, breaks `://` and `www.`), `markdown_join`
  (each list item escaped and truncated on its own) and `terminal_text`. The Jinja2 `finalize`
  hook is `markdown_text`, targets go through the `md_join` filter, the Markdown file is written
  as UTF-8 and the JSON report with `ensure_ascii=True`. There is no HTML or CSV writer.
- **Terminal escape injection in CLI output.** File names, host names, suites and error texts
  were echoed raw; a certificate file named with ANSI/OSC sequences could rewrite the operator's
  terminal. Every such value now goes through `terminal_text`.
- **Compose services ran with default privileges (item 45).** All services now drop all
  capabilities (nginx adds back only CHOWN, SETUID, SETGID and NET_BIND_SERVICE), set
  `no-new-privileges:true` and run with a read-only root filesystem and tmpfs scratch space; the
  app runs as the invoking user (`QUANTUM_UID`/`QUANTUM_GID`, exported by the Makefile) instead
  of root; the network is `internal: true` (still `172.74.0.0/24`) since nothing needs outbound
  access at runtime. `scripts/check_compose_security.py` / `make security-check` fail on
  privileged mode, host namespaces, Docker-socket or credential-directory mounts, missing
  `cap_drop: [ALL]` or no-new-privileges, `SYS_ADMIN`/`ALL` in `cap_add`, and credential-like
  values in environment, build args, command, entrypoint or healthcheck.
- **Committed-secret scan.** A test walks the repository and fails on AWS key ids,
  credential-like assignments without a `stub-`/`lab-` value, URLs with userinfo, and private keys
  outside `tests/fixtures/tls/` (the documented test-only keys).
- The apt-source test now covers every Dockerfile and apt config in the repository, not only the
  top-level Dockerfile.

**Checked, no change needed**
- No credentials, tokens or connection URLs exist in the tool or the compose file, so there is
  nothing to scope or move into `secrets:`; nothing is published on the host.
- Bounded work, strict parsing, fail-closed reporting and exact-match lookups from T16 still hold;
  no HTTP endpoints, user accounts or directory integration exist (no CSRF/auth surface).
- No era-performing comments, @author tags, AI mentions or debug leftovers.

**Tests to write first:** `test_escaping.py` (control/ANSI/bidi/surrogate stripping, truncation,
every special character escaped and round-tripping, block starts, autolinks, numbers kept,
`markdown_join`); `test_report.py` (hostile host/suite/target/algorithm values keep the
Markdown skeleton identical and render inert, truncation, non-string values, surrogates, ASCII
JSON, lint tests: environment `finalize`, no escape bypass in the template, report.py writes only
rendered or `ensure_ascii` JSON text); `test_cli.py` (no escape sequences on stdout/stderr from
file names, report values or report paths); `test_container_config.py` (shipped compose is
least-privileged and internal, each privilege/credential problem is reported, secret file
references allowed, committed-secret scan, apt sources in every Dockerfile).

**Acceptance:** `make build && make test && make lint && make ports-check && make security-check && docker-compose run --rm app python scripts/check_readme.py`

**Commit message**
```
Escape scanned values everywhere and drop container privileges

Route every report and console value through one escape helper and run the
compose services least-privileged on an internal network.
```
