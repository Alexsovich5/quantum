"""JSON and Markdown report files written into the output directory."""

import json
import os
from datetime import datetime

import pytest

from quantum_tool import report as rp

NOW = datetime(2020, 6, 30, 0, 0, 0)

KYBER768 = {
    "algorithm": "Kyber768", "kind": "kem", "public_key_len": 1184, "secret_key_len": 2400,
    "ciphertext_len": 1088, "keygen_ms": 0.05, "encap_ms": 0.06, "decap_ms": 0.05,
}
DILITHIUM3 = {
    "algorithm": "DILITHIUM_3", "kind": "sig", "public_key_len": 1472, "secret_key_len": 3504,
    "signature_len": 2701, "keygen_ms": 0.2, "sign_ms": 0.6, "verify_ms": 0.2,
}


def endpoint(host, port, suite, vulnerabilities):
    return {
        "host": host, "port": port, "status": "ok", "protocol": "TLSv1.2", "tls13": False,
        "negotiated_suite": suite, "offered_suites": [suite], "cipher_suite": suite,
        "key_exchange": "ECDH", "auth_algorithm": "RSA", "key_bits": 128,
        "certificate": None, "scan_time": "2020-06-30T00:00:00",
        "vulnerabilities": vulnerabilities,
    }


def make_report():
    vuln = {"component": "key_exchange", "algorithm": "ECDH", "threat_level": "critical"}
    return {
        "scan_date": "2020-06-30T00:00:00",
        "total_endpoints": 2,
        "vulnerable_endpoints": 1,
        "risk_percentage": 50.0,
        "unreachable": 1,
        "results": [
            endpoint("rsa.test", 443, "ECDHE-RSA-AES128-GCM-SHA256", [vuln]),
            endpoint("safe.test", 8443, "TLS_AES_256_GCM_SHA384", []),
        ],
        "assessments": [
            {"target": "rsa.test:443", "risk_score": 85, "findings": []},
            {"target": "safe.test:8443", "risk_score": 0, "findings": []},
        ],
        "summary": {"critical": 1, "quantum_safe": 1},
    }


def phase(priority, component, algorithm, threat_class, replacement, bench=None):
    return {
        "priority": priority, "component": component, "algorithm": algorithm,
        "threat_class": threat_class, "replacement": replacement,
        "alternative": "SPHINCS+-SHA256-128f-simple" if component == "authentication" else None,
        "hybrid": "Keep ECDHE/RSA alongside Kyber/Dilithium" if threat_class == "shor" else None,
        "targets": ["rsa.test:443"], "max_risk": 85, "bench": bench,
    }


def make_roadmap(with_bench=False):
    return {
        "generated_at": "2020-06-30T00:00:00Z",
        "phases": [
            phase(1, "key_exchange", "ECDH", "shor", "Kyber768",
                  KYBER768 if with_bench else None),
            phase(2, "authentication", "RSA", "shor", "DILITHIUM_3",
                  DILITHIUM3 if with_bench else None),
            phase(3, "cipher", "AES-128", "grover", "AES-256-GCM"),
        ],
    }


def test_json_round_trips_and_keeps_legacy_keys(tmp_path):
    report = make_report()
    path = rp.write_json(report, str(tmp_path), now=NOW)

    assert os.path.basename(path) == "scan-20200630T000000Z.json"
    with open(path) as handle:
        loaded = json.load(handle)
    for key in ("scan_date", "total_endpoints", "vulnerable_endpoints", "risk_percentage",
                "results", "summary"):
        assert loaded[key] == report[key]
    assert loaded["assessments"] == report["assessments"]


def test_json_includes_roadmap_when_given(tmp_path):
    roadmap = make_roadmap()
    path = rp.write_json(make_report(), str(tmp_path), roadmap=roadmap, now=NOW)
    with open(path) as handle:
        assert json.load(handle)["roadmap"] == roadmap


def test_json_does_not_modify_the_report(tmp_path):
    report = make_report()
    rp.write_json(report, str(tmp_path), roadmap=make_roadmap(), now=NOW)
    assert "roadmap" not in report


def test_markdown_has_one_section_per_phase(tmp_path):
    path = rp.write_markdown(make_roadmap(), make_report(), str(tmp_path), now=NOW)

    assert os.path.basename(path) == "roadmap-20200630T000000Z.md"
    with open(path) as handle:
        text = handle.read()
    lines = text.splitlines()
    phase_headings = [line for line in lines if line.startswith("## Phase ")]
    assert phase_headings == [
        "## Phase 1: key_exchange ECDH -> Kyber768",
        "## Phase 2: authentication RSA -> DILITHIUM_3",
        "## Phase 3: cipher AES-128 -> AES-256-GCM",
    ]
    assert "Keep ECDHE/RSA alongside Kyber/Dilithium" in text
    assert "SPHINCS+-SHA256-128f-simple" in text


def test_markdown_has_endpoint_table(tmp_path):
    path = rp.write_markdown(make_roadmap(), make_report(), str(tmp_path), now=NOW)
    with open(path) as handle:
        lines = handle.read().splitlines()

    assert "| Endpoint | Protocol | Negotiated suite | Risk score | Findings |" in lines
    assert "| rsa.test:443 | TLSv1.2 | ECDHE-RSA-AES128-GCM-SHA256 | 85 | 1 |" in lines
    assert "| safe.test:8443 | TLSv1.2 | TLS_AES_256_GCM_SHA384 | 0 | 0 |" in lines
    assert "| Total endpoints | 2 |" in lines
    assert "| Vulnerable endpoints | 1 |" in lines


def test_markdown_benchmark_table_only_with_bench_data(tmp_path):
    without = rp.write_markdown(make_roadmap(), make_report(), str(tmp_path / "a"), now=NOW)
    with open(without) as handle:
        assert "Benchmark" not in handle.read()

    with_bench = rp.write_markdown(make_roadmap(with_bench=True), make_report(),
                                   str(tmp_path / "b"), now=NOW)
    with open(with_bench) as handle:
        lines = handle.read().splitlines()
    assert "## Benchmark" in lines
    assert "| Kyber768 | kem | 1184 | 2400 | 1088 | 0.05 | 0.06 | 0.05 |" in lines
    assert "| DILITHIUM_3 | sig | 1472 | 3504 | 2701 | 0.2 | 0.6 | 0.2 |" in lines


def test_markdown_without_phases_says_so(tmp_path):
    roadmap = {"generated_at": "2020-06-30T00:00:00Z", "phases": []}
    path = rp.write_markdown(roadmap, make_report(), str(tmp_path), now=NOW)
    with open(path) as handle:
        text = handle.read()
    assert "## Phase " not in text
    assert "No migration phases" in text


def test_missing_directory_is_created(tmp_path):
    target = tmp_path / "nested" / "reports"
    json_path = rp.write_json(make_report(), str(target), now=NOW)
    md_path = rp.write_markdown(make_roadmap(), make_report(), str(target), now=NOW)
    assert os.path.isfile(json_path)
    assert os.path.isfile(md_path)
    assert os.path.dirname(json_path) == str(target)


@pytest.mark.parametrize("fmt, expected", [
    ("json", ["scan-20200630T000000Z.json"]),
    ("markdown", ["roadmap-20200630T000000Z.md"]),
    ("both", ["roadmap-20200630T000000Z.md", "scan-20200630T000000Z.json"]),
])
def test_write_outputs_honours_format(tmp_path, fmt, expected):
    paths = rp.write_outputs(make_report(), make_roadmap(), str(tmp_path), fmt, now=NOW)
    assert sorted(os.listdir(str(tmp_path))) == expected
    assert sorted(os.path.basename(p) for p in paths) == expected


def test_write_outputs_rejects_unknown_format(tmp_path):
    with pytest.raises(ValueError):
        rp.write_outputs(make_report(), make_roadmap(), str(tmp_path), "html", now=NOW)
    assert os.listdir(str(tmp_path)) == []


def test_template_ships_as_package_data():
    import setuptools

    captured = {}
    original = setuptools.setup
    setuptools.setup = lambda **kwargs: captured.update(kwargs)
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        setup_py = os.path.join(here, "..", "..", "setup.py")
        with open(setup_py) as handle:
            exec(compile(handle.read(), setup_py, "exec"), {"__name__": "__main__"})
    finally:
        setuptools.setup = original
    assert "templates/*.j2" in captured["package_data"]["quantum_tool"]


def _render(roadmap, report):
    return rp.render_markdown(roadmap, report)


def test_markdown_escapes_values_that_could_break_tables_or_inject_html():
    roadmap = make_roadmap()
    roadmap["phases"][0]["targets"] = ["/certs/a|b<img src=x onerror=alert(1)>.pem\nx"]
    report = make_report()
    report["results"][0]["host"] = "evil|host"

    lines = _render(roadmap, report).splitlines()

    assert "- Targets: /certs/a\\|b&lt;img src=x onerror=alert(1)&gt;.pem x" in lines
    assert any(line.startswith("| evil\\|host:443 |") for line in lines)
    assert not any("<img" in line for line in lines)


def test_markdown_lists_unassessed_endpoints():
    report = make_report()
    report.update(no_tls=1, errors=1, unassessed=[
        {"host": "old.test", "port": 443, "status": "no_tls"},
        {"host": "bad.test", "port": 8443, "status": "error"}])

    lines = _render(make_roadmap(), report).splitlines()

    assert "| Not assessed (no TLS 1.2+ handshake) | 1 |" in lines
    assert "| Scan errors | 1 |" in lines
    assert "| old.test:443 | no_tls |" in lines
    assert "| bad.test:8443 | error |" in lines


def test_markdown_without_phases_does_not_claim_safety_when_nothing_was_assessed():
    report = make_report()
    report.update(total_endpoints=0, results=[], assessments=[], no_tls=2, unassessed=[
        {"host": "old.test", "port": 443, "status": "no_tls"},
        {"host": "old.test", "port": 8443, "status": "no_tls"}])
    roadmap = {"generated_at": "2020-06-30T00:00:00Z", "phases": []}

    text = _render(roadmap, report)

    assert "no quantum-vulnerable or weak algorithms were found" not in text
    assert "assessment is incomplete" in text


def _write(tmp_path, data):
    path = tmp_path / "scan.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return str(path)


@pytest.mark.parametrize("data", [
    "{not json", "[]", {"results": "x"}, {"results": [1]}, {"no_results": []},
    {"results": [], "unreachable": -1}, {"results": [], "unassessed": [{"host": "h"}]},
    "NaN", '{"results": [], "results": []}',
])
def test_read_json_rejects_malformed_reports(tmp_path, data):
    with pytest.raises(ValueError):
        rp.read_json(_write(tmp_path, data))


def test_read_json_rejects_oversized_files(tmp_path, monkeypatch):
    monkeypatch.setattr(rp, "MAX_REPORT_BYTES", 64)
    with pytest.raises(ValueError, match="larger than 64 bytes"):
        rp.read_json(_write(tmp_path, {"results": [], "pad": "x" * 100}))


def test_read_json_rebuilds_totals_and_assessments_from_results(tmp_path):
    data = {
        "scan_date": "2020-06-30T00:00:00", "unreachable": 2,
        "total_endpoints": 0, "assessments": [],
        "results": [{"host": "h", "port": 443, "status": "ok",
                     "negotiated_suite": "ECDHE-RSA-AES128-GCM-SHA256", "certificate": None,
                     "vulnerabilities": [{"threat_level": "critical"}]}],
        "unassessed": [{"host": "old", "port": 443, "status": "no_tls"}],
    }

    report = rp.read_json(_write(tmp_path, data))

    assert report["total_endpoints"] == 1
    assert report["unreachable"] == 2
    assert report["no_tls"] == 1
    assert report["scan_date"] == "2020-06-30T00:00:00"
    [assessment] = report["assessments"]
    assert assessment["target"] == "h:443" and assessment["risk_score"] > 0


def test_read_json_refuses_a_fifo_without_blocking(tmp_path):
    import threading

    fifo = str(tmp_path / "scan.json")
    os.mkfifo(fifo)
    box = {}

    def load():
        try:
            rp.read_json(fifo)
        except ValueError as exc:
            box["error"] = exc

    worker = threading.Thread(target=load, daemon=True)
    worker.start()
    worker.join(5)

    assert not worker.is_alive(), "read_json blocked on a FIFO"
    assert "regular file" in str(box["error"])
