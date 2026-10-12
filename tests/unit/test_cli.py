"""Click command line: options, exit codes and wiring of each command."""

import glob
import json
import os
import ssl
import threading
from unittest import mock

import pytest
from click.testing import CliRunner

from quantum_tool import cli
from quantum_tool.crypto_scanner import CryptoScanner
from tests.unit.fakes import FakeRawSocket, FakeSSLSocket, fake_connection

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures", "tls")

COMMAND_OPTIONS = {
    "scan": ["-c", "--no-enum", "-o", "--fail-on", "-v"],
    "certs": ["-c", "--fail-on", "-v", "PATH"],
    "bench": ["-n", "--alg", "-v"],
    "roadmap": ["-c", "--from-json", "--no-enum", "-o", "--fail-on", "-v"],
}


@pytest.fixture
def runner():
    return CliRunner(mix_stderr=False)


def _write_config(tmp_path, text):
    path = tmp_path / "config.yml"
    path.write_text(text)
    return str(path)


@pytest.mark.parametrize("command", sorted(COMMAND_OPTIONS))
def test_help_lists_spec_options(runner, command):
    result = runner.invoke(cli.main, [command, "--help"])

    assert result.exit_code == 0, result.output
    for option in COMMAND_OPTIONS[command]:
        assert option in result.output, "{} --help lacks {}".format(command, option)


def test_top_level_help_lists_every_command(runner):
    result = runner.invoke(cli.main, ["--help"])

    assert result.exit_code == 0
    for command in COMMAND_OPTIONS:
        assert command in result.output


@pytest.mark.parametrize("command", ["scan", "certs", "roadmap"])
def test_bad_config_exits_2(runner, tmp_path, command):
    config = _write_config(tmp_path, "targets: [example.org]\nunknown_key: 1\n")

    result = runner.invoke(cli.main, [command, "-c", config])

    assert result.exit_code == 2
    assert "unknown_key" in result.stderr


def test_missing_config_file_exits_2(runner, tmp_path):
    result = runner.invoke(cli.main, ["scan", "-c", str(tmp_path / "absent.yml")])

    assert result.exit_code == 2


def test_oversized_cidr_is_a_config_error(runner, tmp_path):
    config = _write_config(tmp_path, "targets: [10.0.0.0/16]\nmax_hosts: 4\n")

    result = runner.invoke(cli.main, ["scan", "-c", config, "-o", str(tmp_path)])

    assert result.exit_code == 2
    assert "max_hosts" in result.stderr


def test_bench_prints_a_row_for_the_requested_algorithm(runner):
    result = runner.invoke(cli.main, ["bench", "-n", "1", "--alg", "Kyber512"])

    assert result.exit_code == 0, result.output
    rows = [line for line in result.output.splitlines() if line.startswith("Kyber512")]
    assert len(rows) == 1
    fields = rows[0].split()
    assert fields[1] == "kem"
    assert fields[2] == "800"  # Kyber512 public key length in bytes


def test_bench_rejects_unknown_algorithm(runner):
    result = runner.invoke(cli.main, ["bench", "-n", "1", "--alg", "NoSuchKEM"])

    assert result.exit_code == 2
    assert "NoSuchKEM" in result.stderr


def test_certs_lists_fixture_certificates_and_keys_with_threat_levels(runner):
    result = runner.invoke(cli.main, ["certs", FIXTURES])

    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    certs = [line for line in lines if line.startswith("certificate ")]
    keys = [line for line in lines if line.startswith("key ")]
    assert len(certs) == 3
    assert len(keys) == 3
    for line in certs + keys:
        assert "critical" in line.split()
    sha1 = [line for line in certs if "rsa2048-sha1-cert.pem" in line]
    assert len(sha1) == 1 and "sha1" in sha1[0].split()


def test_certs_uses_config_cert_paths_when_no_path_given(runner, tmp_path):
    config = _write_config(tmp_path, "cert_paths: [{}]\n".format(FIXTURES))

    result = runner.invoke(cli.main, ["certs", "-c", config])

    assert result.exit_code == 0, result.output
    assert len([ln for ln in result.output.splitlines() if ln.startswith("certificate ")]) == 3


def test_certs_fail_on_critical_exits_1(runner):
    result = runner.invoke(cli.main, ["certs", "--fail-on", "critical", FIXTURES])

    assert result.exit_code == 1


def test_certs_rejects_unknown_fail_on_level(runner):
    result = runner.invoke(cli.main, ["certs", "--fail-on", "severe", FIXTURES])

    assert result.exit_code == 2


def _scan_with_fake_handshake(runner, tmp_path, args):
    config = _write_config(
        tmp_path,
        "targets: [192.0.2.10]\nports: [443]\nenumerate_ciphers: true\n"
        "output_format: json\n")
    fake = FakeSSLSocket(cipher=("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128))
    out = tmp_path / "out"
    with fake_connection(fake), \
            mock.patch.object(CryptoScanner, "enumerate_ciphers",
                              return_value=["AES128-SHA"]) as enum, \
            mock.patch.object(CryptoScanner, "supports_tls13", return_value=False):
        result = runner.invoke(cli.main, ["scan", "-c", config, "-o", str(out)] + args)
    return result, enum, out


def test_scan_no_enum_leaves_offered_suites_empty(runner, tmp_path):
    result, enum, out = _scan_with_fake_handshake(runner, tmp_path, ["--no-enum"])

    assert result.exit_code == 0, result.output
    enum.assert_not_called()
    files = glob.glob(str(out / "scan-*.json"))
    assert len(files) == 1
    with open(files[0]) as handle:
        report = json.load(handle)
    assert report["results"][0]["offered_suites"] == []


def test_scan_without_no_enum_follows_config(runner, tmp_path):
    result, enum, out = _scan_with_fake_handshake(runner, tmp_path, [])

    assert result.exit_code == 0, result.output
    enum.assert_called_once_with("192.0.2.10", 443)
    with open(glob.glob(str(out / "scan-*.json"))[0]) as handle:
        report = json.load(handle)
    assert report["results"][0]["offered_suites"] == ["AES128-SHA"]


def test_scan_fail_on_high_exits_1_for_critical_findings(runner, tmp_path):
    result, _enum, _out = _scan_with_fake_handshake(runner, tmp_path,
                                                    ["--no-enum", "--fail-on", "high"])

    assert result.exit_code == 1


def test_fail_on_threshold_ignores_findings_that_need_no_change():
    assessments = [{"target": "a", "findings": [
        {"threat_class": "none", "threat_level": "low"}]}]

    assert not cli.threshold_reached(assessments, "low")
    assessments[0]["findings"].append({"threat_class": "grover", "threat_level": "low"})
    assert cli.threshold_reached(assessments, "low")
    assert not cli.threshold_reached(assessments, "medium")
    assert not cli.threshold_reached(assessments, None)


def test_roadmap_from_json_skips_scanning(runner, tmp_path):
    report = {
        "scan_date": "2020-06-30T00:00:00", "total_endpoints": 1, "vulnerable_endpoints": 1,
        "risk_percentage": 100.0, "unreachable": 0,
        "results": [{"host": "h", "port": 443, "protocol": "TLSv1.2",
                     "negotiated_suite": "ECDHE-RSA-AES256-GCM-SHA384", "vulnerabilities": []}],
        "assessments": [{"target": "h:443", "risk_score": 50, "findings": [
            {"target": "h:443", "component": "key_exchange", "algorithm": "ECDH",
             "threat_class": "shor", "threat_level": "critical",
             "recommendation": "Kyber"}]}],
        "summary": {"critical": 1, "quantum_safe": 0},
    }
    source = tmp_path / "scan.json"
    source.write_text(json.dumps(report))
    config = _write_config(tmp_path, "bench_iterations: 1\noutput_format: markdown\n")
    out = tmp_path / "out"

    with mock.patch.object(CryptoScanner, "scan_all",
                           side_effect=AssertionError("must not scan")):
        result = runner.invoke(cli.main, ["roadmap", "-c", config, "--from-json", str(source),
                                          "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert glob.glob(str(out / "scan-*.json")) == []
    markdown = glob.glob(str(out / "roadmap-*.md"))
    assert len(markdown) == 1
    with open(markdown[0]) as handle:
        text = handle.read()
    assert "key\\_exchange ECDH -> Kyber768" in text
    assert "## Benchmark" in text


# --- fail closed: unassessed endpoints, unreadable files, malformed reports -----------------

def _scan_no_tls(runner, tmp_path, args):
    config = _write_config(tmp_path, "targets: [192.0.2.10]\nports: [443]\n"
                                     "enumerate_ciphers: false\noutput_format: json\n")
    with mock.patch("socket.create_connection", return_value=FakeRawSocket()), \
            mock.patch.object(ssl.SSLContext, "wrap_socket", autospec=True,
                              side_effect=ssl.SSLError(1, "wrong version number")):
        return runner.invoke(cli.main, ["scan", "-c", config, "-o", str(tmp_path / "o")]
                             + args)


def test_fail_on_exits_1_when_an_endpoint_could_not_be_assessed(runner, tmp_path):
    result = _scan_no_tls(runner, tmp_path, ["--fail-on", "critical"])

    assert result.exit_code == 1, result.output
    assert "not assessed" in result.stderr


def test_unassessed_endpoints_are_reported_without_fail_on(runner, tmp_path):
    result = _scan_no_tls(runner, tmp_path, [])

    assert result.exit_code == 0, result.output
    assert "1 endpoint(s) accepted TCP but completed no TLS 1.2+ handshake" in result.stderr


def test_fail_on_exits_1_when_every_endpoint_is_unreachable(runner, tmp_path):
    config = _write_config(tmp_path, "targets: [192.0.2.10]\nports: [443]\n")
    with mock.patch("socket.create_connection",
                    side_effect=ConnectionRefusedError(111, "Connection refused")):
        result = runner.invoke(cli.main, ["scan", "-c", config, "-o", str(tmp_path / "o"),
                                          "--fail-on", "low"])

    assert result.exit_code == 1
    assert "nothing was assessed" in result.stderr


def _invoke_within(limit, runner, args):
    """runner.invoke in a thread so a blocking read fails the test instead of hanging it."""
    box = {}
    worker = threading.Thread(target=lambda: box.setdefault("r", runner.invoke(cli.main, args)),
                              daemon=True)
    worker.start()
    worker.join(limit)
    assert not worker.is_alive(), "command blocked"
    return box["r"]


def test_certs_fail_on_exits_1_for_unreadable_files(runner, tmp_path):
    os.mkfifo(str(tmp_path / "pipe.pem"))

    result = _invoke_within(10, runner, ["certs", "--fail-on", "critical", str(tmp_path)])

    assert result.exit_code == 1
    assert "pipe.pem" in result.stderr


def test_certs_explicit_unreadable_file_is_an_error_not_a_traceback(runner, tmp_path):
    fifo = str(tmp_path / "pipe.pem")
    os.mkfifo(fifo)

    result = _invoke_within(10, runner, ["certs", fifo])

    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "regular file" in result.stderr


@pytest.mark.parametrize("content", ["{broken", '{"no_results": []}'])
def test_roadmap_from_malformed_json_exits_2(runner, tmp_path, content):
    source = tmp_path / "scan.json"
    source.write_text(content)
    config = _write_config(tmp_path, "bench_iterations: 1\n")

    result = runner.invoke(cli.main, ["roadmap", "-c", config, "--from-json", str(source),
                                      "-o", str(tmp_path / "o")])

    assert result.exit_code == 2
    assert isinstance(result.exception, SystemExit)
    assert "scan report" in result.stderr


def test_roadmap_from_json_recomputes_assessments_instead_of_trusting_them(runner, tmp_path):
    report = {"results": [{"host": "h", "port": 443, "status": "ok",
                           "negotiated_suite": "AES128-SHA", "certificate": None}],
              "assessments": []}
    source = tmp_path / "scan.json"
    source.write_text(json.dumps(report))
    config = _write_config(tmp_path, "bench_iterations: 1\noutput_format: markdown\n")

    with mock.patch.object(cli, "_bench", return_value=[]):
        result = runner.invoke(cli.main, ["roadmap", "-c", config, "--from-json", str(source),
                                          "-o", str(tmp_path / "o"), "--fail-on", "critical"])

    assert result.exit_code == 1, result.output
    assert "migration phase(s)" in result.output
    assert "0 migration phase(s)" not in result.output


# --- console output never carries escape sequences from scanned names ------------------------

def test_certs_output_strips_terminal_escapes_from_file_names(runner, tmp_path):
    import shutil

    shutil.copy(os.path.join(FIXTURES, "rsa2048-sha256-cert.pem"),
                str(tmp_path / "\x1b[2J\x1b]0;owned\x07evil\u202e.pem"))
    os.mkfifo(str(tmp_path / "\x1b[31mpipe.pem"))

    result = _invoke_within(10, runner, ["certs", str(tmp_path)])

    assert result.exit_code == 0, result.output
    for stream in (result.output, result.stderr):
        assert "\x1b" not in stream and "\x07" not in stream and "\u202e" not in stream
    assert "evil.pem" in result.output
    assert "pipe.pem" in result.stderr


def test_scan_output_strips_terminal_escapes_from_report_values(runner, tmp_path):
    report = {"results": [{"host": "h\x1b[2J", "port": 443, "status": "ok",
                           "protocol": "TLSv1.2\x1b]0;x\x07",
                           "negotiated_suite": "AES128-SHA\r\nfake line", "certificate": None}],
              "unassessed": [{"host": "\x1b[31mold", "port": 443, "status": "no_tls"}]}
    source = tmp_path / "scan\x1b[1m.json"
    source.write_text(json.dumps(report))
    config = _write_config(tmp_path, "bench_iterations: 1\noutput_format: json\n")

    with mock.patch.object(cli, "_bench", return_value=[]):
        result = runner.invoke(cli.main, ["roadmap", "-c", config, "--from-json", str(source),
                                          "-o", str(tmp_path / "o")])

    assert result.exit_code == 0, result.output
    for stream in (result.output, result.stderr):
        assert "\x1b" not in stream and "\x07" not in stream
    assert "AES128-SHA fake line" in result.output
    assert "\r" not in result.output


def test_unusable_report_path_is_printed_without_escapes(runner, tmp_path):
    source = tmp_path / "bad\x1b[2J.json"
    source.write_text("{broken")
    config = _write_config(tmp_path, "bench_iterations: 1\n")

    result = runner.invoke(cli.main, ["roadmap", "-c", config, "--from-json", str(source)])

    assert result.exit_code == 2
    assert "\x1b" not in result.stderr
    assert "bad.json is not a usable scan report" in result.stderr
