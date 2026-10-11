"""`python -m quantum_tool` against the compose nginx TLS targets."""

import glob
import json
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG = os.path.join("config", "scan_config.docker.yml")


def _run(*args):
    return subprocess.run([sys.executable, "-m", "quantum_tool"] + list(args),
                          cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, timeout=600)


def test_roadmap_writes_json_and_markdown(tmp_path):
    result = _run("roadmap", "-c", CONFIG, "-o", str(tmp_path))

    assert result.returncode == 0, result.stderr
    reports = glob.glob(str(tmp_path / "scan-*.json"))
    roadmaps = glob.glob(str(tmp_path / "roadmap-*.md"))
    assert len(reports) == 1
    assert len(roadmaps) == 1

    with open(reports[0]) as handle:
        report = json.load(handle)
    assert report["total_endpoints"] == 3
    assert report["roadmap"]["phases"]

    with open(roadmaps[0]) as handle:
        text = handle.read()
    assert "-> Kyber768" in text
    assert "-> DILITHIUM_3" in text
    assert "| tls-legacy:443 |" in text
    assert "## Benchmark" in text


def test_scan_fail_on_critical_exits_1(tmp_path):
    result = _run("scan", "-c", CONFIG, "-o", str(tmp_path), "--fail-on", "critical")

    assert result.returncode == 1, result.stderr
    assert glob.glob(str(tmp_path / "scan-*.json"))
