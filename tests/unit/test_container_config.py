"""Compose and Dockerfile settings that keep the stack local and its packages verified."""

import os
import re
import sys

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import check_ports  # noqa: E402


def _compose(services):
    return {"services": services}


def test_shipped_compose_file_publishes_nothing_off_loopback():
    with open(os.path.join(REPO_ROOT, "docker-compose.yml")) as handle:
        compose = yaml.safe_load(handle)

    assert check_ports.violations(compose) == []


@pytest.mark.parametrize("ports", [
    ["22400:443"],
    ["0.0.0.0:22400:443"],
    ["443"],
    [443],
    ["[::]:22400:443"],
    [{"target": 443, "published": 22400}],
    [{"target": 443, "published": "22400", "host_ip": "0.0.0.0"}],
])
def test_ports_bound_to_all_interfaces_are_reported(ports):
    problems = check_ports.violations(_compose({"web": {"ports": ports}}))

    assert len(problems) == 1
    assert problems[0].startswith("web:")


@pytest.mark.parametrize("ports", [
    ["127.0.0.1:22400:443"],
    ["127.0.0.1:22400:443/tcp"],
    [{"target": 443, "published": 22400, "host_ip": "127.0.0.1"}],
])
def test_loopback_ports_pass(ports):
    assert check_ports.violations(_compose({"web": {"ports": ports}})) == []


def test_host_network_mode_is_reported():
    problems = check_ports.violations(_compose({"web": {"network_mode": "host"}}))

    assert problems == ["web: network_mode host exposes every listening port"]


def test_check_ports_main_reads_compose_config_from_stdin(monkeypatch, capsys):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("services:\n  web:\n    ports: ['80:80']\n"))

    assert check_ports.main(["-"]) == 1
    assert "web:" in capsys.readouterr().out


BYPASSES = re.compile(r"allow-unauthenticated|force-yes|trusted=yes|AllowUnauthenticated|"
                      r"no-check-gpg|AllowInsecureRepositories|AllowDowngradeToInsecure",
                      re.IGNORECASE)


def test_dockerfile_apt_sources_use_https_and_keep_signature_checks():
    with open(os.path.join(REPO_ROOT, "Dockerfile")) as handle:
        dockerfile = handle.read()

    assert "http://" not in dockerfile
    assert "https://snapshot.debian.org/archive/debian/" in dockerfile
    assert not BYPASSES.search(dockerfile)
