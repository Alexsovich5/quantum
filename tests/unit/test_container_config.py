"""Compose and Dockerfile settings that keep the stack local, least-privileged and verified."""

import glob
import os
import re
import sys

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import check_compose_security  # noqa: E402
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


def _apt_files():
    """Every Dockerfile and apt configuration file in the repository."""
    found = []
    for path in glob.glob(os.path.join(REPO_ROOT, "**", "*"), recursive=True):
        name = os.path.basename(path)
        if os.path.isfile(path) and (name.startswith("Dockerfile") or name.endswith(".list")
                                     or "apt" in path.split(os.sep)):
            found.append(path)
    return found


def test_every_dockerfile_and_apt_config_uses_https_and_keeps_signature_checks():
    files = _apt_files()

    assert os.path.join(REPO_ROOT, "Dockerfile") in files
    for path in files:
        with open(path) as handle:
            text = handle.read()
        assert "http://" not in text, path
        assert not BYPASSES.search(text), path
    with open(os.path.join(REPO_ROOT, "Dockerfile")) as handle:
        assert "https://snapshot.debian.org/archive/debian/" in handle.read()


# --- least privilege (check_compose_security) -------------------------------------------------

def _shipped_compose():
    with open(os.path.join(REPO_ROOT, "docker-compose.yml")) as handle:
        return yaml.safe_load(handle)


HARDENED = {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}


def _service(**extra):
    service = dict(HARDENED)
    service.update(extra)
    return {"services": {"svc": service}}


def test_shipped_compose_file_is_least_privileged():
    assert check_compose_security.violations(_shipped_compose()) == []


def test_shipped_compose_hardens_every_service():
    services = _shipped_compose()["services"]

    for name, service in services.items():
        assert service.get("read_only") is True, name
        assert "ALL" in service.get("cap_drop", []), name
        allowed = {"CHOWN", "SETUID", "SETGID", "NET_BIND_SERVICE"}
        assert set(service.get("cap_add") or []) <= allowed, name
    assert "user" in services["app"]
    assert not services["app"].get("cap_add")


def test_shipped_compose_networks_are_internal_and_in_the_lane():
    networks = _shipped_compose()["networks"]

    assert networks["default"]["internal"] is True
    assert networks["default"]["ipam"]["config"] == [{"subnet": "172.74.0.0/24"}]


def test_a_hardened_service_passes():
    assert check_compose_security.violations(_service()) == []


@pytest.mark.parametrize("override", [
    {"privileged": True},
    {"network_mode": "host"},
    {"pid": "host"},
    {"ipc": "host"},
    {"userns_mode": "host"},
    {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]},
    {"volumes": [{"type": "bind", "source": "/var/run/docker.sock", "target": "/sock"}]},
    {"volumes": ["~/.aws:/root/.aws:ro"]},
    {"volumes": ["${HOME}/.kube:/kube"]},
    {"volumes": ["/home/someone:/data"]},
    {"security_opt": []},
    {"security_opt": ["no-new-privileges:false"]},
    {"cap_drop": []},
    {"cap_add": ["SYS_ADMIN"]},
    {"cap_add": ["ALL"]},
    {"environment": {"DB_PASSWORD": "stub-admin"}},
    {"environment": ["VAULT_TOKEN=stub-root"]},
    {"environment": {"API_KEY": "stub-key"}},
    {"command": ["serve", "--password=stub-pw"]},
    {"command": "server -token stub-token"},
    {"entrypoint": ["sh", "-c", "login --secret stub-s"]},
    {"healthcheck": {"test": ["CMD", "curl", "-u", "admin:stub-pw", "http://x"]}},
    {"healthcheck": {"test": "wget --password stub-pw http://x"}},
    {"build": {"context": ".", "args": {"ADMIN_PASSWORD": "stub-pw"}}},
])
def test_each_privilege_or_credential_problem_is_reported(override):
    problems = check_compose_security.violations(_service(**override))

    assert len(problems) == 1, problems
    assert problems[0].startswith("svc:")


def test_secret_file_references_are_allowed():
    compose = _service(environment={"DB_PASSWORD_FILE": "/run/secrets/db_password"},
                       secrets=["db_password"])

    assert check_compose_security.violations(compose) == []


def test_check_compose_security_main_reads_stdin(monkeypatch, capsys):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("services:\n  web:\n    privileged: true\n"))

    assert check_compose_security.main(["-"]) == 1
    out = capsys.readouterr().out
    assert "web: privileged" in out


# --- committed files hold no real-looking secrets ---------------------------------------------

SKIP_DIRS = {".git", "reports", "__pycache__", ".pytest_cache"}
TEST_KEY_DIR = os.path.join("tests", "fixtures", "tls")
SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)\b(?:password|passwd|secret|token|api_?key)\s*[:=]\s*[\"']?"
               r"(?!stub-|lab-|None\b|\{|\$|\))([A-Za-z0-9/+_.\-]{6,})(?![A-Za-z0-9/+_.\-(])"),
    re.compile(r"(?i)[a-z]+://[^/\s:@]+:[^/\s@]+@"),
]
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def _committed_text_files():
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(root, name)
            try:
                with open(path, encoding="utf-8") as handle:
                    yield os.path.relpath(path, REPO_ROOT), handle.read()
            except (UnicodeDecodeError, OSError):
                continue


def test_committed_files_contain_no_real_looking_secrets():
    problems = []
    for rel, text in _committed_text_files():
        if PRIVATE_KEY.search(text) and os.path.dirname(rel) != TEST_KEY_DIR:
            problems.append("{}: private key outside {}".format(rel, TEST_KEY_DIR))
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                problems.append("{}: {}".format(rel, match.group(0)[:40]))

    assert problems == []


def test_secret_scan_patterns_catch_real_looking_values():
    # built at run time so this file does not trip its own scan
    samples = ["AKIA" + "ABCDEFGHIJKLMNOP", "pass" + "word = 'hunter2hunter2'",
               "TOK" + "EN: abcdef123456", "https://user" + ":pass@example.org/"]
    for sample in samples:
        assert any(p.search(sample) for p in SECRET_PATTERNS), sample
    for sample in ["password=None", "token: stub-token", "password: lab-pw"]:
        assert not any(p.search(sample) for p in SECRET_PATTERNS), sample
