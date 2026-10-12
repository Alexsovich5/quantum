"""Fail when a compose service has more privilege or credentials than it needs.

    docker-compose config | python scripts/check_compose_security.py -   # rendered config
    python scripts/check_compose_security.py docker-compose.yml          # or a compose file

Every service must drop all capabilities (cap_drop: [ALL], adding back only
what it needs) and set no-new-privileges. Refused: privileged mode, host
network/pid/ipc/user/uts namespaces, the Docker socket or host home, cloud and
kube credential directories as volumes, SYS_ADMIN or ALL in cap_add, and any
credential-like value in environment, build args, command, entrypoint or
healthcheck (use `secrets:` and a *_FILE variable instead). Exit 1 lists every
problem.
"""
import re
import sys

import yaml

HOST_NAMESPACES = ("network_mode", "pid", "ipc", "userns_mode", "uts")
FORBIDDEN_CAPS = {"ALL", "SYS_ADMIN"}
SECRET_NAME = re.compile(r"(?i)(passw(or)?d|secret|token|api_?key|private_?key|credential)")
SECRET_ARGUMENT = re.compile(
    r"(?i)(--?(passw(or)?d|pass|secret|token|api-?key)\b"
    r"|\b(passw(or)?d|secret|token|api_?key)="
    r"|\s-u\s+\S+:\S+|[a-z]+://[^/\s:@]+:[^/\s@]+@)")
# The Docker socket, a whole home directory, or a credential directory anywhere.
SENSITIVE_SOURCES = re.compile(
    r"(docker\.sock"
    r"|^(~|\$\{?HOME\}?|/root|/home/[^/]+|/Users/[^/]+)/?$"
    r"|(^|/)\.(aws|kube|ssh|docker|gnupg)(/|$))")


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _environment(value):
    """(name, value) pairs from the mapping or the list form of environment/args."""
    if isinstance(value, dict):
        return [(str(k), "" if v is None else str(v)) for k, v in value.items()]
    pairs = []
    for entry in _as_list(value):
        name, _, val = str(entry).partition("=")
        pairs.append((name, val))
    return pairs


def _volume_source(entry):
    if isinstance(entry, dict):
        return str(entry.get("source") or "")
    return str(entry).split(":", 1)[0]


def _no_new_privileges(options):
    for option in _as_list(options):
        text = str(option).replace("=", ":").replace(" ", "")
        if text in ("no-new-privileges", "no-new-privileges:true"):
            return True
    return False


def _command_text(value):
    if isinstance(value, dict):  # healthcheck
        value = value.get("test")
    return " ".join(str(part) for part in _as_list(value))


def service_violations(name, service):
    """Problems of one service definition."""
    service = service or {}
    problems = []

    def report(message):
        problems.append("{}: {}".format(name, message))

    if service.get("privileged"):
        report("privileged mode")
    for key in HOST_NAMESPACES:
        if str(service.get(key) or "") == "host":
            report("{} host shares the host namespace".format(key))
    for entry in _as_list(service.get("volumes")):
        source = _volume_source(entry)
        if SENSITIVE_SOURCES.search(source):
            report("volume {!r} exposes the Docker socket or host credentials".format(source))
    if not _no_new_privileges(service.get("security_opt")):
        report("security_opt lacks no-new-privileges:true")
    if "ALL" not in [str(c).upper() for c in _as_list(service.get("cap_drop"))]:
        report("cap_drop lacks ALL")
    added = {str(c).upper() for c in _as_list(service.get("cap_add"))}
    if added & FORBIDDEN_CAPS:
        report("cap_add grants {}".format(", ".join(sorted(added & FORBIDDEN_CAPS))))
    for var, value in _environment(service.get("environment")):
        if SECRET_NAME.search(var) and value and not var.upper().endswith("_FILE"):
            report("environment {} carries a credential; mount it with secrets:".format(var))
    build = service.get("build")
    if isinstance(build, dict):
        for arg, value in _environment(build.get("args")):
            if SECRET_NAME.search(arg) and value:
                report("build arg {} carries a credential".format(arg))
    for key in ("command", "entrypoint", "healthcheck"):
        if SECRET_ARGUMENT.search(" " + _command_text(service.get(key))):
            report("{} passes a credential on the command line".format(key))
    return problems


def violations(compose):
    """Return one message per least-privilege problem in a compose config."""
    problems = []
    for name, service in sorted(((compose or {}).get("services") or {}).items()):
        problems.extend(service_violations(name, service))
    return problems


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 2
    if argv[0] == "-":
        compose = yaml.safe_load(sys.stdin)
    else:
        with open(argv[0]) as handle:
            compose = yaml.safe_load(handle)
    problems = violations(compose)
    for problem in problems:
        print(problem)
    if problems:
        return 1
    print("compose services: least privilege, no credentials in config")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
