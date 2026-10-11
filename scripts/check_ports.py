"""Fail when a compose file publishes a port on anything but 127.0.0.1.

    docker-compose config | python scripts/check_ports.py -   # rendered config on stdin
    python scripts/check_ports.py docker-compose.yml          # or a compose file

Both the short ("127.0.0.1:22400:443") and the long (host_ip/published) port
syntax are checked, and network_mode "host" is refused. Exit 1 lists every
offending service.
"""
import sys

import yaml

LOOPBACK = "127.0.0.1"


def _short_syntax_host_ip(entry):
    """Host IP of a short-syntax entry; None when the port is published on all interfaces."""
    text = str(entry)
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host if rest.startswith(":") else None
    parts = text.split(":")
    return parts[0] if len(parts) == 3 else None


def _published(entry):
    if isinstance(entry, dict):
        return entry.get("host_ip")
    return _short_syntax_host_ip(entry)


def violations(compose):
    """Return one message per published port or network mode not bound to loopback."""
    problems = []
    for name, service in sorted(((compose or {}).get("services") or {}).items()):
        service = service or {}
        if service.get("network_mode") == "host":
            problems.append("{}: network_mode host exposes every listening port".format(name))
        for entry in service.get("ports") or []:
            if _published(entry) != LOOPBACK:
                problems.append("{}: port {!r} is not bound to {}".format(name, entry, LOOPBACK))
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
    print("compose ports: nothing published beyond {}".format(LOOPBACK))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
