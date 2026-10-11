"""Shared setup for tests that talk to the compose nginx TLS targets."""

import socket
import time

import pytest

TLS_TARGETS = [("tls-rsa", 443), ("tls-ecdsa", 443), ("tls-legacy", 443)]
WAIT_SECONDS = 30


def _port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session", autouse=True)
def tls_targets_ready():
    """Wait for every nginx target to accept TCP connections, or fail with the missing ones."""
    deadline = time.monotonic() + WAIT_SECONDS
    pending = list(TLS_TARGETS)
    while pending and time.monotonic() < deadline:
        pending = [(h, p) for h, p in pending if not _port_open(h, p)]
        if pending:
            time.sleep(0.5)
    if pending:
        pytest.fail("TLS targets not reachable after %d s: %s (is the compose stack up?)"
                    % (WAIT_SECONDS, ", ".join("%s:%d" % t for t in pending)))
