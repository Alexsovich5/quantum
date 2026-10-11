"""Test doubles for the TLS handshake performed by CryptoScanner.scan_host."""

import contextlib
import socket
import ssl
from unittest import mock


class FakeRawSocket:
    """Stands in for the TCP socket returned by socket.create_connection."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class FakeSSLSocket:
    """Returns canned handshake results instead of talking to a server."""

    def __init__(self, cipher=None, version="TLSv1.2", cert=b"\x30\x82\x01\x00"):
        self._cipher = cipher
        self._version = version
        self._cert = cert
        self.closed = False

    def cipher(self):
        return self._cipher

    def version(self):
        return self._version

    def getpeercert(self, binary_form=False):
        if not binary_form:
            raise AssertionError("scanner is expected to request the DER certificate")
        return self._cert

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


@contextlib.contextmanager
def fake_connection(ssl_socket):
    """Patch socket.create_connection and SSLContext.wrap_socket to yield ssl_socket.

    Yields a namespace with the two mocks so tests can inspect call arguments.
    """
    raw = FakeRawSocket()
    with mock.patch.object(socket, "create_connection", return_value=raw) as connect, \
            mock.patch.object(ssl.SSLContext, "wrap_socket",
                              autospec=True, return_value=ssl_socket) as wrap:
        yield mock.Mock(connect=connect, wrap=wrap, raw=raw)


@contextlib.contextmanager
def failing_connection(error):
    """Patch socket.create_connection so every connection attempt raises error."""
    with mock.patch.object(socket, "create_connection", side_effect=error) as connect:
        yield connect
