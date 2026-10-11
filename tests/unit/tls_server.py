"""Threaded TLS 1.2 server on 127.0.0.1 for exercising the cipher enumeration.

Every accepted connection gets one handshake attempt; failed handshakes are
swallowed so the server keeps serving until it is stopped.
"""

import os
import socket
import ssl
import threading

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), os.pardir, "fixtures", "tls")
RSA_CERT = os.path.join(FIXTURES, "rsa2048-sha256-cert.pem")
RSA_KEY = os.path.join(FIXTURES, "rsa2048-sha256-key.pem")


class LocalTLSServer:
    """Accept loop in a daemon thread serving a restricted TLS 1.2 cipher list."""

    def __init__(self, ciphers):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(RSA_CERT, RSA_KEY)
        self.context.maximum_version = ssl.TLSVersion.TLSv1_2
        self.context.set_ciphers(ciphers)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        self.host, self.port = self.listener.getsockname()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)
        self.listener.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self._handle(conn)

    def _handle(self, conn):
        conn.settimeout(5)
        try:
            with self.context.wrap_socket(conn, server_side=True) as tls:
                try:
                    tls.recv(1)
                except (ssl.SSLError, OSError):
                    pass
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()


@pytest.fixture
def tls_server():
    """Factory fixture: tls_server("CIPHERS") starts a server; all are stopped afterwards."""
    servers = []

    def start(ciphers):
        server = LocalTLSServer(ciphers).start()
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.stop()


class TricklingServer:
    """Answers every connection with a TLS record header announcing 16 KiB, then one byte
    every ``interval`` seconds, so a client relying on per-read timeouts never gives up."""

    HEADER = b"\x16\x03\x03\x40\x00"

    def __init__(self, interval=0.1):
        self.interval = interval
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        self.host, self.port = self.listener.getsockname()
        self._stop = threading.Event()
        self._threads = [threading.Thread(target=self._serve, daemon=True)]

    def start(self):
        self._threads[0].start()
        return self

    def stop(self):
        self._stop.set()
        for thread in list(self._threads):
            thread.join(timeout=5)
        self.listener.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self._trickle, args=(conn,), daemon=True)
            self._threads.append(worker)
            worker.start()

    def _trickle(self, conn):
        try:
            conn.sendall(self.HEADER)
            while not self._stop.wait(self.interval):
                conn.sendall(b"\x00")
        except OSError:
            pass
        finally:
            conn.close()


@pytest.fixture
def trickling_server():
    server = TricklingServer().start()
    yield server
    server.stop()
