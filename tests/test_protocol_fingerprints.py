"""Fixture-only protocol tests; no public network targets or credentials."""
from __future__ import annotations

import socket
import threading

import pytest

from worker.scanners.fingerprints import fingerprint_banner
from worker.scanners import tcp


@pytest.mark.parametrize("port,banner,service,product", [
    (22222, b"SSH-2.0-OpenSSH_9.5\r\n", "ssh", "OpenSSH"),
    (21, b"220 ProFTPD 1.3.8 Server\r\n", "ftp", ""),
    (25, b"220 mx.example.test ESMTP Postfix\r\n", "smtp", ""),
    (143, b"* OK [CAPABILITY IMAP4rev1] Ready\r\n", "imap", ""),
    (110, b"+OK POP3 server ready\r\n", "pop3", ""),
    (6379, b"-NOAUTH Authentication required.\r\n", "redis", "Redis"),
    (48888, b"HTTP/1.1 200 OK\r\nServer: Example\r\n\r\n", "http", ""),
    (9999, b"220 unidentified server\r\n", "tcp", ""),
])
def test_banner_fingerprints(port, banner, service, product):
    result = fingerprint_banner(port, banner)
    assert result.service == service
    assert result.product == product


def test_mysql_binary_greeting():
    payload = b"\x0a8.0.37\x00" + b"\x01" * 15
    greeting = len(payload).to_bytes(3, "little") + b"\x00" + payload
    result = fingerprint_banner(3306, greeting)
    assert result.service == "mysql" and result.product == "MySQL 8.0.37"


def test_mariadb_binary_greeting():
    payload = b"\x0a5.5.5-10.11.3-MariaDB\x00" + b"\x01" * 15
    greeting = len(payload).to_bytes(3, "little") + b"\x00" + payload
    result = fingerprint_banner(3306, greeting)
    assert result.service == "mysql" and result.product.startswith("MariaDB ")


def _loopback_exchange(response: bytes, probe: bytes | None = None):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    errors = []

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(2)
                if probe is not None:
                    assert conn.recv(2048) == probe
                conn.sendall(response)
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread, errors


def test_redis_ping_is_read_only():
    port, thread, errors = _loopback_exchange(b"+PONG\r\n", b"*1\r\n$4\r\nPING\r\n")
    tcp.REDIS_PORTS.add(port)
    try:
        result = tcp.scan_endpoint("127.0.0.1", port, 1, 1)
    finally:
        tcp.REDIS_PORTS.discard(port)
    thread.join(timeout=3)
    assert not errors
    assert result and result["service"] == "redis" and result["product"] == "Redis"
    assert result["banner"] == "+PONG\r\n"


def test_postgresql_sslrequest_is_read_only():
    port, thread, errors = _loopback_exchange(b"N", b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
    tcp.POSTGRES_PORTS.add(port)
    try:
        result = tcp.scan_endpoint("127.0.0.1", port, 1, 1)
    finally:
        tcp.POSTGRES_PORTS.discard(port)
    thread.join(timeout=3)
    assert not errors
    assert result and result["service"] == "postgresql"


def test_unknown_port_does_not_send_probe():
    port, thread, errors = _loopback_exchange(b"SSH-2.0-OpenSSH_fixture\r\n")
    result = tcp.scan_endpoint("127.0.0.1", port, 1, 1)
    thread.join(timeout=3)
    assert not errors
    assert result and result["service"] == "ssh"
