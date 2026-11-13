"""Bounded TCP-connect scanner with protocol-aware service and banner collection."""
from __future__ import annotations

import hashlib
import socket
import ssl
import struct
import time
from typing import Any

from .fingerprints import (
    HTTP_PORTS, HTTPS_PORTS, TLS_PORTS, REDIS_PORTS, POSTGRES_PORTS,
    fingerprint_banner,
)


def _headers(data: bytes) -> dict[str, str]:
    lines = data.decode("iso-8859-1", "replace").split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return {}
    result = {"status": lines[0][:200]}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip().lower()] = value.strip()[:1000]
    return result


def scan_endpoint(ip: str, port: int, connect_timeout: float = 3, banner_timeout: float = 3) -> dict[str, Any] | None:
    """Return an observation for an open TCP port, never for a refused connection.

    Protocol probes are restricted to standard read-only handshakes: HTTP HEAD,
    Redis PING and PostgreSQL SSLRequest. Other ports receive no application data.
    """
    started = time.monotonic()
    try:
        sock = socket.create_connection((ip, port), timeout=connect_timeout)
    except (OSError, TimeoutError):
        return None
    latency = round((time.monotonic() - started) * 1000, 2)
    sock.settimeout(banner_timeout)
    banner = b""
    http: dict[str, str] = {}
    tls: dict[str, str] = {}
    service = "tcp"
    product = ""
    ssh_id = ""
    tls_connected = False

    try:
        if port in HTTPS_PORTS or port in TLS_PORTS:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=ip)
            tls_connected = True
            certificate = sock.getpeercert(binary_form=True) or b""
            tls = {
                "version": sock.version() or "",
                "cipher": (sock.cipher() or ("",))[0],
                "certificate_sha256": hashlib.sha256(certificate).hexdigest() if certificate else "",
            }

        if port in HTTP_PORTS or port in HTTPS_PORTS:
            sock.sendall(
                b"HEAD / HTTP/1.0\r\nHost: " + ip.encode("ascii") +
                b"\r\nUser-Agent: ScanLattice/0.5\r\nConnection: close\r\n\r\n"
            )
            banner = sock.recv(8192)
            http = _headers(banner)
        elif port in REDIS_PORTS:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            banner = sock.recv(8192)
        elif port in POSTGRES_PORTS:
            sock.sendall(struct.pack("!II", 8, 80877103))
            banner = sock.recv(1)
        else:
            banner = sock.recv(8192)

        fingerprint = fingerprint_banner(port, banner)
        service, product, ssh_id = fingerprint
        if http:
            service = "https" if tls_connected else "http"
            product = http.get("server", "")
        elif tls_connected and service == "tcp":
            service = "tls"
    except (OSError, ssl.SSLError, ValueError):
        # The TCP port was open even when a protocol negotiation did not finish.
        pass
    finally:
        sock.close()

    return {
        "ip": ip, "port": port, "proto": "tcp",
        "service": service, "product": product[:160],
        "banner": banner.decode("utf-8", "replace")[:8192],
        "http": http, "tls": tls, "ssh_id": ssh_id,
        "latency_ms": latency,
    }
