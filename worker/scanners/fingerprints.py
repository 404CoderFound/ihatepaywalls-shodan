"""Conservative, non-invasive service identification for TCP banner observations.

The scanner does not authenticate, enumerate resources or attempt exploits.
Port hints are only used where a well-defined, read-only protocol greeting exists.
"""
from __future__ import annotations

from typing import NamedTuple

HTTP_PORTS = {80, 8000, 8080, 8888}
HTTPS_PORTS = {443, 8443, 9443}
TLS_PORTS = {465, 636, 853, 993, 995, 6380}
SSH_PORTS = {22, 2222}
FTP_PORTS = {21, 2121}
SMTP_PORTS = {25, 465, 587, 2525}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}
REDIS_PORTS = {6379, 6380}
POSTGRES_PORTS = {5432}


class Fingerprint(NamedTuple):
    service: str
    product: str = ""
    ssh_id: str = ""


def fingerprint_banner(port: int, banner: bytes) -> Fingerprint:
    """Identify only clear protocol signatures, including on unexpected ports."""
    if not banner:
        return Fingerprint("tcp")
    head = banner[:8192]
    upper = head.upper()

    if head.startswith(b"HTTP/"):
        return Fingerprint("http")
    if head.startswith(b"SSH-"):
        identity = head.decode("utf-8", "replace").splitlines()[0][:500]
        return Fingerprint("ssh", "OpenSSH" if b"OPENSSH" in upper else "SSH", identity)

    # MySQL/MariaDB sends a length-prefixed binary greeting; no request is needed.
    if len(head) >= 7 and head[3] == 0 and head[4] == 10:
        packet_size = int.from_bytes(head[:3], "little")
        version = head[5:].split(b"\x00", 1)[0]
        if 2 <= packet_size <= 65535 and 1 <= len(version) <= 100 and all(32 <= b <= 126 for b in version):
            vendor = "MariaDB" if b"mariadb" in version.lower() else "MySQL"
            return Fingerprint("mysql", f"{vendor} {version.decode('ascii')}")

    if head[:1] in {b"N", b"S"} and port in POSTGRES_PORTS and len(head) == 1:
        return Fingerprint("postgresql", "PostgreSQL")

    if head.startswith(b"+PONG") or (
        port in REDIS_PORTS and head.startswith((b"-NOAUTH", b"-ERR", b"+OK"))
    ):
        return Fingerprint("redis", "Redis")
    if head.startswith(b"* OK") and (port in IMAP_PORTS or b"IMAP" in upper):
        return Fingerprint("imap")
    if head.startswith(b"+OK") and (port in POP3_PORTS or b"POP3" in upper):
        return Fingerprint("pop3")
    if head.startswith(b"220"):
        if port in FTP_PORTS or b"FTP" in upper:
            return Fingerprint("ftp")
        if port in SMTP_PORTS or b"SMTP" in upper:
            return Fingerprint("smtp")

    return Fingerprint("tcp")
