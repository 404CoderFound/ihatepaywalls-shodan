from __future__ import annotations

import hashlib
import socket
import ssl
import time
from typing import Any

HTTP_PORTS={80,8080,8000,8888}; HTTPS_PORTS={443,8443,9443}; SSH_PORTS={22,2222}

def _headers(data:bytes)->dict[str,str]:
    lines=data.decode("iso-8859-1","replace").split("\r\n")
    result={"status":lines[0][:200]} if lines else {}
    for line in lines[1:]:
        if ":" in line:
            key,value=line.split(":",1);result[key.strip().lower()]=value.strip()[:1000]
    return result

def scan_endpoint(ip:str,port:int,connect_timeout:float=3,banner_timeout:float=3)->dict[str,Any]|None:
    started=time.monotonic()
    try:sock=socket.create_connection((ip,port),timeout=connect_timeout)
    except (OSError,TimeoutError):return None
    latency=round((time.monotonic()-started)*1000,2);sock.settimeout(banner_timeout)
    banner=b"";http={};tls={};service="tcp";product=""
    try:
        if port in HTTPS_PORTS:
            service="https";context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
            sock=context.wrap_socket(sock,server_hostname=ip);cert=sock.getpeercert(binary_form=True) or b""
            tls={"version":sock.version() or "","cipher":(sock.cipher() or ("",))[0],"certificate_sha256":hashlib.sha256(cert).hexdigest() if cert else ""}
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: "+ip.encode()+b"\r\nUser-Agent: ScanLattice/0.2\r\nConnection: close\r\n\r\n");banner=sock.recv(8192);http=_headers(banner);product=http.get("server","")
        elif port in HTTP_PORTS:
            service="http";sock.sendall(b"HEAD / HTTP/1.0\r\nHost: "+ip.encode()+b"\r\nUser-Agent: ScanLattice/0.2\r\nConnection: close\r\n\r\n");banner=sock.recv(8192);http=_headers(banner);product=http.get("server","")
        else:
            try:banner=sock.recv(8192)
            except socket.timeout:banner=b""
            if port in SSH_PORTS or banner.startswith(b"SSH-"):service="ssh";product="OpenSSH" if b"OpenSSH" in banner else "SSH"
    except (OSError,ssl.SSLError):pass
    finally:sock.close()
    text=banner.decode("utf-8","replace")[:8192]
    return {"ip":ip,"port":port,"proto":"tcp","service":service,"product":product[:160],"banner":text,"http":http,"tls":tls,"ssh_id":text.splitlines()[0][:500] if service=="ssh" and text else "","latency_ms":latency}
