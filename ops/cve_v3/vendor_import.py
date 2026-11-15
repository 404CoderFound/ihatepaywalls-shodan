#!/usr/bin/env python3
"""Import recent Ubuntu OVAL exports from an SSH-only inbox on Debian.

Ignores symlinks and unsafe JSON. The inbox is not publicly served and the
source is local host-supplied evidence (not a remotely verified scan).
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from merge_report import valid_oval_file

INBOX = Path("/home/ihatepaywalls/scanlattice-vendor-inbox")
STORE = Path("/var/lib/scanlattice-cve/vendor")

def import_one(path):
    if not path.is_file() or path.is_symlink():
        return False
    fd=os.open(path,os.O_RDONLY | getattr(os,"O_NOFOLLOW",0))
    try:
        if os.fstat(fd).st_size>20_000_000:
            raise RuntimeError("Evidence too large")
        raw=os.read(fd,20_000_001)
    finally:
        os.close(fd)
    item=json.loads(raw)
    if not valid_oval_file(item):
        raise RuntimeError("Not fresh canonical USN OVAL local evidence")
    ip=str(ipaddress.ip_address(item["ip"]))
    statuses=item["cve_status"]
    if len(statuses)>200_000:
        raise RuntimeError("Too many CVEs in evidence")
    for cve,status in statuses.items():
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}",cve):
            raise RuntimeError("Invalid CVE identifier")
        if status not in ("vendor_affected","vendor_not_affected","vendor_unknown"):
            raise RuntimeError("Invalid vendor status")
    STORE.mkdir(parents=True,exist_ok=True)
    name=ip.replace(":","_")+".json"
    target=STORE/name
    if target.exists():
        previous=json.loads(target.read_text())
        if previous.get("generated_at","") >= item["generated_at"]:
            return False
    with tempfile.NamedTemporaryFile(mode="wb",dir=STORE,delete=False) as f:
        temp=Path(f.name)
        f.write(raw)
        f.flush()
        os.fchmod(f.fileno(),0o600)
        os.fsync(f.fileno())
    os.replace(temp,target)
    return True

def main():
    if not INBOX.is_dir():
        print("Vendor inbox absent; continuing with remote-only potential matches.")
        return
    imported=0
    for path in sorted(INBOX.glob("*.json")):
        try:
            if import_one(path):
                imported+=1
                print("IMPORTED OVAL",path.name,flush=True)
            path.unlink(missing_ok=True)
        except Exception as exc:
            print("INVALID VENDOR EVIDENCE",path.name,str(exc),file=sys.stderr)
    print("Imported new Ubuntu OVAL reports:",imported)

if __name__=="__main__":main()
