#!/usr/bin/env python3
"""Audit AWS completed per-host jobs against ScanLattice web ingestion.

No new scans are sent. Reads at most 20 recently completed jobs and checks
that website host.last_scan_at is newer than the job's creation.
"""
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import urllib.request
import urllib.parse

def stamp(v):
    try:
        d=datetime.fromisoformat(str(v).replace("Z","+00:00"))
        return d.astimezone(timezone.utc) if d.tzinfo else None
    except (TypeError,ValueError):
        return None

def scanner_jobs():
    c=json.loads(Path("/etc/scanlattice-v3/config.json").read_text())
    directory=Path(c.get("state_dir","/var/lib/scanlattice-v3"))/"jobs"
    if directory.is_dir():
        result=[]
        for i,path in enumerate(directory.glob("*.json")):
            if i>=100000:raise RuntimeError("Job directory unexpectedly large")
            if path.stat().st_size>2_000_000:continue
            result.append(json.loads(path.read_text()))
        return result
    p=subprocess.run(["/usr/local/bin/scanlattice-v3","jobs"],
                     check=True,capture_output=True,text=True,timeout=50)
    return json.loads(p.stdout).get("jobs",[])

def website(ip):
    url="https://scanlattice.plezi.eu/api/hosts/"+urllib.parse.quote(ip,safe="")
    req=urllib.request.Request(url,headers={"Accept":"application/json",
                                            "User-Agent":"ScanLattice-upload-audit/1.0"})
    with urllib.request.urlopen(req,timeout=20) as response:
        return json.loads(response.read(1024*1024))

def audit(jobs, read=website):
    completed=[]
    for item in jobs:
        if item.get("status")!="completed":continue
        request=item.get("request") or {}
        if request.get("target_type")!="ip":continue
        try:
            ip=str(ipaddress.ip_address(request["target"]))
        except (ValueError,KeyError):
            continue
        created=stamp(item.get("created_at"))
        if not created:continue
        if datetime.now(timezone.utc)-created>timedelta(days=2):
            continue
        completed.append((created,ip))
    completed.sort(reverse=True)
    failures=[]
    checked=0
    for created,ip in completed[:20]:
        checked+=1
        try:
            detail=read(ip)
            last=stamp((detail.get("host") or {}).get("last_scan_at"))
            if not last or last < created-timedelta(minutes=5):
                failures.append((ip,"No recent active scan timestamp on website"))
        except Exception as exc:
            failures.append((ip,str(exc)))
    return checked,failures

def main():
    checked,failures=audit(scanner_jobs())
    print("Recent completed AWS jobs cross-checked:",checked)
    print("Website upload mismatches:",len(failures))
    for ip,error in failures[:20]:
        print("  MISSING",ip,error)
    if failures:
        sys.exit(2)
    if checked==0:
        print("No completed jobs in the last two days; cannot yet validate ingestion.")

if __name__=="__main__":
    main()
