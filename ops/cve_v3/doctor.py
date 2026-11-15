#!/usr/bin/env python3
"""ScanLattice operational health checks for Debian control plane or AWS worker.

Read-only; writes structured health output and exits nonzero on critical errors.
Optional HTTPS webhook via SCANLATTICE_HEALTH_WEBHOOK environment variable.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request
import urllib.parse

def now():
    return datetime.now(timezone.utc)

def age_hours(value):
    if not value:return None
    try:
        d=datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if not d.tzinfo:return None
        return max(0,(now()-d).total_seconds()/3600)
    except (ValueError,TypeError):return None

def read_json(path):
    p=Path(path)
    return json.loads(p.read_text()) if p.is_file() else None

def active(name):
    return subprocess.run(["systemctl","is-active","--quiet",name],
                          check=False,stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode==0

def http_json(url):
    req=urllib.request.Request(url,headers={
        "Accept":"application/json","User-Agent":"ScanLattice-health/1.0"})
    with urllib.request.urlopen(req,timeout=15) as response:
        return json.loads(response.read(4*1024*1024))

def check_debian():
    alerts=[]
    for name in ("scanlattice-cve-v2-refresh.timer",
                 "scanlattice-cve-v2-assess.timer"):
        if not active(name):
            alerts.append(("critical",name+" is inactive"))
    if not Path("/var/lib/scanlattice-cve/applicability-v2.sqlite3").is_file():
        alerts.append(("critical","Full NVD applicability index missing"))
    report=read_json("/var/lib/scanlattice-cve/applicability-v2-report.json")
    r_age=age_hours(report.get("generated_at")) if report else None
    if r_age is None or r_age>2:
        alerts.append(("warning","CVE V2 assessment report is older than 2 hours"))
    elif report.get("fingerprinted_services",0)<5:
        alerts.append(("warning","Fewer than five services have evidence-backed CPEs"))
    sync=read_json("/var/lib/scanlattice-cve/applicability-v2-sync.json")
    s_age=age_hours(sync.get("last_success")) if sync else None
    if s_age is None:
        alerts.append(("warning","No successful scheduled NVD/CISA update recorded yet"))
    elif s_age>4:
        alerts.append(("critical","NVD/CISA synchronization overdue: "+str(round(s_age,1))+" hours"))
    try:
        health=http_json("https://scanlattice.plezi.eu/api/health")
        vuln=http_json("https://scanlattice.plezi.eu/api/vulnerabilities/stats")
        if not health:
            alerts.append(("critical","Website health returned no data"))
        total=vuln.get("total_cves",0)
        if total<300000:
            alerts.append(("critical","CVE catalog unusually small: "+str(total)))
    except Exception as exc:
        total=0
        alerts.append(("critical","Website health/catalog request failed: "+str(exc)))
    disk=shutil.disk_usage("/var/lib/scanlattice-cve")
    if disk.free<2*1024**3:
        alerts.append(("critical","Less than 2 GiB free on Debian index filesystem"))
    return {
        "role":"debian",
        "cve_catalog_total":total,
        "v2_assessment_age_hours":r_age,
        "feed_sync_age_hours":s_age,
        "fingerprinted_services":report.get("fingerprinted_services",0) if report else 0,
        "disk_free_gib":round(disk.free/1024**3,1),
        "alerts":alerts,
    }

def read_aws_jobs():
    config=read_json("/etc/scanlattice-v3/config.json") or {}
    directory=Path(config.get("state_dir","/var/lib/scanlattice-v3"))/"jobs"
    if not directory.is_dir():
        raise RuntimeError("AWS job directory missing: "+str(directory))
    counts=Counter()
    completed=[]
    for i, path in enumerate(directory.glob("*.json")):
        if i>100000:
            raise RuntimeError("Too many AWS job records")
        item=json.loads(path.read_text())
        counts[item.get("status","unknown")]+=1
        if item.get("status")=="completed":
            completed.append(age_hours(item.get("finished_at")))
    return counts,[t for t in completed if t is not None]

def check_aws():
    alerts=[]
    for name in ("scanlattice-inventory-rescan.timer",
                 "scanlattice-v3.service"):
        if not active(name):
            alerts.append(("critical",name+" is inactive"))
    try:
        jobs,completed=read_aws_jobs()
    except Exception as exc:
        jobs=Counter()
        completed=[]
        alerts.append(("warning","Cannot read scanner jobs: "+str(exc)))
    if completed and min(completed)>30:
        alerts.append(("warning","No successful AWS scanner job in last 30 hours"))
    elif not completed:
        alerts.append(("warning","No successful AWS scanner job recorded yet"))
    try:
        query=urllib.parse.urlencode({"q":"","sort":"ip","page":1,"limit":100})
        data=http_json("https://scanlattice.plezi.eu/api/search?"+query)
        total=data.get("total")
    except Exception as exc:
        total=None
        alerts.append(("critical","Cannot obtain website host inventory: "+str(exc)))
    if jobs["failed"]>0:
        alerts.append(("warning",str(jobs["failed"])+" AWS scan job(s) have failed; inspect job details"))
    return {
        "role":"aws",
        "indexed_hosts_total":total,
        "job_states":dict(jobs),
        "latest_completed_job_hours_ago":min(completed) if completed else None,
        "alerts":alerts,
    }

def notify(summary):
    url=os.getenv("SCANLATTICE_HEALTH_WEBHOOK","").strip()
    if not url or not summary["alerts"]:return
    parts=urllib.parse.urlsplit(url)
    if parts.scheme!="https" or not parts.netloc or parts.username:
        raise RuntimeError("Webhook must be HTTPS without URL credentials")
    payload=json.dumps(summary).encode()
    req=urllib.request.Request(url,data=payload,headers={"Content-Type":"application/json"},
                               method="POST")
    with urllib.request.urlopen(req,timeout=15) as response:
        if response.status>=300:raise RuntimeError("Webhook rejected notification")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--role",choices=["debian","aws"],required=True)
    p.add_argument("--output")
    a=p.parse_args()
    state=check_debian() if a.role=="debian" else check_aws()
    state["generated_at"]=now().isoformat(timespec="seconds")
    state["ok"]=not any(level=="critical" for level,_ in state["alerts"])
    print(json.dumps(state,indent=2))
    if a.output:
        dest=Path(a.output)
        dest.parent.mkdir(parents=True,exist_ok=True)
        tmp=dest.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        os.replace(tmp,dest)
    notify(state)
    if not state["ok"]:sys.exit(2)

if __name__=="__main__":main()
