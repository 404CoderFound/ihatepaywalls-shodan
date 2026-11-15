#!/usr/bin/env python3
"""Create a conservative, provenance-labelled CVE snapshot from V2 and OVAL.

Read-only on PostgreSQL. No vulnerability findings are inserted into the
old host_vulnerability_matches table.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPORT = Path("/var/lib/scanlattice-cve/applicability-v2-report.json")
OUTPUT = Path("/var/lib/scanlattice-cve/cve-v3-public.json")
EVIDENCE = Path("/var/lib/scanlattice-cve/vendor")
CONTAINER = "scanlattice-v2-prodweb-web-1"

def now():
    return datetime.now(timezone.utc)

def read_time(value):
    try:
        d = datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if d.tzinfo is not None: return d.astimezone(timezone.utc)
    except (ValueError, TypeError): pass
    return None

def valid_oval_file(payload, freshness_hours=48):
    if payload.get("schema_version") != 1 or payload.get("os_family") != "ubuntu":
        return False
    if payload.get("source") != "canonical_ubuntu_usn_oval_local_openscap":
        return False
    if not isinstance(payload.get("cve_status"),dict):
        return False
    stamp = read_time(payload.get("generated_at"))
    return bool(stamp and timedelta(0) <= now() - stamp <= timedelta(hours=freshness_hours))

def load_vendor_evidence(directory):
    data = {}
    if not directory.is_dir():
        return data
    for file in sorted(directory.glob("*.json")):
        if file.stat().st_size > 20_000_000:
            raise RuntimeError("Vendor evidence unexpectedly large: "+file.name)
        payload=json.loads(file.read_text())
        if not valid_oval_file(payload):
            print("STALE/UNSUPPORTED vendor evidence:", file.name, file=sys.stderr)
            continue
        ip = str(ipaddress.ip_address(payload["ip"]))
        old = data.get(ip)
        if old is None or old["generated_at"] < payload["generated_at"]:
            data[ip] = payload
    return data

def metadata(cves, container=CONTAINER):
    """Retrieve metadata for the relevant CVEs with the *running PG backend*."""
    result = {}
    ids = sorted(set(cves))
    for start in range(0,len(ids),250):
        batch=ids[start:start+250]
        code = """
import json,sys
from app.database import connection
ids=json.loads(sys.argv[1])
with connection() as db:
  q=','.join('?' for _ in ids)
  rows=db.execute(
    'SELECT cve,severity,cvss,known_exploited,description FROM vulnerabilities WHERE cve IN ('+q+')',
    ids
  ).fetchall() if ids else []
  print(json.dumps([dict(x) for x in rows]))
"""
        p=subprocess.run(["docker","exec",container,"python","-c",code,
                          json.dumps(batch)],capture_output=True,text=True,timeout=90,check=True)
        for row in json.loads(p.stdout):
            result[row["cve"]] = row
    return result

def combine(report, vendor, catalog):
    """Combine potential NVD signals and fresh Ubuntu OVAL package results.

    A negative OVAL result does NOT prove a fixed patch; it only means the
    vendor's local rule did not establish affectedness.
    """
    by_pair={}
    checked_hosts=set()
    for entry in report.get("findings", []):
        ip=str(ipaddress.ip_address(entry["ip"]))
        cve=entry["cve"].upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}",cve):continue
        checked_hosts.add(ip)
        if cve not in catalog: continue
        status=entry.get("status")
        if status not in ("potential","needs_evidence"):continue
        by_pair[(ip,cve)]={
            "ip":ip,"cve":cve,"status":status,
            "evidence":"NVD configuration vs remote service fingerprint",
            "note":"Not a verified vulnerability; OS backports and packages unknown",
        }

    # Verified local vendor evaluation supersedes weak remote inference.
    # Allow a positive local vendor result even if no CPE was fingerprinted.
    suppressed=0
    for ip, payload in vendor.items():
        checked_hosts.add(ip)
        for cve,status in payload["cve_status"].items():
            cve=cve.upper()
            if cve not in catalog: continue
            pair=(ip,cve)
            if status=="vendor_not_affected":
                if pair in by_pair:
                    suppressed+=1
                    del by_pair[pair]
            elif status=="vendor_affected":
                by_pair[pair]={
                    "ip":ip,"cve":cve,"status":"vendor_affected",
                    "evidence":"Canonical Ubuntu USN OVAL evaluated locally with OpenSCAP",
                    "note":"Local vendor package rule returned affected; verify security impact",
                    "vendor_checked_at":payload["generated_at"],
                    "os_codename":payload.get("os_codename",""),
                }
            elif status=="vendor_unknown" and pair in by_pair:
                by_pair[pair]["status"]="needs_evidence"
                by_pair[pair]["note"]="OpenSCAP could not establish package applicability"
    rank={"vendor_affected":0,"potential":1,"needs_evidence":2}
    rows=sorted(by_pair.values(),key=lambda x:(rank.get(x["status"],9),x["ip"],x["cve"]))
    for row in rows:
        meta=catalog[row["cve"]]
        row.update(severity=(meta.get("severity") or "").upper(),
                   cvss=meta.get("cvss"),
                   known_exploited=bool(meta.get("known_exploited")),
                   description=(meta.get("description") or "")[:300])
    counts=Counter(row["status"] for row in rows)
    return {
        "schema_version":1,
        "generated_at":now().isoformat(timespec="seconds"),
        "v2_assessed_at":report.get("generated_at"),
        "source":"ScanLattice CVE V2 NVD + optional local Ubuntu OVAL",
        "hosts_assessed":len(checked_hosts),
        "vendor_hosts":len(vendor),
        "v2_fingerprinted_services":report.get("fingerprinted_services",0),
        "vendor_suppressed_remote_signals":suppressed,
        "counts":dict(counts),
        "status_note":"Remote CVE correlations are POTENTIAL. Vendor-affected requires authenticated local OVAL results. Vendor-false means not affected by that test, not necessarily patched.",
        "findings":rows,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v2-report",type=Path,default=REPORT)
    p.add_argument("--evidence-dir",type=Path,default=EVIDENCE)
    p.add_argument("--output",type=Path,default=OUTPUT)
    p.add_argument("--container",default=CONTAINER)
    a=p.parse_args()
    v2=json.loads(a.v2_report.read_text())
    vendor=load_vendor_evidence(a.evidence_dir)
    ids={r["cve"] for r in v2.get("findings",[])}
    ids.update(cve for payload in vendor.values() for cve,status
               in payload["cve_status"].items() if status=="vendor_affected")
    result=combine(v2,vendor,metadata(ids,a.container))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    tmp=a.output.with_suffix(".tmp")
    tmp.write_text(json.dumps(result,ensure_ascii=False,separators=(",",":")))
    os.chmod(tmp,0o644)
    os.replace(tmp,a.output)
    print("Published snapshot staged locally:",a.output)
    print("Vendor hosts:",result["vendor_hosts"],"statuses:",result["counts"],
          "suppressed unverified matches:",result["vendor_suppressed_remote_signals"])

if __name__=="__main__":main()
