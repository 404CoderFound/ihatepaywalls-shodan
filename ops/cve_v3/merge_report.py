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

def confirmation_is_sufficient(item, vendor_status, expected_ip, expected_cve):
    """No automatic promotion: requires local package result AND reviewed
    host-specific evidence. This is an evidence gate, never a claim of
    mathematical certainty or a guarantee of exploitability.
    """
    if vendor_status != "vendor_affected" or not isinstance(item, dict):
        return False
    if item.get("schema_version") != 1:
        return False
    if item.get("ip") != expected_ip or item.get("cve") != expected_cve:
        return False
    if item.get("status") != "confirmed":
        return False
    for key in ("component_present", "affected_configuration_verified",
                "unpatched_installed_package_verified"):
        if item.get(key) is not True:
            return False
    if not all(isinstance(item.get(k),str) and len(item[k].strip()) >= 8
               for k in ("reviewer", "evidence_reference", "verification_method")):
        return False
    checked_at = read_time(item.get("verified_at"))
    return bool(checked_at and timedelta(0) <= now()-checked_at <= timedelta(hours=48))


def load_confirmations(directory):
    """Opt-in reviewed attestations from a root-managed, non-web directory."""
    confirmations={}
    if not directory.is_dir():
        return confirmations
    for path in directory.glob("*.json"):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
            continue
        try:
            row=json.loads(path.read_text())
            ip=str(ipaddress.ip_address(row["ip"]))
            cve=str(row["cve"]).upper()
            if re.fullmatch(r"CVE-\d{4}-\d{4,}",cve):
                confirmations[(ip,cve)] = row
        except (OSError,ValueError,KeyError,TypeError):
            continue
    return confirmations


def combine(report, vendor, catalog, confirmations=None):
    """Public output contains ONLY host findings backed by two evidence gates.

    1. Fresh authenticated on-host Canonical USN OVAL = affected package.
    2. Separately reviewed proof of present component, vulnerable unpatched
       installed package and applicable configuration.

    In particular, never publish V2 remote CPE / NVD research candidates.
    """
    confirmations = confirmations or {}
    rows=[]
    suppressed_remote=len(report.get("findings", []))
    for ip,payload in vendor.items():
        for cve,local_status in payload.get("cve_status",{}).items():
            cve=cve.upper()
            if cve not in catalog:
                continue
            evidence=confirmations.get((ip,cve))
            if not confirmation_is_sufficient(evidence, local_status, ip,cve):
                continue
            meta=catalog[cve]
            rows.append({
                "ip":ip, "cve":cve, "status":"confirmed",
                "severity":(meta.get("severity") or "").upper(),
                "cvss":meta.get("cvss"),
                "known_exploited":bool(meta.get("known_exploited")),
                "description":(meta.get("description") or "")[:300],
                "evidence":"Local Ubuntu OpenSCAP plus separately reviewed host-specific evidence",
                "verified_at":evidence["verified_at"],
                "verification_method":evidence["verification_method"],
                "evidence_reference":evidence["evidence_reference"],
                "os_codename":payload.get("os_codename",""),
            })
    rows.sort(key=lambda x:(x["ip"],x["cve"]))
    return {
        "schema_version":1,
        "generated_at":now().isoformat(timespec="seconds"),
        "v2_assessed_at":report.get("generated_at"),
        "source":"Strict verified-host evidence; remote CPE correlations excluded",
        "hosts_assessed":report.get("hosts_checked",0),
        "vendor_hosts":len(vendor),
        "v2_fingerprinted_services":report.get("fingerprinted_services",0),
        "unverified_signals_excluded":suppressed_remote,
        "counts":{"confirmed":len(rows)},
        "status_note":"Only locally assessed AND separately reviewed host-specific findings are displayed. Zero findings does not prove safety. No scanner can guarantee 100% vulnerability certainty.",
        "findings":rows,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v2-report",type=Path,default=REPORT)
    p.add_argument("--evidence-dir",type=Path,default=EVIDENCE)
    p.add_argument("--output",type=Path,default=OUTPUT)
    p.add_argument("--container",default=CONTAINER)
    p.add_argument("--confirmations-dir",type=Path,default=Path("/var/lib/scanlattice-cve/confirmed-host-evidence"))
    a=p.parse_args()
    v2=json.loads(a.v2_report.read_text())
    vendor=load_vendor_evidence(a.evidence_dir)
    confirmations=load_confirmations(a.confirmations_dir)
    ids={cve for (ip,cve),confirmation in confirmations.items()
         if ip in vendor and vendor[ip].get("cve_status",{}).get(cve)=="vendor_affected"}
    result=combine(v2,vendor,metadata(ids,a.container),confirmations)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    tmp=a.output.with_suffix(".tmp")
    tmp.write_text(json.dumps(result,ensure_ascii=False,separators=(",",":")))
    os.chmod(tmp,0o644)
    os.replace(tmp,a.output)
    print("Published snapshot staged locally:",a.output)
    print("Strict host findings:",result["counts"]["confirmed"],
          "remote-only correlations withheld:",result["unverified_signals_excluded"])

if __name__=="__main__":main()
