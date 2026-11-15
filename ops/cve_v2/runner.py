#!/usr/bin/env python3
"""ScanLattice CVE V2: full-configuration index, refresh, and read-only assessment.

Requires python3-ijson; uses existing Debian admin API and PostgreSQL container.
Nothing in this file starts network port scans or writes host vulnerability matches.
"""
import argparse
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import urllib.request
import urllib.error

from applicability import assess, candidates, key

FEEDS = Path("/srv/scanlattice-data/nvd-feeds")
STORE = Path("/var/lib/scanlattice-cve")
INDEX = STORE / "applicability-v2.sqlite3"
STATE = STORE / "applicability-v2-sync.json"
REPORT = STORE / "applicability-v2-report.json"
CONTAINER = "scanlattice-v2-prodweb-web-1"
FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCE = "ScanLattice CVE V2"
LOCKFILE = Path("/run/lock/scanlattice-cve-v2.lock")

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def write_state(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def open_index():
    STORE.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(INDEX, timeout=60)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=60000")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS cves(
      cve TEXT PRIMARY KEY,
      last_modified TEXT NOT NULL,
      configs_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS candidates(
      product_key TEXT NOT NULL, cve TEXT NOT NULL,
      PRIMARY KEY(product_key, cve)
    );
    CREATE INDEX IF NOT EXISTS candidate_cve_idx ON candidates(cve);
    CREATE TABLE IF NOT EXISTS feeds(
      name TEXT PRIMARY KEY, sha256 TEXT NOT NULL,
      offset INTEGER NOT NULL DEFAULT 0, complete INTEGER NOT NULL DEFAULT 0
    );
    """)
    db.commit()
    return db

def local_files():
    files = list(FEEDS.glob("nvdcve-2.0-*.json.gz"))
    def rank(p):
        name = p.name.removeprefix("nvdcve-2.0-").removesuffix(".json.gz")
        return (0, int(name)) if name.isdigit() else (1, name)
    return sorted(files, key=rank)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while data := f.read(4 * 1024 * 1024):
            h.update(data)
    return h.hexdigest()

def iter_feed(path):
    try:
        import ijson
    except ImportError as exc:
        raise RuntimeError("Install python3-ijson on Debian") from exc
    with gzip.open(path, "rb") as stream:
        yield from ijson.items(stream, "vulnerabilities.item", use_float=True)

def build(files=None):
    files = files if files is not None else local_files()
    if not files:
        raise RuntimeError("No NVD 2.0 feeds found under " + str(FEEDS))
    db = open_index()
    try:
        for path in files:
            name = path.name
            digest = sha256(path)
            old = db.execute("SELECT * FROM feeds WHERE name=?", (name,)).fetchone()
            if old and old[1] == digest and old[3]:
                print("INDEX skipped", name, flush=True)
                continue
            offset = old[2] if old and old[1] == digest else 0
            db.execute(
                "INSERT INTO feeds(name,sha256,offset,complete) VALUES(?,?,?,0) "
                "ON CONFLICT(name) DO UPDATE SET sha256=excluded.sha256,"
                "offset=excluded.offset,complete=0", (name,digest,offset)
            )
            db.commit()
            buffered = []
            count = 0
            for record in iter_feed(path):
                count += 1
                if count <= offset:
                    continue
                cve = record.get("cve", record)
                cve_id = str(cve.get("id", "")).upper()
                if not cve_id.startswith("CVE-"):
                    continue
                buffered.append(cve)
                if len(buffered) >= 500:
                    index_batch(db, buffered)
                    buffered.clear()
                    db.execute("UPDATE feeds SET offset=? WHERE name=?", (count,name))
                    db.commit()
            if buffered:
                index_batch(db, buffered)
            db.execute("UPDATE feeds SET offset=?,complete=1 WHERE name=?", (count,name))
            db.commit()
            print("INDEX complete", name, f"{count:,} records", flush=True)
        n = db.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        print("Applicability index ready:", f"{n:,}", "non-rejected CVEs", flush=True)
    finally:
        db.close()

def index_batch(db, items):
    for cve in items:
        cve_id = str(cve.get("id", "")).upper()
        status = str(cve.get("vulnStatus","")).lower()
        if status == "rejected":
            db.execute("DELETE FROM candidates WHERE cve=?", (cve_id,))
            db.execute("DELETE FROM cves WHERE cve=?", (cve_id,))
            continue
        modified = str(cve.get("lastModified") or cve.get("published") or "")
        existing = db.execute("SELECT last_modified FROM cves WHERE cve=?", (cve_id,)).fetchone()
        if existing and modified < existing[0]:
            continue
        configs = cve.get("configurations", [])
        serialized = json.dumps(configs, separators=(",", ":"))
        db.execute("INSERT INTO cves(cve,last_modified,configs_json) VALUES(?,?,?) "
                   "ON CONFLICT(cve) DO UPDATE SET "
                   "last_modified=excluded.last_modified, configs_json=excluded.configs_json",
                   (cve_id,modified,serialized))
        db.execute("DELETE FROM candidates WHERE cve=?", (cve_id,))
        for product in candidates(configs):
            db.execute("INSERT OR IGNORE INTO candidates(product_key,cve) VALUES(?,?)",
                       (product,cve_id))

def read_services():
    program = """import json
from app.database import connection
with connection() as db:
    rows = db.execute("SELECT host_ip,cpe,source,last_seen FROM services WHERE cpe!=''").fetchall()
    print(json.dumps([dict(r) for r in rows]))
"""
    output = subprocess.check_output(
        ["docker", "exec", CONTAINER, "python", "-c", program],
        text=True, timeout=120
    )
    return json.loads(output)

def run_assessment():
    services = read_services()
    hosts = defaultdict(list)
    for service in services:
        hosts[service["host_ip"]].append(service)
    db = open_index()
    findings, counts = [], Counter()
    try:
        for host, seen in hosts.items():
            observed = [s["cpe"] for s in seen]
            products = sorted({p for cpe in observed if (p := key(cpe))})
            if not products:
                continue
            placeholders = ",".join("?" for _ in products)
            # Product-index lookup, not a 407k-CVE cross-product.
            rows = db.execute(
                f"SELECT DISTINCT c.cve,c.configs_json FROM cves c "
                f"JOIN candidates p ON p.cve=c.cve "
                f"WHERE p.product_key IN ({placeholders})",
                products
            )
            for cve, raw_config in rows:
                status = assess(json.loads(raw_config), observed)
                if status is None:
                    continue
                counts[status] += 1
                findings.append({
                    "ip":host,"cve":cve,"status":status,
                    "evidence":"Remote CPE/product-version observation only",
                    "observed_cpes":observed,
                    "limitations":"Not a verified vulnerability; installed patches and "
                                  "unobserved platform requirements may change applicability"
                })
        report = {
            "generated_at":now_iso(),
            "hosts_checked":len(hosts),
            "fingerprinted_services":len(services),
            "potential":counts["potential"],
            "needs_evidence":counts["needs_evidence"],
            "findings":findings
        }
        write_state(REPORT, report)
        print("Assessment saved:", REPORT, flush=True)
        print("Hosts:",len(hosts),"CPE services:",len(services),
              "potential:",counts["potential"],
              "needs evidence:",counts["needs_evidence"], flush=True)
        for finding in findings[:15]:
            print(finding["status"].upper(), finding["ip"], finding["cve"])
        print("READ ONLY: no host vulnerability matches written.",flush=True)
    finally:
        db.close()

def fetch(url, headers=None, attempts=5):
    for attempt in range(attempts):
        try:
            req=urllib.request.Request(
                url,headers={"User-Agent":"ScanLattice-CVE-V2/1.0",**(headers or {})}
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code not in (408,429,500,502,503,504) or attempt == attempts-1:
                raise
            try:
                delay=min(120,float(e.headers.get("Retry-After","0")))
            except ValueError:
                delay=0
            time.sleep(delay or min(90,2**(attempt+1)))
        except (TimeoutError,OSError):
            if attempt == attempts-1: raise
            time.sleep(min(90,2**(attempt+1)))

def decompress_sha256(path):
    h=hashlib.sha256()
    with gzip.open(path, "rb") as f:
        while chunk := f.read(4*1024*1024):
            h.update(chunk)
    return h.hexdigest()

def fetch_modified():
    meta=fetch(FEED_URL+"modified.meta").decode("utf-8")
    props=dict(line.strip().split(":",1) for line in meta.splitlines() if ":" in line)
    expected=props["sha256"].strip().lower()
    if len(expected)!=64 or any(c not in "0123456789abcdef" for c in expected):
        raise RuntimeError("Invalid NVD metadata hash")
    dest=FEEDS/"nvdcve-2.0-modified.json.gz"
    if dest.exists() and decompress_sha256(dest)==expected:
        return dest, expected
    raw=fetch(FEED_URL+"modified.json.gz")
    temp=dest.with_suffix(dest.suffix+".new")
    dest.parent.mkdir(parents=True,exist_ok=True)
    temp.write_bytes(raw)
    if decompress_sha256(temp)!=expected:
        temp.unlink(missing_ok=True)
        raise RuntimeError("Modified-feed SHA256 mismatch")
    os.replace(temp,dest)
    return dest,expected

def sync_api(feed_path, sync_kev=True):
    sys.path.insert(0,"/home/ihatepaywalls")
    import nvd_full_backfill as base
    token=Path(base.TOKEN).read_text().strip()
    if len(token)<20:
        raise RuntimeError("Missing administrator API token")
    image=subprocess.check_output(
        ["docker","inspect","-f","{{.Config.Image}}",CONTAINER],text=True
    ).strip()
    if image!="scanlattice-prodweb:cve-bulk-v1":
        raise RuntimeError("Expected cve-bulk-v1; refusing expensive full matcher")
    batch=[]
    count=0
    def send(records, source):
        if not records: return
        result=base.json_request(
            base.ADMIN,headers={
                "X-Admin-Token":token,"Content-Type":"application/json"
            },payload={"source":source,"records":records}
        )
        if result.get("imported")!=len(records):
            raise RuntimeError("Unexpected import response; no sync checkpoint set")
    for item in iter_feed(feed_path):
        normalized=base.normalize(item)
        if normalized:
            batch.append(normalized)
        if len(batch)>=250:
            send(batch,"NVD 2.0 modified")
            count+=len(batch)
            batch=[]
    send(batch,"NVD 2.0 modified")
    count+=len(batch)
    print("PostgreSQL NVD upserts:",count,flush=True)
    return base,token

def sync_cisa(base,token):
    raw=fetch(KEV_URL)
    data=json.loads(raw)
    entries=data.get("vulnerabilities")
    if not isinstance(entries,list) or len(entries)<100:
        raise RuntimeError("Invalid CISA KEV response")
    records=[]
    for v in entries:
        cve=str(v.get("cveID","")).upper()
        if cve.startswith("CVE-"):
            records.append({"cve":cve,"description":"",
                            "severity":"","cvss":None,
                            "known_exploited":True,"cpes":[]})
    for i in range(0,len(records),250):
        part=records[i:i+250]
        result=base.json_request(
            base.ADMIN,headers={"X-Admin-Token":token,
                                "Content-Type":"application/json"},
            payload={"source":"CISA KEV","records":part}
        )
        if result.get("imported")!=len(part):
            raise RuntimeError("CISA KEV import response invalid")
    print("CISA KEV refreshed:",len(records),flush=True)

def refresh():
    existing=json.loads(STATE.read_text()) if STATE.exists() else {}
    if not INDEX.exists():
        raise RuntimeError("Build full index first")
    last=existing.get("last_success")
    if last and datetime.now(timezone.utc)-datetime.fromisoformat(last)>timedelta(days=6):
        raise RuntimeError("NVD modified feed lookback exceeded; run year-feed "
                           "catch-up before resuming to avoid missing older changes")
    path,source_sha=fetch_modified()
    if existing.get("modified_sha")!=source_sha:
        base,token=sync_api(path)
        # Rebuild ONLY the changed feed after its PostgreSQL upserts succeeded.
        build([path])
    else:
        sys.path.insert(0,"/home/ihatepaywalls")
        import nvd_full_backfill as base
        token=Path(base.TOKEN).read_text().strip()
    sync_cisa(base,token)
    existing["modified_sha"]=source_sha
    existing["last_success"]=now_iso()
    write_state(STATE,existing)
    run_assessment()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("command",choices=["index","assess","refresh","status"])
    args=parser.parse_args()
    if args.command=="status":
        print("index present",INDEX.exists())
        print("sync state",STATE.read_text() if STATE.exists() else "not started")
        print("last report", REPORT if REPORT.exists() else "none")
        return
    with open(LOCKFILE,"a+") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        {"index":build,"assess":run_assessment,"refresh":refresh}[args.command]()

if __name__=="__main__":
    main()
