#!/usr/bin/env python3
"""Rescan eligible ScanLattice-indexed hosts on AWS, with a strict scope gate.

The public /api/search page gives the inventory, NOT authorization to scan.
Only configured authorized_cidrs are eligible. This is intentionally
one-shot, paced scheduling; individual per-IP recurring jobs are NOT created.
"""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
import urllib.request

DEFAULT_CONFIG = "/etc/scanlattice-v3/inventory-rescan.json"
LOCK = "/run/lock/scanlattice-inventory-rescan.lock"
BUSY = {"queued", "running", "scheduled", "upload_pending", "completed_local", "cancelling"}

def clock():
    return datetime.now(timezone.utc)

def parse_date(value):
    if not value:
        return None
    try:
        value = value.replace("Z", "+00:00")
        timestamp = datetime.fromisoformat(value)
        return timestamp.astimezone(timezone.utc) if timestamp.tzinfo else None
    except (ValueError, AttributeError):
        return None

def load_config(path):
    cfg = json.loads(Path(path).read_text())
    website = cfg.get("website_url", "")
    origin = urllib.parse.urlsplit(website)
    if (origin.scheme != "https" or not origin.netloc or
            origin.username or origin.password or origin.path not in ("", "/") or
            origin.query or origin.fragment):
        raise ValueError("website_url must be an HTTPS origin without path/query")
    allowed = cfg.get("authorized_cidrs")
    if not isinstance(allowed, list) or not allowed:
        raise ValueError("authorized_cidrs must contain explicit approved ranges; nothing queued")
    cfg["_allowed"] = [ipaddress.ip_network(n, strict=True) for n in allowed]
    if len(cfg["_allowed"]) > 500:
        raise ValueError("too many authorized ranges")
    # Supplement, never weaken, the scanner's own policy exclusions.
    scanner = json.loads(Path(cfg.get("scanner_config", "/etc/scanlattice-v3/config.json")).read_text())
    cfg["_excluded"] = [ipaddress.ip_network(n, strict=False)
                        for n in scanner.get("excluded_cidrs", [])]
    profile = cfg.get("ports", "extended")
    if profile not in ("quick", "standard", "extended", "all-tcp"):
        raise ValueError("invalid ports profile")
    for key, upper in (("max_inventory_hosts", 100000),
                       ("max_jobs_per_tick", 200),
                       ("max_pending_jobs", 1000),
                       ("max_jobs_per_night", 20000),
                       ("max_checks_per_night", 100000000),
                       ("cooldown_hours", 168)):
        value = cfg.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= upper:
            raise ValueError("invalid "+key)
    start, end = cfg.get("night_start_utc"), cfg.get("night_end_utc")
    if not (isinstance(start,int) and isinstance(end,int) and
            0 <= start < end <= 24):
        raise ValueError("night hours must satisfy 0 <= start < end <= 24")
    cfg["_website"] = website.rstrip("/")
    return cfg

def http_json(url, timeout=30):
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "ScanLattice-inventory-rescan/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise RuntimeError("inventory response exceeds 8MB")
    return json.loads(data)

def inventory(cfg, fetch=http_json):
    """Fetch complete paginated website hosts list. Fail on pagination drift."""
    ips = set()
    page = 1
    original_total = None
    while True:
        query = urllib.parse.urlencode({
            "q": "", "sort": "ip", "limit": 100, "page": page})
        data = fetch(cfg["_website"] + "/api/search?" + query)
        total = data.get("total")
        rows = data.get("hosts", data.get("results"))
        if not isinstance(total,int) or total < 0 or not isinstance(rows,list):
            raise RuntimeError("unexpected ScanLattice search response")
        if total > cfg["max_inventory_hosts"]:
            raise RuntimeError(
                "website has "+str(total)+" hosts, exceeds max_inventory_hosts="+
                str(cfg["max_inventory_hosts"])+". No jobs submitted.")
        if original_total is None:
            original_total = total
        if total != original_total or data.get("page") != page:
            raise RuntimeError("website pagination changed; retry next cycle")
        for row in rows:
            if not isinstance(row,dict) or not isinstance(row.get("ip"),str):
                raise RuntimeError("invalid host record in inventory")
            try:
                ip = ipaddress.ip_address(row["ip"])
            except ValueError as exc:
                raise RuntimeError("unexpected IP in inventory") from exc
            ips.add(str(ip))
        if not data.get("has_next", False):
            break
        page += 1
        if page > (cfg["max_inventory_hosts"] + 99) // 100 + 1:
            raise RuntimeError("inventory pagination never ended")
    if len(ips) != original_total:
        raise RuntimeError("inventory incomplete or changed; no jobs submitted")
    return sorted(ips, key=lambda s: (ipaddress.ip_address(s).version,
                                      int(ipaddress.ip_address(s))))

def permitted(ip, cfg):
    obj = ipaddress.ip_address(ip)
    # AWS cannot reach home/private addresses through public Internet.
    if not obj.is_global:
        return False
    if any(obj in n for n in cfg["_excluded"]):
        return False
    return any(obj in network for network in cfg["_allowed"])

def scanner(args, binary="/usr/local/bin/scanlattice-v3"):
    result = subprocess.run([binary, *args], capture_output=True,
                            text=True, timeout=45, check=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("unexpected Go scanner response") from exc

def history(jobs, profile, when):
    recent = {}
    busy = set()
    nightly_jobs = 0
    nightly_checks = 0
    pending = 0
    for job in jobs:
        if not isinstance(job, dict):
            raise RuntimeError("unexpected scanner job record")
        req = job.get("request") or {}
        status = job.get("status", "")
        if status in BUSY:
            pending += 1
        if req.get("target_type") != "ip" or req.get("ports") != profile:
            continue
        ip = req.get("target")
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue
        if status in BUSY:
            busy.add(ip)
        finished = parse_date(job.get("finished_at"))
        if status in ("completed", "scheduled") and finished:
            recent[ip] = max(recent.get(ip, finished), finished)
        created = parse_date(job.get("created_at"))
        if created and created.date() == when.date():
            nightly_jobs += 1
            nightly_checks += int((job.get("plan") or {}).get("check_count", 0))
    return recent, busy, pending, nightly_jobs, nightly_checks

def run(cfg, enqueue=False, fetch=http_json, call=scanner, now=None):
    now = now or clock()
    ips = inventory(cfg, fetch=fetch)
    approved = [ip for ip in ips if permitted(ip,cfg)]
    jobs_response = call(["jobs"], cfg.get("scanner_bin","/usr/local/bin/scanlattice-v3"))
    jobs = jobs_response.get("jobs")
    if not isinstance(jobs,list):
        raise RuntimeError("invalid scanner jobs response")
    recent, busy, pending, nightly_jobs, nightly_checks = history(
        jobs,cfg.get("ports","extended"),now)
    threshold = now - timedelta(hours=cfg["cooldown_hours"])
    due = [ip for ip in approved
           if ip not in busy and (ip not in recent or recent[ip] < threshold)]
    due.sort(key=lambda ip: (recent.get(ip,datetime.min.replace(tzinfo=timezone.utc)),
                             ipaddress.ip_address(ip).version,
                             int(ipaddress.ip_address(ip))))
    print("Website indexed hosts:",len(ips))
    print("Authorized public hosts:",len(approved))
    print("Skipped outside authorized scope:",len(ips)-len(approved))
    print("Hosts due for rescan:",len(due))
    print("Scanner pending/running jobs:",pending)
    print("Already queued today:",nightly_jobs,"jobs /",nightly_checks,"checks")
    if not enqueue:
        print("PREVIEW ONLY; no scans queued.")
        for ip in due[:20]:
            print("  DUE",ip)
        return 0
    if not cfg["night_start_utc"] <= now.hour < cfg["night_end_utc"]:
        print("Outside UTC nighttime window; no scans queued.")
        return 0
    slots = min(cfg["max_jobs_per_tick"],
                max(0,cfg["max_pending_jobs"]-pending),
                max(0,cfg["max_jobs_per_night"]-nightly_jobs))
    submitted = 0
    checks = nightly_checks
    for ip in due:
        if submitted >= slots:
            break
        request = ["--ip",ip,"--ports",cfg.get("ports","extended")]
        plan = call(["plan",*request],
                    cfg.get("scanner_bin","/usr/local/bin/scanlattice-v3"))
        if int(plan.get("host_count",0)) != 1:
            raise RuntimeError("scanner plan was not exactly one host: "+ip)
        num = int(plan.get("check_count",0))
        if num <= 0:
            raise RuntimeError("empty scanner plan for "+ip)
        if checks + num > cfg["max_checks_per_night"]:
            print("Nightly check budget reached before",ip)
            break
        result = call(["scan",*request],
                      cfg.get("scanner_bin","/usr/local/bin/scanlattice-v3"))
        if result.get("status") not in ("queued","scheduled"):
            raise RuntimeError("scanner did not confirm queued job for "+ip)
        submitted += 1
        checks += num
        print("QUEUED",ip,"job",result.get("id"),"checks",num,flush=True)
    print("Enqueued:",submitted,"; remaining due:",len(due)-submitted)
    if due and submitted < len(due):
        print("Backlog remains. Increase AWS capacity or budget only after review.")
    return submitted

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--config",default=DEFAULT_CONFIG)
    parser.add_argument("--enqueue",action="store_true",
                        help="Actually create jobs, only inside nightly UTC window")
    args=parser.parse_args()
    cfg=load_config(args.config)
    if args.enqueue:
        Path(LOCK).parent.mkdir(parents=True,exist_ok=True)
        with open(LOCK,"a+") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
            run(cfg,enqueue=True)
    else:
        run(cfg)

if __name__=="__main__":
    main()
