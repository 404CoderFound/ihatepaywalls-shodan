"""ScanLattice control plane MVP — passive index + authenticated worker registry.

There are deliberately NO active scanner imports, OS command execution, or
network probes in the web/control server.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import shlex
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DATABASE_PATH", "/data/scanlattice.db"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
ENROLLMENT_TOKEN = os.getenv("ENROLLMENT_TOKEN", "")
SEED_DEMO = os.getenv("SEED_DEMO", "false").lower() == "true"

app = FastAPI(title="ScanLattice API", version="0.1.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@contextmanager
def connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=20)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    finally:
        db.close()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_secret(supplied: str | None, secret: str, label: str) -> None:
    if not secret:
        raise HTTPException(503, f"{label} is not configured")
    if not supplied or not hmac.compare_digest(supplied, secret):
        raise HTTPException(401, "Invalid credentials")


def require_admin(token: str | None) -> None:
    require_secret(token, ADMIN_TOKEN, "Admin token")


def require_worker(db: sqlite3.Connection, token: str | None) -> sqlite3.Row:
    if not token:
        raise HTTPException(401, "Worker credentials missing")
    row = db.execute("SELECT * FROM workers WHERE token_hash=?", (digest(token),)).fetchone()
    if row is None:
        raise HTTPException(401, "Invalid worker credentials")
    return row


def init_db() -> None:
    with connection() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                proto TEXT NOT NULL DEFAULT 'tcp',
                asn TEXT NOT NULL DEFAULT '',
                org TEXT NOT NULL DEFAULT '',
                country TEXT NOT NULL DEFAULT '',
                product TEXT NOT NULL DEFAULT '',
                banner TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'manual',
                seen_at TEXT NOT NULL,
                is_demo INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_observations_ip ON observations(ip);
            CREATE INDEX IF NOT EXISTS idx_observations_port ON observations(port);
            CREATE INDEX IF NOT EXISTS idx_observations_asn ON observations(asn);
            CREATE TABLE IF NOT EXISTS workers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                capabilities TEXT NOT NULL DEFAULT '[]',
                cpu_pct REAL NOT NULL DEFAULT 0,
                memory_pct REAL NOT NULL DEFAULT 0,
                active_jobs INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_seen INTEGER NOT NULL DEFAULT 0
            );
        """)
        if SEED_DEMO and db.execute("SELECT COUNT(*) FROM observations WHERE is_demo=1").fetchone()[0] == 0:
            samples = [
                ("192.0.2.10", 443, "tcp", "AS64500", "Example Systems", "US", "nginx", "HTTP/1.1 200 OK\\nserver: nginx\\ncontent-type: text/html", "example", 1),
                ("198.51.100.22", 22, "tcp", "AS64501", "Test Network", "NL", "OpenSSH", "SSH-2.0-OpenSSH_9.6", "example", 1),
                ("203.0.113.40", 80, "tcp", "AS64502", "Documentation ISP", "DE", "Apache", "HTTP/1.1 200 OK\\nserver: Apache/2.4", "example", 1),
                ("192.0.2.75", 8443, "tcp", "AS64500", "Example Systems", "US", "Jetty", "HTTP/1.1 302 Found\\nserver: Jetty", "example", 1),
            ]
            db.executemany("""INSERT INTO observations
                (ip,port,proto,asn,org,country,product,banner,source,is_demo,seen_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""", [(*r, utc_now()) for r in samples])


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "role": "control-plane", "active_scanning": False}


@app.get("/api/stats")
def stats():
    with connection() as db:
        count = db.execute("SELECT COUNT(*) AS c FROM observations").fetchone()["c"]
        hosts = db.execute("SELECT COUNT(DISTINCT ip) AS c FROM observations").fetchone()["c"]
        workers = db.execute("SELECT COUNT(*) AS c FROM workers WHERE last_seen > ?", (int(time.time()) - 45,)).fetchone()["c"]
    return {"observations": count, "hosts": hosts, "workers_online": workers, "demo_enabled": SEED_DEMO}


KNOWN_FIELDS = {"ip", "asn", "port", "country", "org", "product", "net", "source"}


def parse_query(text: str):
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid query: {exc}") from exc
    filters, free = {}, []
    for tok in tokens:
        if ":" in tok and tok.split(":", 1)[0].lower() in KNOWN_FIELDS:
            key, val = tok.split(":", 1)
            filters.setdefault(key.lower(), []).append(val)
        else:
            free.append(tok)
    return filters, free


@app.get("/api/search")
def search(q: str = Query("", max_length=500), limit: int = Query(50, ge=1, le=100)):
    filters, free = parse_query(q)
    wheres, params = [], []
    for key, vals in filters.items():
        for val in vals:
            if key == "net":
                try:
                    network = ipaddress.ip_network(val, strict=False)
                except ValueError:
                    raise HTTPException(400, "Invalid CIDR network")
                # This first milestone has a small SQLite index; an indexed CIDR
                # lookup should replace this in the production search engine.
                wheres.append("1=1")
                continue
            if key == "port":
                try:
                    n = int(val)
                    if not 0 < n <= 65535:
                        raise ValueError()
                except ValueError:
                    raise HTTPException(400, "Invalid port")
                wheres.append("port=?")
                params.append(n)
            elif key in {"ip", "asn", "country", "source"}:
                wheres.append(f"{key} = ?")
                params.append(val.upper() if key in {"asn", "country"} else val)
            else:
                wheres.append(f"LOWER({key}) LIKE ?")
                params.append(f"%{val.lower()}%")
    for tok in free:
        wheres.append("(LOWER(banner) LIKE ? OR LOWER(product) LIKE ? OR LOWER(org) LIKE ? OR LOWER(ip) LIKE ?)")
        params.extend([f"%{tok.lower()}%"] * 4)
    where = " WHERE " + " AND ".join(wheres) if wheres else ""
    with connection() as db:
        query_rows = db.execute("SELECT * FROM observations" + where + " ORDER BY seen_at DESC, id DESC", params).fetchall()
        if "net" in filters:
            nets = [ipaddress.ip_network(v, strict=False) for v in filters["net"]]
            query_rows = [r for r in query_rows if all(ipaddress.ip_address(r["ip"]) in n for n in nets)]
        total = len(query_rows)
        rows = [dict(r) for r in query_rows[:limit]]
        ports = {}
        countries = {}
        for row in query_rows:
            ports[str(row["port"])] = ports.get(str(row["port"]), 0) + 1
            countries[row["country"] or "Unknown"] = countries.get(row["country"] or "Unknown", 0) + 1
    return {"query": q, "total": total, "results": rows, "facets": {"ports": ports, "countries": countries}}


@app.get("/api/hosts/{ip}")
def host(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP")
    with connection() as db:
        rows = [dict(r) for r in db.execute("SELECT * FROM observations WHERE ip=? ORDER BY port", (ip,)).fetchall()]
    if not rows:
        raise HTTPException(404, "Not indexed")
    return {"ip": ip, "services": rows}


class Registration(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    capabilities: list[str] = Field(default_factory=list, max_length=15)


@app.post("/api/worker/register")
def worker_register(payload: Registration, x_enrollment_token: Annotated[str | None, Header()] = None):
    require_secret(x_enrollment_token, ENROLLMENT_TOKEN, "Enrollment token")
    worker_id = secrets.token_hex(12)
    worker_token = secrets.token_urlsafe(48)
    with connection() as db:
        db.execute("""INSERT INTO workers (id,name,token_hash,capabilities,created_at,last_seen)
                     VALUES (?,?,?,?,?,?)""", (worker_id, payload.name, digest(worker_token), json.dumps(payload.capabilities), utc_now(), int(time.time())))
    return {"worker_id": worker_id, "worker_token": worker_token, "heartbeat_seconds": 10}


class Heartbeat(BaseModel):
    cpu_pct: float = Field(ge=0, le=100)
    memory_pct: float = Field(ge=0, le=100)
    active_jobs: int = Field(default=0, ge=0, le=10000)


@app.post("/api/worker/heartbeat")
def worker_heartbeat(payload: Heartbeat, x_worker_token: Annotated[str | None, Header()] = None):
    with connection() as db:
        worker = require_worker(db, x_worker_token)
        db.execute("UPDATE workers SET cpu_pct=?,memory_pct=?,active_jobs=?,last_seen=? WHERE id=?", (
            payload.cpu_pct, payload.memory_pct, payload.active_jobs, int(time.time()), worker["id"]))
    return {"status": "ok", "jobs_available": 0}


@app.get("/api/worker/jobs")
def worker_jobs(x_worker_token: Annotated[str | None, Header()] = None):
    with connection() as db:
        require_worker(db, x_worker_token)
    # No targets are scanned in this release. An authorized-scope job queue
    # will be added later, without installing a scanner on this server.
    return {"jobs": [], "scanning_enabled": False}


@app.get("/api/admin/workers")
def admin_workers(x_admin_token: Annotated[str | None, Header()] = None):
    require_admin(x_admin_token)
    with connection() as db:
        rows = [dict(r) for r in db.execute("SELECT id,name,capabilities,cpu_pct,memory_pct,active_jobs,created_at,last_seen FROM workers ORDER BY created_at DESC")]
    cutoff = int(time.time()) - 45
    for r in rows:
        r["online"] = r["last_seen"] > cutoff
        r["capabilities"] = json.loads(r["capabilities"])
    return {"workers": rows, "scan_jobs_enabled": False}


class Observation(BaseModel):
    ip: str
    port: int = Field(ge=1, le=65535)
    proto: str = Field(default="tcp", pattern="^(tcp|udp)$")
    asn: str = Field(default="", max_length=40)
    org: str = Field(default="", max_length=160)
    country: str = Field(default="", max_length=8)
    product: str = Field(default="", max_length=160)
    banner: str = Field(default="", max_length=8192)
    source: str = Field(default="manual", max_length=100)


class ImportPayload(BaseModel):
    observations: list[Observation] = Field(min_length=1, max_length=1000)


@app.post("/api/admin/import")
def import_observations(payload: ImportPayload, x_admin_token: Annotated[str | None, Header()] = None):
    require_admin(x_admin_token)
    data = []
    for row in payload.observations:
        try:
            ipaddress.ip_address(row.ip)
        except ValueError:
            raise HTTPException(400, f"Invalid IP: {row.ip}")
        data.append((row.ip, row.port, row.proto, row.asn.upper(), row.org, row.country.upper(), row.product, row.banner, row.source, utc_now()))
    with connection() as db:
        db.executemany("""INSERT INTO observations (ip,port,proto,asn,org,country,product,banner,source,seen_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""", data)
    return {"imported": len(data)}
