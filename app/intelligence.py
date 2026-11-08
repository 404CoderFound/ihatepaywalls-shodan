"""Additional data-backed intelligence APIs for the v1.0 development line."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import io
import json
import re
import secrets
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .database import connection, utc_now

router = APIRouter(prefix="/api", tags=["intelligence"])


def _admin(request: Request) -> None:
    if not getattr(request.state, "admin_authenticated", False):
        raise HTTPException(401, "Administrator authentication required")


def _key_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _valid_cve(value: str) -> str:
    value = value.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
        raise HTTPException(422, "CVE must use CVE-YYYY-NNNN format")
    return value


class KeyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    scopes: list[str] = Field(default_factory=lambda: ["search:read"], max_length=8)


class VulnerabilityImport(BaseModel):
    records: list[dict] = Field(min_length=1, max_length=5000)
    source: str = Field(min_length=2, max_length=120)


class MonitorCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    target: str = Field(min_length=1, max_length=253)
    authorization_id: int


class SavedSearchCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    query: str = Field(min_length=1, max_length=500)


class DNSImport(BaseModel):
    records: list[dict] = Field(min_length=1, max_length=5000)
    source: str = Field(min_length=2, max_length=120)
    method: str = Field(pattern="^(dataset|passive_dataset|certificate_transparency)$")


@router.get("/hosts/{ip}/observations")
def observation_history(ip: str, page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=200)):
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(400, "Invalid IP") from exc
    with connection() as db:
        total = db.execute("SELECT COUNT(*) FROM observations WHERE ip=?", (ip,)).fetchone()[0]
        rows = [dict(r) for r in db.execute(
            "SELECT * FROM observations WHERE ip=? ORDER BY seen_at DESC,id DESC LIMIT ? OFFSET ?",
            (ip, limit, (page - 1) * limit))]
    return {"ip": ip, "results": rows, "page": page, "per_page": limit, "total": total,
            "provenance": "Each row retains its ingestion or worker source and observation timestamp."}


@router.get("/domains/{domain}")
def domain_intelligence(domain: str):
    domain = domain.rstrip(".").lower()
    if len(domain) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise HTTPException(400, "Invalid domain name")
    with connection() as db:
        rows = [dict(r) for r in db.execute("SELECT * FROM dns_observations WHERE domain=? ORDER BY observed_at DESC,id DESC", (domain,))]
        passive = [dict(r) for r in db.execute("SELECT * FROM passive_records WHERE domain=? ORDER BY observed_at DESC,id DESC", (domain,))]
        ips = [dict(r) for r in db.execute("SELECT ip,source,MIN(seen_at) first_seen,MAX(seen_at) last_seen FROM observations WHERE LOWER(hostname)=? GROUP BY ip,source", (domain,))]
    return {"domain": domain, "dns_history": rows, "passive_intelligence": passive,
            "indexed_hosts": ips, "message": None if rows or passive or ips else "No indexed or passive information available."}


@router.post("/admin/domains/{domain}/dns-import")
def import_domain_dns(domain: str, payload: DNSImport, request: Request):
    _admin(request)
    domain=domain.rstrip(".").lower()
    if len(domain)>253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",domain):
        raise HTTPException(400,"Invalid domain name")
    allowed={"A","AAAA","MX","NS","TXT","CNAME","SOA","PTR"}
    now=utc_now();count=0
    with connection() as db:
        for record in payload.records:
            kind=str(record.get("type","")).upper();value=str(record.get("value", ""))
            if kind not in allowed or not value or len(value)>4096:raise HTTPException(422,"DNS record has an unsupported type or empty/oversized value")
            observed=str(record.get("observed_at",now))[:64]
            db.execute("INSERT INTO dns_observations(domain,record_type,value,source,method,observed_at) VALUES(?,?,?,?,?,?)",(domain,kind,value,payload.source,payload.method,observed));count+=1
    return {"domain":domain,"imported":count,"source":payload.source,"method":payload.method,"imported_at":now}


@router.get("/vulnerabilities")
def vulnerabilities(q: str = Query("", max_length=200), severity: str = Query("", max_length=20), page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=200)):
    clauses, args = [], []
    if q:
        clauses.append("(cve LIKE ? OR LOWER(description) LIKE ?)"); args.extend([f"%{q.upper()}%", f"%{q.lower()}%"])
    if severity:
        clauses.append("UPPER(severity)=UPPER(?)"); args.append(severity)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with connection() as db:
        total = db.execute("SELECT COUNT(*) FROM vulnerabilities" + where, args).fetchone()[0]
        rows = [dict(r) for r in db.execute("SELECT * FROM vulnerabilities" + where + " ORDER BY COALESCE(cvss,0) DESC,cve LIMIT ? OFFSET ?", args + [limit, (page - 1) * limit])]
    return {"results": rows, "page": page, "per_page": limit, "total": total,
            "evidence_note": "Host matches require explicit correlation evidence; imported CVE records alone do not establish host vulnerability."}


@router.post("/admin/vulnerabilities/import")
def import_vulnerabilities(payload: VulnerabilityImport, request: Request):
    _admin(request)
    now = utc_now(); count = 0
    with connection() as db:
        for record in payload.records:
            cve = _valid_cve(str(record.get("cve", "")))
            score = record.get("cvss")
            try: score = float(score) if score is not None else None
            except (ValueError, TypeError): score = None
            if score is not None and not 0 <= score <= 10: score = None
            exploited = bool(record.get("known_exploited", False))
            db.execute("""INSERT INTO vulnerabilities(cve,description,cvss,severity,known_exploited,source,updated_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(cve) DO UPDATE SET description=excluded.description,cvss=excluded.cvss,
                severity=excluded.severity,known_exploited=excluded.known_exploited,source=excluded.source,updated_at=excluded.updated_at""",
                (cve, str(record.get("description", ""))[:10000], score, str(record.get("severity", ""))[:20], int(exploited), payload.source, now))
            count += 1
    return {"imported": count, "source": payload.source, "updated_at": now}


@router.get("/admin/api-keys")
def list_api_keys(request: Request):
    _admin(request)
    with connection() as db:
        rows = [dict(r) for r in db.execute("SELECT id,name,scopes,created_at,last_used_at,revoked_at FROM api_keys ORDER BY id DESC")]
    for row in rows: row["scopes"] = json.loads(row["scopes"])
    return {"keys": rows}


@router.post("/admin/api-keys")
def create_api_key(payload: KeyCreate, request: Request):
    _admin(request)
    allowed = {"search:read", "host:read", "analytics:read"}
    if not payload.scopes or any(scope not in allowed for scope in payload.scopes):
        raise HTTPException(422, "API keys may only receive read-only scopes")
    token = "sl_" + secrets.token_urlsafe(36)
    with connection() as db:
        cur = db.execute("INSERT INTO api_keys(name,key_hash,scopes,created_at) VALUES(?,?,?,?)",
                         (payload.name, _key_hash(token), json.dumps(sorted(set(payload.scopes))), utc_now()))
        key_id = cur.lastrowid
    return {"id": key_id, "name": payload.name, "token": token, "scopes": sorted(set(payload.scopes)),
            "message": "Copy this token now; it will not be shown again."}


@router.post("/admin/api-keys/{key_id}/revoke")
def revoke_api_key(key_id: int, request: Request):
    _admin(request)
    with connection() as db:
        cur = db.execute("UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at=''", (utc_now(), key_id))
        if cur.rowcount != 1: raise HTTPException(404, "Active API key not found")
    return {"revoked": True, "id": key_id}


@router.post("/admin/monitor/targets")
def create_monitor(payload: MonitorCreate, request: Request):
    _admin(request)
    try:
        network = ipaddress.ip_network(payload.target, strict=False)
    except ValueError:
        try: ipaddress.ip_address(payload.target); network = ipaddress.ip_network(payload.target, strict=False)
        except ValueError as exc: raise HTTPException(422, "Monitoring target must be an IP or CIDR") from exc
    with connection() as db:
        auth = db.execute("SELECT * FROM authorizations WHERE id=? AND enabled=1", (payload.authorization_id,)).fetchone()
        if not auth: raise HTTPException(403, "An enabled target authorization is required")
        authorized = ipaddress.ip_network(auth["cidr"], strict=False)
        if network.version != authorized.version or not network.subnet_of(authorized):
            raise HTTPException(403, "Monitor target is outside its authorized scope")
        cur = db.execute("INSERT INTO monitor_targets(name,target,authorization_id,created_at) VALUES(?,?,?,?)",
                         (payload.name, str(network), payload.authorization_id, utc_now()))
    return {"id": cur.lastrowid, "name": payload.name, "target": str(network), "enabled": True}


@router.get("/admin/monitor/targets")
def list_monitors(request: Request):
    _admin(request)
    with connection() as db:
        targets = [dict(r) for r in db.execute("SELECT * FROM monitor_targets ORDER BY id DESC")]
        events = [dict(r) for r in db.execute("SELECT * FROM monitor_events ORDER BY id DESC LIMIT 200")]
    for event in events: event["details"] = json.loads(event["details"])
    return {"targets": targets, "events": events}


@router.get("/admin/monitor/events")
def monitor_events(request: Request, page: int = Query(1, ge=1)):
    _admin(request)
    with connection() as db:
        total = db.execute("SELECT COUNT(*) FROM monitor_events").fetchone()[0]
        rows = [dict(r) for r in db.execute("SELECT * FROM monitor_events ORDER BY id DESC LIMIT 100 OFFSET ?", ((page - 1) * 100,))]
    for row in rows: row["details"] = json.loads(row["details"])
    return {"results": rows, "page": page, "per_page": 100, "total": total}


@router.post("/admin/saved-searches")
def save_search(payload: SavedSearchCreate, request: Request):
    _admin(request)
    now = utc_now()
    with connection() as db:
        cur = db.execute("INSERT INTO saved_searches(name,query,created_at,updated_at) VALUES(?,?,?,?)", (payload.name, payload.query, now, now))
    return {"id": cur.lastrowid, "name": payload.name, "query": payload.query, "created_at": now}


@router.get("/admin/saved-searches")
def saved_searches(request: Request):
    _admin(request)
    with connection() as db:
        return {"searches": [dict(r) for r in db.execute("SELECT * FROM saved_searches ORDER BY updated_at DESC") ]}


@router.get("/analytics/summary")
def analytics_summary(request: Request):
    # Public aggregates disclose only indexed observation counts/distributions.
    with connection() as db:
        countries = [dict(r) for r in db.execute("SELECT country,COUNT(*) hosts FROM hosts WHERE country!='' GROUP BY country ORDER BY hosts DESC LIMIT 50")]
        ports = [dict(r) for r in db.execute("SELECT port,COUNT(DISTINCT host_ip) hosts FROM services GROUP BY port ORDER BY hosts DESC LIMIT 50")]
        products = [dict(r) for r in db.execute("SELECT product,COUNT(DISTINCT host_ip) hosts FROM services WHERE product!='' GROUP BY product ORDER BY hosts DESC LIMIT 50")]
        days = [dict(r) for r in db.execute("SELECT substr(seen_at,1,10) day,COUNT(*) observations,COUNT(DISTINCT ip) hosts FROM observations GROUP BY day ORDER BY day DESC LIMIT 180")]
        totals = {"hosts": db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0], "observations": db.execute("SELECT COUNT(*) FROM observations").fetchone()[0], "services": db.execute("SELECT COUNT(*) FROM services").fetchone()[0]}
    return {"totals": totals, "countries": countries, "ports": ports, "products": products, "daily": list(reversed(days)), "source": "indexed database observations"}


@router.get("/reports/export.csv")
def export_csv():
    buffer = io.StringIO(); writer = csv.writer(buffer)
    writer.writerow(["ip", "port", "protocol", "service", "product", "source", "observed_at"])
    with connection() as db:
        rows = db.execute("SELECT ip,port,proto,service,product,source,seen_at FROM observations ORDER BY seen_at DESC LIMIT 100000")
        writer.writerows(rows)
    buffer.seek(0)
    return StreamingResponse(iter([buffer.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=scanlattice-observations.csv"})
