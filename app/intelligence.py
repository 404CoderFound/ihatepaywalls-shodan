"""Additional data-backed intelligence APIs for the v1.0 development line."""
from __future__ import annotations

import csv
import asyncio
import gzip
import hashlib
import ipaddress
import io
import json
import os
import re
import secrets
import re
import shutil
import time
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from .database import connection, utc_now
from . import database as database_module
from .ingestion import iter_dataset_records, normalize_record
from .vulnerability_feeds import _provider_state, correlate_all, upsert_vulnerabilities, update_kev, update_nvd
from .monitoring import _validate_public_https

router = APIRouter(prefix="/api", tags=["intelligence"])

MAX_IMPORT_CHUNK = int(os.getenv("MAX_IMPORT_CHUNK_BYTES", str(8 * 1024 * 1024)))
MAX_IMPORT_BYTES = int(os.getenv("MAX_IMPORT_BYTES", str(20 * 1024 * 1024 * 1024)))


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
    alert_types: list[str] = Field(default_factory=lambda:["service_observed","software_changed","service_disappeared","certificate_expiring","certificate_changed","vulnerability_new"],max_length=12)
    cooldown_seconds: int = Field(default=900,ge=60,le=604800)


class MonitorDestinationCreate(BaseModel):
    name: str = Field(min_length=2,max_length=100)
    kind: str = Field(pattern="^(webhook|email)$")
    endpoint: str = Field(min_length=4,max_length=2048)


class SavedSearchCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    query: str = Field(min_length=1, max_length=500)


class DNSImport(BaseModel):
    records: list[dict] = Field(min_length=1, max_length=5000)
    source: str = Field(min_length=2, max_length=120)
    method: str = Field(pattern="^(dataset|passive_dataset|certificate_transparency)$")


def _store_host_identity(db, host: dict, source: str) -> None:
    import ipaddress
    from .database import utc_now
    from .main import store
    address=ipaddress.ip_address(host["ip"]);now=host.get("observed_at") or utc_now()
    asn=host.get("asn","");org=host.get("org","");network_prefix=""
    if not asn:
        best=None
        for route in db.execute("SELECT prefix,asn,organization FROM routing_prefixes WHERE expires_at IS NULL OR expires_at>?",(int(time.time()),)):
            try:
                network=ipaddress.ip_network(route["prefix"],strict=False)
                if address.version==network.version and address in network and (best is None or network.prefixlen>best[0]):best=(network.prefixlen,route,network)
            except ValueError:continue
        if best:
            _,route,network=best;asn=route["asn"];org=org or route["organization"];network_prefix=str(network)
    if asn and not network_prefix:
        route=db.execute("SELECT prefix FROM routing_prefixes WHERE asn=? AND (expires_at IS NULL OR expires_at>?) ORDER BY length(prefix) DESC LIMIT 1",(asn,int(time.time()))).fetchone()
        if route:network_prefix=route[0]
    db.execute("""INSERT INTO hosts(ip,hostname,asn,org,country,first_seen,last_seen,last_scan_at,network_prefix,source,ip_version,ip_hex,os_name)
      VALUES(?,?,?,?,?,?,?,'',?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
      hostname=CASE WHEN excluded.hostname!='' THEN excluded.hostname ELSE hosts.hostname END,
      asn=CASE WHEN excluded.asn!='' THEN excluded.asn ELSE hosts.asn END,
      org=CASE WHEN excluded.org!='' THEN excluded.org ELSE hosts.org END,
      country=CASE WHEN excluded.country!='' THEN excluded.country ELSE hosts.country END,
      first_seen=MIN(hosts.first_seen,excluded.first_seen),last_seen=MAX(hosts.last_seen,excluded.last_seen),
      network_prefix=CASE WHEN excluded.network_prefix!='' THEN excluded.network_prefix ELSE hosts.network_prefix END,
      os_name=CASE WHEN excluded.os_name!='' THEN excluded.os_name ELSE hosts.os_name END,
      source=excluded.source""",(host["ip"],host.get("hostname", ""),asn,org,host.get("country", ""),now,now,network_prefix,source,address.version,f"{int(address):032x}",host.get("os_name", "")))
    for hostname in host.get("hostnames",[]):
        if hostname:
            db.execute("INSERT INTO hostnames(ip,hostname,source,first_seen,last_seen) VALUES(?,?,?,?,?) ON CONFLICT(ip,hostname,source) DO UPDATE SET last_seen=MAX(hostnames.last_seen,excluded.last_seen)",(host["ip"],hostname,source,now,now))


def _process_dataset_import(import_id: str) -> dict:
    with connection() as db:
        run=db.execute("SELECT * FROM dataset_import_runs WHERE id=?",(import_id,)).fetchone()
        if not run:raise ValueError("Import run does not exist")
        if run["uploaded_bytes"]!=run["total_bytes"]:raise ValueError("Upload is incomplete")
        db.execute("UPDATE dataset_import_runs SET status='processing',error='',updated_at=? WHERE id=?",(utc_now(),import_id))
        source,fmt,encoding,path,processed=run["source"],run["format"],run["encoding"],Path(run["spool_path"]),run["records_processed"]
    from .main import Observation, store
    pending=[];row_number=0
    try:
        for record in iter_dataset_records(path,fmt,encoding):
            row_number+=1
            if row_number<=processed:continue
            host,observations=normalize_record(record,source)
            if not observations:host["observed_at"]=""
            pending.append((row_number,host,observations))
            if len(pending)>=250:
                processed=_commit_import_batch(import_id,pending,processed,Observation,store,source);pending=[]
        if pending:processed=_commit_import_batch(import_id,pending,processed,Observation,store,source)
        with connection() as db:
            db.execute("UPDATE dataset_import_runs SET status='completed',records_processed=?,error='',updated_at=? WHERE id=?",(processed,utc_now(),import_id))
        correlate_all()
        return {"id":import_id,"status":"completed","records_processed":processed}
    except Exception as exc:
        with connection() as db:db.execute("UPDATE dataset_import_runs SET status='partial',records_processed=?,error=?,updated_at=? WHERE id=?",(processed,str(exc)[:1000],utc_now(),import_id))
        return {"id":import_id,"status":"partial","records_processed":processed,"error":str(exc)[:1000]}


def _commit_import_batch(import_id, batch, prior, Observation, store, source):
    count=prior
    with connection() as db:
        for row_number,host,items in batch:
            mark=db.execute("INSERT OR IGNORE INTO dataset_import_records(import_id,row_number,observation_count) VALUES(?,?,?)",(import_id,row_number,len(items)))
            if mark.rowcount==0:continue
            if items:store(db,[Observation(**item) for item in items],source)
            else:_store_host_identity(db,host,source)
            # Preserve secondary hostnames when a host has one or more services.
            if items:
                for hostname in host.get("hostnames",[]):
                    db.execute("INSERT OR IGNORE INTO hostnames(ip,hostname,source,first_seen,last_seen) VALUES(?,?,?,?,?)",(host["ip"],hostname,source,items[0].get("observed_at") or utc_now(),items[0].get("observed_at") or utc_now()))
            count=max(count,row_number)
        db.execute("UPDATE dataset_import_runs SET records_processed=?,updated_at=? WHERE id=?",(count,utc_now(),import_id))
    return count


@router.post("/admin/datasets/imports")
async def upload_dataset_chunk(request: Request,
        x_import_id: str = Header(...),
        x_import_source: str = Header(...),
        x_import_format: str = Header(...),
        x_import_encoding: str = Header("identity"),
        content_range: str = Header(...)):
    """Upload raw file chunks; the exact durable byte offset is returned for resume."""
    _admin(request)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}",x_import_id):raise HTTPException(400,"Import id must be 1..80 safe characters")
    if x_import_format not in {"csv","json","jsonl"} or x_import_encoding not in {"identity","gzip"}:raise HTTPException(400,"Unsupported dataset format or encoding")
    match=re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)",content_range)
    if not match:raise HTTPException(400,"Content-Range must use bytes START-END/TOTAL")
    start,end,total=map(int,match.groups());expected=end-start+1
    if total<1 or total>MAX_IMPORT_BYTES or end>=total:raise HTTPException(413,"Dataset size exceeds configured limit or range is invalid")
    if expected<1 or expected>MAX_IMPORT_CHUNK:raise HTTPException(413,f"Chunk must not exceed {MAX_IMPORT_CHUNK} bytes")
    with connection() as db:
        run=db.execute("SELECT * FROM dataset_import_runs WHERE id=?",(x_import_id,)).fetchone()
        if run is None:
            if start!=0:raise HTTPException(409,"First import chunk must start at byte 0")
            spool_dir=database_module.DB_PATH.parent/"dataset-imports";spool_dir.mkdir(parents=True,exist_ok=True)
            path=spool_dir/(x_import_id+".upload")
            db.execute("INSERT INTO dataset_import_runs(id,source,format,encoding,total_bytes,status,spool_path,created_at,updated_at) VALUES(?,?,?,?,?,'uploading',?,?,?)",(x_import_id,x_import_source[:200],x_import_format,x_import_encoding,total,str(path),utc_now(),utc_now()))
            uploaded=0
        else:
            if (run["source"],run["format"],run["encoding"],run["total_bytes"])!=(x_import_source[:200],x_import_format,x_import_encoding,total):raise HTTPException(409,"Import metadata cannot change when resuming")
            if run["status"] not in {"uploading","partial"}:raise HTTPException(409,f"Import cannot accept data while status is {run['status']}")
            uploaded=run["uploaded_bytes"];path=Path(run["spool_path"])
        if start!=uploaded:raise HTTPException(409,f"Resume at byte offset {uploaded}")
    path.parent.mkdir(parents=True,exist_ok=True)
    mode="wb" if start==0 else "r+b";written=0
    try:
        with path.open(mode) as output:
            output.seek(start)
            async for chunk in request.stream():
                written+=len(chunk)
                if written>expected:raise HTTPException(413,"Chunk exceeded its Content-Range size")
                output.write(chunk)
            if written!=expected:raise HTTPException(400,f"Chunk length mismatch: expected {expected}, received {written}")
            output.truncate(end+1);output.flush();os.fsync(output.fileno())
    except Exception:
        if path.exists():
            with path.open("r+b") as output:output.truncate(start)
        raise
    uploaded=end+1;status="uploaded" if uploaded==total else "uploading"
    with connection() as db:db.execute("UPDATE dataset_import_runs SET uploaded_bytes=?,status=?,updated_at=? WHERE id=?",(uploaded,status,utc_now(),x_import_id))
    if uploaded<total:return JSONResponse({"id":x_import_id,"status":"uploading","uploaded_bytes":uploaded,"total_bytes":total,"resume_offset":uploaded},status_code=202)
    result=await asyncio.to_thread(_process_dataset_import,x_import_id)
    return JSONResponse({**result,"uploaded_bytes":uploaded,"total_bytes":total},status_code=200 if result["status"]=="completed" else 422)


@router.post("/admin/datasets/imports/{import_id}/resume")
async def resume_dataset_import(import_id: str, request: Request):
    _admin(request)
    with connection() as db:
        run=db.execute("SELECT uploaded_bytes,total_bytes,status FROM dataset_import_runs WHERE id=?",(import_id,)).fetchone()
        if not run:raise HTTPException(404,"Import run not found")
        if run["uploaded_bytes"]!=run["total_bytes"]:raise HTTPException(409,"Upload bytes are incomplete; resume by uploading from the returned offset")
        if run["status"] not in {"partial","uploaded"}:raise HTTPException(409,f"Import status does not allow processing retry: {run['status']}")
    result=await asyncio.to_thread(_process_dataset_import,import_id)
    return JSONResponse(result,status_code=200 if result["status"]=="completed" else 422)


@router.get("/admin/datasets/imports")
def list_dataset_imports(request: Request):
    _admin(request)
    with connection() as db:
        rows=[dict(r) for r in db.execute("SELECT id,source,format,encoding,total_bytes,uploaded_bytes,records_processed,status,error,created_at,updated_at FROM dataset_import_runs ORDER BY created_at DESC LIMIT 200")]
    return {"imports":rows}


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
    for row in rows:
        row["http"]=json.loads(row.pop("http_json") or "{}")
        row["tls"]=json.loads(row.pop("tls_json") or "{}")
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
        rows = [dict(r) for r in db.execute("SELECT v.*, (SELECT COUNT(DISTINCT host_ip) FROM host_vulnerability_matches m WHERE m.cve=v.cve) affected_hosts FROM vulnerabilities v" + where.replace("cve", "v.cve").replace("description", "v.description").replace("severity", "v.severity") + " ORDER BY COALESCE(cvss,0) DESC,cve LIMIT ? OFFSET ?", args + [limit, (page - 1) * limit])]
    for row in rows:row["cpes"]=json.loads(row.pop("cpes_json") or "[]")
    return {"results": rows, "page": page, "per_page": limit, "total": total,
            "evidence_note": "Host matches require explicit correlation evidence; imported CVE records alone do not establish host vulnerability."}


@router.post("/admin/vulnerabilities/import")
def import_vulnerabilities(payload: VulnerabilityImport, request: Request):
    _admin(request)
    now = utc_now(); records=[]
    for record in payload.records:
        cve=_valid_cve(str(record.get("cve","")));score=record.get("cvss")
        try:score=float(score) if score is not None else None
        except (ValueError,TypeError):score=None
        if score is not None and not 0<=score<=10:score=None
        cpes=record.get("cpes",[])
        cpes=[{"criteria":item,"vulnerable":True} if isinstance(item,str) else item for item in cpes if isinstance(item,(str,dict))]
        records.append({"cve":cve,"description":str(record.get("description",""))[:10000],"cvss":score,"severity":str(record.get("severity",""))[:20],"known_exploited":bool(record.get("known_exploited",False)),"cpes":cpes,"updated_at":now})
    count=upsert_vulnerabilities(records,payload.source)
    return {"imported": count, "source": payload.source, "updated_at": now}


class VulnerabilityRefresh(BaseModel):
    providers: list[str] = Field(default_factory=lambda:["nvd","kev"],min_length=1,max_length=2)
    modified_since: str = Field(default="",max_length=40)
    max_pages: int = Field(default=20,ge=1,le=1000)


@router.post("/admin/vulnerabilities/refresh")
async def refresh_vulnerabilities(payload: VulnerabilityRefresh, request: Request):
    _admin(request)
    if any(provider not in {"nvd","kev"} for provider in payload.providers):raise HTTPException(422,"Supported feeds are nvd and kev")
    outcomes=[]
    for provider in payload.providers:
        try:
            if provider=="kev":outcome=await asyncio.to_thread(update_kev)
            else:outcome=await asyncio.to_thread(update_nvd,modified_since=payload.modified_since or None,max_pages=payload.max_pages,page_delay=6.2 if not os.getenv("NVD_API_KEY") else 0.7)
            outcomes.append({**outcome,"status":"completed"})
        except Exception as exc:outcomes.append({"source":provider.upper(),"status":"failed","error":str(exc)[:500]})
        if outcomes[-1]["status"]=="failed":_provider_state("cisa_kev" if provider=="kev" else "nvd","failed",0,outcomes[-1]["error"])
    return {"providers":outcomes,"completed":sum(1 for item in outcomes if item["status"]=="completed"),"failed":sum(1 for item in outcomes if item["status"]=="failed")}


@router.get("/admin/vulnerabilities/providers")
def vulnerability_provider_status(request: Request):
    _admin(request)
    with connection() as db:
        states=[dict(r) for r in db.execute("SELECT * FROM intelligence_provider_state ORDER BY provider")]
        cursor=db.execute("SELECT provider,window_start,window_end,next_index,total_results,updated_at FROM vulnerability_feed_cursors").fetchone()
    return {"providers":states,"nvd_cursor":dict(cursor) if cursor else None,"automatic_refresh_enabled":os.getenv("VULNERABILITY_AUTO_REFRESH","false").lower() in {"1","true","yes"}}


@router.get("/vulnerabilities/stats")
def vulnerability_stats():
    with connection() as db:
        total=db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        exploited=db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE known_exploited=1").fetchone()[0]
        matches=db.execute("SELECT COUNT(DISTINCT host_ip||':'||cve) FROM host_vulnerability_matches").fetchone()[0]
        by_severity=[dict(r) for r in db.execute("SELECT UPPER(severity) severity,COUNT(*) total FROM vulnerabilities GROUP BY UPPER(severity) ORDER BY total DESC")]
    return {"total_cves":total,"known_exploited":exploited,"potential_host_matches":matches,"by_severity":by_severity}


@router.get("/vulnerabilities/{cve}")
def vulnerability_detail(cve: str, page: int=Query(1,ge=1)):
    cve=_valid_cve(cve)
    with connection() as db:
        record=db.execute("SELECT * FROM vulnerabilities WHERE cve=?",(cve,)).fetchone()
        if not record:raise HTTPException(404,"Vulnerability not found")
        total=db.execute("SELECT COUNT(*) FROM host_vulnerability_matches WHERE cve=?",(cve,)).fetchone()[0]
        hosts=[dict(r) for r in db.execute("SELECT m.host_ip,m.confidence,m.evidence_json,m.source,m.observed_at,h.asn,h.org FROM host_vulnerability_matches m JOIN hosts h ON h.ip=m.host_ip WHERE m.cve=? ORDER BY m.observed_at DESC LIMIT 50 OFFSET ?",(cve,(page-1)*50))]
    value=dict(record);value["cpes"]=json.loads(value.pop("cpes_json") or "[]")
    for host in hosts:host["evidence"]=json.loads(host.pop("evidence_json"))
    return {"vulnerability":value,"potential_host_matches":hosts,"matches_total":total,"page":page,"per_page":50,"evidence_limit":"Product/version CPE correlation is potential evidence, not confirmed exploitability."}


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
        allowed_types={"service_observed","software_changed","service_disappeared","certificate_expiring","certificate_changed","vulnerability_new"}
        if any(event not in allowed_types for event in payload.alert_types):raise HTTPException(422,"Unsupported monitoring event type")
        cur = db.execute("INSERT INTO monitor_targets(name,target,authorization_id,created_at,alert_types_json,cooldown_seconds) VALUES(?,?,?,?,?,?)",
                         (payload.name, str(network), payload.authorization_id, utc_now(),json.dumps(sorted(set(payload.alert_types))),payload.cooldown_seconds))
    return {"id": cur.lastrowid, "name": payload.name, "target": str(network), "enabled": True}


@router.get("/admin/monitor/targets")
def list_monitors(request: Request):
    _admin(request)
    with connection() as db:
        targets = [dict(r) for r in db.execute("SELECT * FROM monitor_targets ORDER BY id DESC")]
        events = [dict(r) for r in db.execute("SELECT * FROM monitor_events ORDER BY id DESC LIMIT 200")]
    for event in events: event["details"] = json.loads(event["details"])
    return {"targets": targets, "events": events}


@router.post("/admin/monitor/destinations")
def create_monitor_destination(payload: MonitorDestinationCreate, request: Request):
    _admin(request)
    endpoint=payload.endpoint.strip()
    if payload.kind=="webhook":
        try:_validate_public_https(endpoint)
        except ValueError as exc:raise HTTPException(422,str(exc)) from exc
    else:
        address=parseaddr(endpoint)[1]
        if not address or "@" not in address or any(c in address for c in "\r\n"):
            raise HTTPException(422,"Email destination is invalid")
    with connection() as db:
        cur=db.execute("INSERT INTO monitor_destinations(name,kind,endpoint,created_at) VALUES(?,?,?,?)",(payload.name,payload.kind,endpoint,utc_now()))
    return {"id":cur.lastrowid,"name":payload.name,"kind":payload.kind,"enabled":True}


@router.get("/admin/monitor/destinations")
def list_monitor_destinations(request: Request):
    _admin(request)
    with connection() as db:
        destinations=[dict(r) for r in db.execute("SELECT id,name,kind,endpoint,enabled,created_at FROM monitor_destinations ORDER BY id DESC")]
        delivery=[dict(r) for r in db.execute("SELECT status,COUNT(*) count FROM monitor_notifications GROUP BY status")]
    return {"destinations":destinations,"notification_status":delivery,"scheduler_enabled":os.getenv("MONITORING_AUTO_CHECKS","false").lower() in {"1","true","yes"}}


@router.get("/admin/monitor/notifications")
def list_monitor_notifications(request: Request, page: int=Query(1,ge=1)):
    _admin(request)
    with connection() as db:
        total=db.execute("SELECT COUNT(*) FROM monitor_notifications").fetchone()[0]
        rows=[dict(r) for r in db.execute("""SELECT n.id,n.event_id,n.destination_id,n.status,n.attempts,n.next_attempt_at,n.delivered_at,n.error,
          d.name destination_name,d.kind,e.ip,e.event_type,e.created_at event_created
          FROM monitor_notifications n JOIN monitor_destinations d ON d.id=n.destination_id
          JOIN monitor_events e ON e.id=n.event_id ORDER BY n.id DESC LIMIT 100 OFFSET ?""",((page-1)*100,))]
    return {"results":rows,"page":page,"per_page":100,"total":total}


@router.post("/admin/monitor/notifications/{notification_id}/retry")
def retry_monitor_notification(notification_id: int, request: Request):
    _admin(request)
    with connection() as db:
        cur=db.execute("UPDATE monitor_notifications SET status='queued',next_attempt_at=0,error='' WHERE id=? AND status='failed'",(notification_id,))
        if cur.rowcount!=1:raise HTTPException(404,"Failed notification not found")
    return {"id":notification_id,"status":"queued"}


@router.get("/admin/monitor/events")
def monitor_events(request: Request, page: int = Query(1, ge=1)):
    _admin(request)
    with connection() as db:
        total = db.execute("SELECT COUNT(*) FROM monitor_events").fetchone()[0]
        rows = [dict(r) for r in db.execute("SELECT * FROM monitor_events ORDER BY id DESC LIMIT 100 OFFSET ?", ((page - 1) * 100,))]
    for row in rows: row["details"] = json.loads(row["details"])
    return {"results": rows, "page": page, "per_page": 100, "total": total}


@router.post("/admin/monitor/events/{event_id}/acknowledge")
def acknowledge_monitor_event(event_id: int, request: Request):
    _admin(request)
    with connection() as db:
        cur=db.execute("UPDATE monitor_events SET acknowledged_at=? WHERE id=? AND acknowledged_at=''",(utc_now(),event_id))
        if cur.rowcount!=1:raise HTTPException(404,"Unacknowledged monitor event not found")
    return {"id":event_id,"acknowledged":True}


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


@router.delete("/admin/saved-searches/{search_id}")
def delete_saved_search(search_id: int, request: Request):
    _admin(request)
    with connection() as db:
        cur=db.execute("DELETE FROM saved_searches WHERE id=?",(search_id,))
        if cur.rowcount!=1:raise HTTPException(404,"Saved search not found")
    return {"deleted":True,"id":search_id}


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
