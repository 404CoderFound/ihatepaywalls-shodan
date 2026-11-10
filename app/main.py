"""ScanLattice control plane. Active network operations are intentionally absent."""
from __future__ import annotations

import csv, hashlib, hmac, io, ipaddress, json, math, os, secrets, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import unquote
from fastapi import Body, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.datastructures import Headers
from .database import connection, init_db, upsert_host_identity, utc_now
from .search import QueryError, parse_query
from .host_search import asn_intelligence, search_hosts
from .passive import APPROVED_RDAP_BASES, provider_status, search_cached
from .enrichment import enrichment_target, ensure_enrichment, queue_job, recover_pending, run_due_schedules_once, start_schedule_runner
from .rate_limit import FixedWindowLimiter
from .intelligence import MAX_IMPORT_BYTES, MAX_IMPORT_CHUNK, router as intelligence_router
from .monitoring import create_event, start_scheduler as start_monitoring_scheduler
from .result_batches import BatchUpload, BatchFinish, accept_batch, finish_batches
from .index_scheduler import (
    create_refresh_request, get_refresh_request, list_generations, list_refresh_requests,
    list_tasks, sync_generation_states,
)

ROOT=Path(__file__).resolve().parent
ADMIN_TOKEN=os.getenv("ADMIN_TOKEN",""); ENROLLMENT_TOKEN=os.getenv("ENROLLMENT_TOKEN","")
SEED_DEMO=os.getenv("SEED_DEMO","false").lower()=="true"
OFFLINE=int(os.getenv("WORKER_OFFLINE_SECONDS","45")); LEASE=int(os.getenv("JOB_LEASE_SECONDS","90"))
MAX_TARGETS=int(os.getenv("MAX_JOB_TARGETS","4096")); MAX_PORTS=int(os.getenv("MAX_JOB_PORTS","100"))
PUBLIC_RATE_LIMIT=int(os.getenv("PUBLIC_RATE_LIMIT","60")); LOGIN_RATE_LIMIT=int(os.getenv("LOGIN_RATE_LIMIT","5"))
SESSION_SECONDS=int(os.getenv("ADMIN_SESSION_SECONDS","28800")); COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE","true").lower()=="true"
ENRICHMENT_ENABLED=os.getenv("PASSIVE_ENRICHMENT_ENABLED","true").lower()=="true"
MAX_ENRICHMENT_QUEUE=int(os.getenv("MAX_ENRICHMENT_QUEUE","100"))
MAX_SCREENSHOT_BYTES=int(os.getenv("MAX_SCREENSHOT_BYTES",str(5*1024*1024)))
MAX_CAMPAIGN_TARGETS=int(os.getenv("MAX_CAMPAIGN_TARGETS","65536"));MAX_BATCH_TARGETS=int(os.getenv("MAX_BATCH_TARGETS","256"))
MAX_REFRESH_TARGETS=int(os.getenv("MAX_REFRESH_TARGETS","256"))
MAX_REFRESH_CHECKS=int(os.getenv("MAX_REFRESH_CHECKS","25600"))
V2_SCHEDULER_WORKER_SENTINEL="__scanlattice_v2_scheduler__"
RATE_LIMITER=FixedWindowLimiter()
app=FastAPI(title="ScanLattice API",version="1.0.0",docs_url=None,redoc_url=None)
app.include_router(intelligence_router)
app.mount("/static",StaticFiles(directory=ROOT/"static"),name="static")

@app.middleware("http")
async def bounded(request:Request,call_next):
    screenshot_path=request.url.path.startswith("/api/admin/hosts/") and request.url.path.endswith("/screenshots")
    body_limit=int(os.getenv("MAX_IMPORT_CHUNK_BYTES",str(8*1024*1024))) if request.url.path=="/api/admin/datasets/imports" else MAX_SCREENSHOT_BYTES if screenshot_path else int(os.getenv("MAX_BODY_BYTES",str(2*1024*1024)))
    if int(request.headers.get("content-length","0"))>body_limit:
        return JSONResponse({"detail":"Request body too large"},413)
    identity=request.client.host if request.client else "unknown"
    request.state.api_scopes=[]
    authorization=request.headers.get("authorization","")
    api_token=authorization[7:] if authorization.lower().startswith("bearer ") else request.headers.get("x-api-key","")
    if api_token:
        with connection() as db:
            key=db.execute("SELECT id,scopes FROM api_keys WHERE key_hash=? AND revoked_at=''",(digest(api_token),)).fetchone()
            if key is None:return JSONResponse({"detail":"Invalid API key"},401)
            request.state.api_scopes=json.loads(key["scopes"])
            identity="api-key:"+str(key["id"])
            db.execute("UPDATE api_keys SET last_used_at=? WHERE id=?",(utc_now(),key["id"]))
        path=request.url.path
        required_scope=("analytics:read" if path.startswith(("/api/analytics/","/api/reports/")) else
                        "host:read" if path.startswith(("/api/hosts/","/api/domains/")) else
                        "search:read" if path.startswith(("/api/search","/api/vulnerabilities")) else None)
        if required_scope and required_scope not in request.state.api_scopes:
            return JSONResponse({"detail":f"API key requires {required_scope} scope"},403)
    public_path=request.url.path.startswith("/api/") and not request.url.path.startswith(("/api/admin/","/api/worker/")) and request.url.path not in {"/api/docs","/api/health"}
    if public_path:
        allowed,remaining=RATE_LIMITER.allow("public",identity,PUBLIC_RATE_LIMIT)
        if not allowed:return JSONResponse({"detail":"Public API rate limit exceeded"},429,headers={"Retry-After":"60","X-RateLimit-Remaining":"0"})
    elif request.url.path=="/api/admin/session" and request.method=="POST":
        allowed,remaining=RATE_LIMITER.allow("login",identity,LOGIN_RATE_LIMIT)
        if not allowed:return JSONResponse({"detail":"Login rate limit exceeded"},429,headers={"Retry-After":"60"})
    else:remaining=None
    session_token=request.cookies.get("scanlattice_session")
    session=None
    supplied_admin_header=request.headers.get("x-admin-token")
    header_authenticated=bool(ADMIN_TOKEN and supplied_admin_header and hmac.compare_digest(supplied_admin_header,ADMIN_TOKEN))
    if request.url.path.startswith("/api/admin/") and supplied_admin_header and not header_authenticated:
        return JSONResponse({"detail":"Invalid admin credentials"},401)
    if session_token:
        now=int(time.time())
        with connection() as db:
            session=db.execute("SELECT * FROM admin_sessions WHERE token_hash=? AND expires_at>?",(digest(session_token),now)).fetchone()
            db.execute("DELETE FROM admin_sessions WHERE expires_at<=?",(now,))
            if session:db.execute("UPDATE admin_sessions SET last_seen=? WHERE token_hash=?",(now,digest(session_token)))
        if session and request.url.path.startswith("/api/admin"):
            if not header_authenticated and request.method not in {"GET","HEAD","OPTIONS"} and request.url.path!="/api/admin/session":
                csrf=request.headers.get("x-csrf-token","")
                if not csrf or not hmac.compare_digest(digest(csrf),session["csrf_hash"]):return JSONResponse({"detail":"CSRF validation failed"},403)
            if "x-admin-token" not in request.headers:
                request.scope["headers"].append((b"x-admin-token",ADMIN_TOKEN.encode()))
                request._headers=Headers(scope=request.scope)
    request.state.admin_authenticated=bool(session) or header_authenticated
    response=await call_next(request)
    if remaining is not None:response.headers["X-RateLimit-Remaining"]=str(remaining)
    return response

def digest(value:str)->str:return hashlib.sha256(value.encode()).hexdigest()
def secret(given:str|None,expected:str,label:str):
    if not expected: raise HTTPException(503,f"{label} is not configured")
    if not given or not hmac.compare_digest(given,expected): raise HTTPException(401,"Invalid credentials")
def admin(token:str|None):secret(token,ADMIN_TOKEN,"Admin token")
def worker(db,token:str|None):
    row=db.execute("SELECT * FROM workers WHERE token_hash=?",(digest(token or ""),)).fetchone()
    if row is None: raise HTTPException(401,"Invalid worker credentials")
    return row
def audit(db,action:str,details:dict,actor="admin"):
    db.execute("INSERT INTO audit_logs(action,actor,details,created_at) VALUES(?,?,?,?)",(action,actor,json.dumps(details),utc_now()))

@app.on_event("startup")
def startup():
    init_db(SEED_DEMO)
    if ENRICHMENT_ENABLED:recover_pending();start_schedule_runner()
    from .vulnerability_feeds import start_scheduled_refresh
    start_scheduled_refresh()
    start_monitoring_scheduler()
@app.get("/")
def home():return FileResponse(ROOT/"static"/"index.html")
@app.get("/api/health")
def health():return {"status":"ok","role":"control-plane","active_scanning":False,"passive_enrichment":ENRICHMENT_ENABLED,"host_page_size":10,"version":"1.0.0"}
@app.get("/api/stats")
def stats():
    with connection() as db:return {"observations":db.execute("SELECT COUNT(*) FROM observations").fetchone()[0],"services":db.execute("SELECT COUNT(*) FROM services").fetchone()[0],"hosts":db.execute("SELECT COUNT(*) FROM (SELECT ip FROM hosts UNION SELECT ip FROM passive_records WHERE ip!='')").fetchone()[0],"passive_records":db.execute("SELECT COUNT(*) FROM passive_records").fetchone()[0],"workers_online":db.execute("SELECT COUNT(*) FROM workers WHERE last_seen>?",(int(time.time())-OFFLINE,)).fetchone()[0],"demo_enabled":SEED_DEMO}

@app.get("/api/search")
def search(q:str=Query("",max_length=500),page:int=Query(1,ge=1),prefix_page:int=Query(1,ge=1),metadata_page:int=Query(1,ge=1),limit:int=Query(10,ge=1,le=100),sort:str=Query("last_seen",pattern="^(last_seen|first_seen|ip)$")):
    try: parsed=parse_query(q)
    except QueryError as exc:raise HTTPException(400,str(exc)) from exc
    should_queue=False;enrichment_job=None
    with connection() as db:
        host_page=search_hosts(db,parsed,page,sort,limit)
        passive=search_cached(db,parsed)
        enrichment_job,should_queue=ensure_enrichment(db,parsed,ENRICHMENT_ENABLED,MAX_ENRICHMENT_QUEUE)
        enrichment=provider_status(db)
        asn_values=parsed.filters.get("asn",[])
        asn_result=asn_intelligence(db,asn_values[0],prefix_page,metadata_page) if len(asn_values)==1 else None
    if should_queue and enrichment_job:queue_job(enrichment_job["id"])
    facets={"ports":{str(row["port"]):row["hosts"] for row in host_page["facets"]["ports"]},
            "countries":{row["country"]:row["hosts"] for row in host_page["facets"]["countries"]},
            "products":{row["product"]:row["hosts"] for row in host_page["facets"]["products"]}}
    passive_total=len(passive);metadata_per_page=25;metadata_start=(metadata_page-1)*metadata_per_page
    passive_page=[] if asn_result else passive[metadata_start:metadata_start+metadata_per_page]
    return {"query":q,"sort":sort,**{key:host_page[key] for key in ("page","per_page","total","total_pages","has_next","has_previous","range_start","range_end")},"pages":host_page["total_pages"],"results":host_page["hosts"],"hosts":host_page["hosts"],"indexed_observations":host_page["hosts"],"passive_total":passive_total,"passive_intelligence":passive_page,"passive_pagination":{"page":metadata_page,"per_page":metadata_per_page,"total":passive_total,"total_pages":math.ceil(passive_total/metadata_per_page) if passive_total else 0,"has_next":metadata_start+metadata_per_page<passive_total},"asn_intelligence":asn_result,"has_information":bool(host_page["total"] or passive or asn_result),"message":None if host_page["total"] or passive or asn_result else "No indexed or passive information available.","enrichment":dict(enrichment_job) if enrichment_job else enrichment,"facets":facets}

@app.get("/api/enrichment/{job_id}")
def enrichment_status(job_id:str):
    with connection() as db:job=db.execute("SELECT * FROM enrichment_jobs WHERE id=?",(job_id,)).fetchone()
    if job is None:raise HTTPException(404,"Enrichment job not found")
    return dict(job)

@app.get("/api/hosts/{ip}")
def host(ip:str):
    try:ipaddress.ip_address(ip)
    except ValueError as exc:raise HTTPException(400,"Invalid IP") from exc
    with connection() as db:
        h=db.execute("SELECT * FROM hosts WHERE ip=?",(ip,)).fetchone(); rows=[dict(r) for r in db.execute("SELECT * FROM observations WHERE ip=? ORDER BY seen_at DESC,port",(ip,))];passive=[dict(r) for r in db.execute("SELECT * FROM passive_records WHERE ip=? ORDER BY observed_at DESC",(ip,))];matches=[dict(r) for r in db.execute("SELECT cve,confidence,evidence_json,source,observed_at FROM host_vulnerability_matches WHERE host_ip=? ORDER BY observed_at DESC",(ip,))]
    for row in passive:row["value"]=json.loads(row.pop("value_json"))
    if not rows and not passive and not h:raise HTTPException(404,"No indexed or passive information available")
    for row in rows:
        row["http"]=json.loads(row.pop("http_json") or "{}")
        row["tls"]=json.loads(row.pop("tls_json") or "{}")
    for row in matches:row["evidence"]=json.loads(row.pop("evidence_json"))
    latest={}
    for r in rows:latest.setdefault((r["port"],r["proto"]),r)
    return {"host":dict(h) if h else {"ip":ip,"last_scan_at":""},"services":rows,"latest_by_port":list(latest.values()),"passive_intelligence":passive,"potential_vulnerabilities":matches}

def _route_inventory():
    # FastAPI's deferred router inclusion stores intelligence routes in the
    # included APIRouter until lifespan setup. Include them explicitly here so
    # the published route inventory is complete both before and after startup.
    routes=[*app.routes,*intelligence_router.routes]
    seen=set();inventory=[]
    for route in routes:
        path=getattr(route,"path","");methods=getattr(route,"methods",None)
        if not path.startswith("/api/") or not methods:continue
        methods=sorted(method for method in methods if method not in {"HEAD","OPTIONS"})
        key=(path,tuple(methods))
        if key in seen:continue
        seen.add(key)
        inventory.append({"path":path,"methods":methods,"authorization":"administrator" if path.startswith("/api/admin/") else "worker token" if path.startswith("/api/worker/") else "public read or scoped read-only API key"})
    return inventory

@app.get("/api/docs")
def docs():return {
    "version":"1.0.0",
    "authentication":{"public":"No credentials required for public search and catalog reads","admin_browser":"HttpOnly SameSite=Strict session cookie; X-CSRF-Token on mutations","admin_api":"X-Admin-Token","read_api_key":"Authorization: Bearer <key> or X-API-Key; scoped read-only","worker":"X-Worker-Token"},
    "rate_limits":{"public":"PUBLIC_RATE_LIMIT requests per client per fixed minute window (default 60)","login":"LOGIN_RATE_LIMIT attempts per client per fixed minute window (default 5)"},
    "search":{"syntax":["port:443","asn:AS30925","country:NL",'org:"Example Organization"',"domain:example.org","hostname:edge.example.org","net:192.0.2.0/24","service:ssh","product:OpenSSH","os:Linux","http.title:admin","http.headers:server","ssl.cert.subject.cn:example.org","ssl.cert.issuer.cn:Example CA","cpe:cpe:2.3:a:vendor:product:1.2:*:*:*:*:*:*:*","vuln:CVE-2024-0001","after:2025-01-01","before:2025-12-31","port:22 OR port:443","port:22 -country:US"],"pagination":"GET /api/search accepts page, limit (1..100), sort (last_seen, first_seen, ip); result includes total and facets"},
    "provenance":"Indexed observations and passive intelligence are separate. Each record retains source and observation time; passive port metadata is never exposed as a service banner.",
    "endpoints":{
        "public_read":["GET /api/search","GET /api/hosts/{ip}","GET /api/hosts/{ip}/observations","GET /api/domains/{domain}","GET /api/stats","GET /api/enrichment/{id}","GET /api/analytics/summary","GET /api/reports/export.csv","GET /api/vulnerabilities","GET /api/vulnerabilities/stats","GET /api/vulnerabilities/{cve}"],
        "admin_session":["POST /api/admin/session","GET /api/admin/session","POST /api/admin/session/logout"],
        "admin_control":["GET/POST /api/admin/authorizations","GET /api/admin/hosts/{ip}/authorization","POST /api/admin/hosts/{ip}/screenshots","GET /api/admin/screenshots","GET /api/admin/screenshots/{id}/content","GET/POST /api/admin/jobs","POST /api/admin/jobs/{id}/cancel","GET/POST /api/admin/refresh-requests","GET /api/admin/refresh-requests/{id}","GET /api/admin/scan-generations","GET /api/admin/scan-tasks","POST /api/admin/scan-generations/{id}/cancel","GET /api/admin/workers","POST /api/admin/passive/providers","PUT /api/admin/passive/providers/{id}","POST /api/admin/datasets/imports (Content-Range chunk upload)","POST /api/admin/datasets/imports/{id}/resume","POST /api/admin/vulnerabilities/refresh","GET /api/admin/vulnerabilities/providers","GET/POST /api/admin/monitor/targets","GET/POST /api/admin/monitor/destinations","POST /api/admin/monitor/run-once","GET /api/admin/monitor/events","GET /api/admin/monitor/notifications","POST /api/admin/monitor/notifications/{id}/retry","POST /api/admin/monitor/events/{id}/acknowledge","GET/POST /api/admin/api-keys","GET/POST /api/admin/saved-searches"],
        "worker":["POST /api/worker/register","POST /api/worker/heartbeat","GET /api/worker/jobs/next","POST /api/worker/jobs/{id}/results"]
    },
    "dataset_import":{"formats":["CSV","JSON array or object","JSONL"],"encoding":["identity","gzip"],"maximum_bytes":MAX_IMPORT_BYTES,"maximum_chunk_bytes":MAX_IMPORT_CHUNK,"resume":"Reuse the import id and continue at the returned byte offset; failed parsing can be retried with POST /api/admin/datasets/imports/{id}/resume"}
    ,"route_inventory":_route_inventory()
}

class SessionLogin(BaseModel):
    admin_token:str=Field(min_length=1,max_length=500)

@app.post("/api/admin/session")
def session_login(p:SessionLogin,response:Response):
    admin(p.admin_token);token=secrets.token_urlsafe(48);csrf=secrets.token_urlsafe(32);now=int(time.time())
    with connection() as db:
        db.execute("INSERT INTO admin_sessions(token_hash,csrf_hash,created_at,expires_at,last_seen) VALUES(?,?,?,?,?)",(digest(token),digest(csrf),now,now+SESSION_SECONDS,now));audit(db,"admin.session_created",{},"administrator")
    response.set_cookie("scanlattice_session",token,max_age=SESSION_SECONDS,httponly=True,secure=COOKIE_SECURE,samesite="strict",path="/")
    return {"authenticated":True,"csrf_token":csrf,"expires_at":now+SESSION_SECONDS}

@app.get("/api/admin/session")
def session_status(request:Request):
    return {"authenticated":bool(request.state.admin_authenticated)}

@app.post("/api/admin/session/logout")
def session_logout(request:Request,response:Response,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    token=request.cookies.get("scanlattice_session")
    if token:
        with connection() as db:db.execute("DELETE FROM admin_sessions WHERE token_hash=?",(digest(token),))
    response.delete_cookie("scanlattice_session",path="/",secure=COOKIE_SECURE,samesite="strict")
    return {"authenticated":False}

class Registration(BaseModel):
    name:str=Field(min_length=1,max_length=80); capabilities:list[str]=Field(default_factory=list,max_length=20); version:str=Field(default="legacy",max_length=40); max_concurrent:int=Field(default=1,ge=1,le=16)
@app.post("/api/worker/register")
def register(p:Registration,x_enrollment_token:Annotated[str|None,Header()]=None):
    secret(x_enrollment_token,ENROLLMENT_TOKEN,"Enrollment token"); wid=secrets.token_hex(12); token=secrets.token_urlsafe(48)
    with connection() as db:
        db.execute("INSERT INTO workers(id,name,token_hash,capabilities,version,max_concurrent,created_at,last_seen) VALUES(?,?,?,?,?,?,?,?)",(wid,p.name,digest(token),json.dumps(p.capabilities),p.version,p.max_concurrent,utc_now(),int(time.time())));audit(db,"worker.enrolled",{"worker_id":wid,"name":p.name},"enrollment")
    return {"worker_id":wid,"worker_token":token,"heartbeat_seconds":10}

class Heartbeat(BaseModel):
    cpu_pct:float=Field(ge=0,le=100);memory_pct:float=Field(ge=0,le=100);active_jobs:int=Field(default=0,ge=0,le=100);version:str=Field(default="",max_length=40);capabilities:list[str]|None=None;max_concurrent:int|None=Field(default=None,ge=1,le=16)

def schedule(db):
    now=int(time.time())
    revoked=db.execute("SELECT j.id FROM scan_jobs j JOIN authorizations a ON a.id=j.authorization_id WHERE a.enabled=0 AND j.status IN ('queued','assigned','running')").fetchall()
    for row in revoked:
        db.execute("UPDATE scan_jobs SET status='cancelled',error='Target authorization revoked',lease_token=NULL,lease_expires_at=NULL,updated_at=?,completed_at=? WHERE id=?",(utc_now(),utc_now(),row["id"]))
    for j in db.execute("SELECT * FROM scan_jobs WHERE status IN ('assigned','running') AND lease_expires_at<?",(now,)).fetchall():
        status="failed" if j["attempts"]>=j["max_attempts"] else "queued"
        db.execute("UPDATE scan_jobs SET status=?,assigned_worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,error='Worker lease expired',updated_at=? WHERE id=?",(status,utc_now(),j["id"]))
        task=db.execute("SELECT id,attempt_count FROM scan_tasks WHERE scan_job_id=?",(j["id"],)).fetchone()
        if task and status=="queued":
            delay=min(300,5*(2**max(0,int(task["attempt_count"])-1)))
            db.execute("UPDATE scan_tasks SET available_at=?,error='Worker lease expired',updated_at=? WHERE id=?",(now+delay,utc_now(),task["id"]))
    workers=[dict(r) for r in db.execute("SELECT * FROM workers WHERE last_seen>?",(now-OFFLINE,))]
    for j in db.execute("SELECT * FROM scan_jobs WHERE status='queued' ORDER BY created_at").fetchall():
        task=db.execute("SELECT available_at FROM scan_tasks WHERE scan_job_id=?",(j["id"],)).fetchone()
        if task and task["available_at"]>now:continue
        choices=[]
        for w in workers:
            if "tcp-connect" not in json.loads(w["capabilities"]) or (j["requested_worker_id"] and j["requested_worker_id"]!=V2_SCHEDULER_WORKER_SENTINEL and j["requested_worker_id"]!=w["id"]):continue
            running=db.execute("SELECT COUNT(*) FROM scan_jobs WHERE assigned_worker_id=? AND status IN ('assigned','running')",(w["id"],)).fetchone()[0]
            if running<w["max_concurrent"]:choices.append((running*40+w["cpu_pct"]*.4+w["memory_pct"]*.2,w))
        if choices:
            w=min(choices,key=lambda x:x[0])[1]
            db.execute("UPDATE scan_jobs SET status='assigned',assigned_worker_id=?,attempts=attempts+1,lease_token=?,lease_expires_at=?,updated_at=? WHERE id=? AND status='queued'",(w["id"],secrets.token_urlsafe(24),now+LEASE,utc_now(),j["id"]))
    sync_generation_states(db)

@app.post("/api/worker/heartbeat")
def heartbeat(p:Heartbeat,x_worker_token:Annotated[str|None,Header()]=None):
    with connection() as db:
        w=worker(db,x_worker_token); fields=["cpu_pct=?","memory_pct=?","active_jobs=?","last_seen=?"]; vals=[p.cpu_pct,p.memory_pct,p.active_jobs,int(time.time())]
        if p.version:fields+=['version=?'];vals+=[p.version]
        if p.capabilities is not None:fields+=['capabilities=?'];vals+=[json.dumps(p.capabilities)]
        if p.max_concurrent is not None:fields+=['max_concurrent=?'];vals+=[p.max_concurrent]
        db.execute(f"UPDATE workers SET {','.join(fields)} WHERE id=?",vals+[w["id"]]);schedule(db);available=db.execute("SELECT COUNT(*) FROM scan_jobs WHERE assigned_worker_id=? AND status='assigned'",(w["id"],)).fetchone()[0]
    return {"status":"ok","jobs_available":available}

@app.post("/api/worker/jobs/claim")
def claim(x_worker_token:Annotated[str|None,Header()]=None):
    with connection() as db:
        w=worker(db,x_worker_token);schedule(db);rows=[dict(r) for r in db.execute("SELECT j.*,p.connect_timeout,p.banner_timeout,p.max_concurrency,p.rate_per_second,a.cidr authorization_cidr FROM scan_jobs j JOIN scan_profiles p ON p.id=j.profile_id JOIN authorizations a ON a.id=j.authorization_id AND a.enabled=1 WHERE j.assigned_worker_id=? AND j.status='assigned' ORDER BY j.created_at LIMIT ?",(w["id"],w["max_concurrent"]))]
    for r in rows:r["ports"]=json.loads(r["ports"])
    return {"jobs":rows}

@app.get("/api/worker/jobs")
def legacy_jobs(x_worker_token:Annotated[str|None,Header()]=None):
    """Keep v0.1 heartbeat-only agents connected until their container is upgraded."""
    with connection() as db:worker(db,x_worker_token)
    return {"jobs":[],"upgrade_required":True,"minimum_worker_version":"0.2.0"}

class LeaseAction(BaseModel):
    lease_token:str=Field(min_length=10,max_length=200);progress_done:int|None=Field(default=None,ge=0);error:str=Field(default="",max_length=1000)
def leased(db,jid,wid,token):
    j=db.execute("SELECT * FROM scan_jobs WHERE id=? AND assigned_worker_id=? AND lease_token=?",(jid,wid,token)).fetchone()
    if j is None or j["status"] in {"cancelled","completed","failed"} or (j["lease_expires_at"] or 0)<int(time.time()):raise HTTPException(409,"Job lease is invalid or expired")
    return j
@app.post("/api/worker/jobs/{jid}/start")
def start(jid:str,p:LeaseAction,x_worker_token:Annotated[str|None,Header()]=None):
    with connection() as db:
        w=worker(db,x_worker_token);j=leased(db,jid,w["id"],p.lease_token)
        if not db.execute("SELECT 1 FROM authorizations WHERE id=? AND enabled=1",(j["authorization_id"],)).fetchone():raise HTTPException(409,"Target authorization was revoked")
        db.execute("UPDATE scan_jobs SET status='running',started_at=COALESCE(started_at,?),updated_at=?,lease_expires_at=? WHERE id=?",(utc_now(),utc_now(),int(time.time())+LEASE,jid));sync_generation_states(db)
    return {"status":"running"}
@app.post("/api/worker/jobs/{jid}/progress")
def progress(jid:str,p:LeaseAction,x_worker_token:Annotated[str|None,Header()]=None):
    with connection() as db:w=worker(db,x_worker_token);j=leased(db,jid,w["id"],p.lease_token);db.execute("UPDATE scan_jobs SET progress_done=?,updated_at=?,lease_expires_at=? WHERE id=?",(min(p.progress_done or 0,j["progress_total"]),utc_now(),int(time.time())+LEASE,jid));sync_generation_states(db)
    return {"status":"ok"}

class Observation(BaseModel):
    ip:str;port:int=Field(ge=1,le=65535);proto:str=Field(default="tcp",pattern="^(tcp|udp)$");hostname:str=Field(default="",max_length=253);asn:str=Field(default="",max_length=40);org:str=Field(default="",max_length=160);country:str=Field(default="",max_length=8);service:str=Field(default="",max_length=80);product:str=Field(default="",max_length=160);banner:str=Field(default="",max_length=8192);source:str=Field(default="manual",max_length=200);http:dict[str,Any]=Field(default_factory=dict);tls:dict[str,Any]=Field(default_factory=dict);ssh_id:str=Field(default="",max_length=500);latency_ms:float|None=Field(default=None,ge=0,le=120000);observed_at:str=Field(default="",max_length=64);cpe:str=Field(default="",max_length=500);os_name:str=Field(default="",max_length=160)
class Results(BaseModel):
    lease_token:str;idempotency_key:str=Field(min_length=8,max_length=200);observations:list[Observation]=Field(default_factory=list,max_length=10000);completed_checks:int|None=Field(default=None,ge=0)

class PassiveRecord(BaseModel):
    subject:str=Field(min_length=1,max_length=500)
    subject_type:str=Field(pattern="^(ip|domain|asn|network)$")
    ip:str=Field(default="",max_length=64)
    domain:str=Field(default="",max_length=253)
    asn:str=Field(default="",max_length=40)
    org:str=Field(default="",max_length=200)
    network:str=Field(default="",max_length=80)
    record_type:str=Field(min_length=1,max_length=80)
    value:dict[str,Any]=Field(default_factory=dict)
    source:str=Field(min_length=2,max_length=200)
    observed_at:str=Field(default_factory=utc_now)
    ttl_seconds:int|None=Field(default=None,ge=60,le=31536000)

class PassiveImport(BaseModel):
    records:list[PassiveRecord]=Field(min_length=1,max_length=1000)

class DatasetPage(BaseModel):
    dataset_id:str=Field(min_length=2,max_length=120)
    source:str=Field(min_length=2,max_length=200)
    cursor:str=Field(default="",max_length=500)
    next_cursor:str=Field(default="",max_length=500)
    complete:bool=False
    observations:list[Observation]=Field(min_length=1,max_length=1000)

class ScheduleCreate(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    query:str=Field(min_length=1,max_length=500)
    interval_seconds:int=Field(ge=300,le=31536000)
    enabled:bool=True

class ProviderCreate(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    provider_type:str=Field(pattern="^(import|ripestat|rdap|passive_dns|certificate_transparency|shodan_internetdb)$")
    enabled:bool=False
    config:dict[str,Any]=Field(default_factory=dict)
    requests_per_minute:int=Field(default=10,ge=1,le=120)

class ProviderUpdate(BaseModel):
    enabled:bool
    requests_per_minute:int=Field(default=10,ge=1,le=120)

class ProfileCreate(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    ports:list[int]=Field(min_length=1,max_length=100)
    connect_timeout:float=Field(default=3,ge=.2,le=15)
    banner_timeout:float=Field(default=3,ge=.2,le=15)
    max_concurrency:int=Field(default=20,ge=1,le=50)
    rate_per_second:float=Field(default=20,ge=.1,le=1000)

def store(db,rows:list[Observation],source:str,jid=None,wid=None):
    now=utc_now()
    for r in rows:
        try:address=ipaddress.ip_address(r.ip)
        except ValueError as exc:raise HTTPException(400,f"Invalid IP: {r.ip}") from exc
        asn=r.asn.upper();asn=f"AS{int(asn.removeprefix('AS'))}" if asn.removeprefix("AS").isdigit() else asn;org=r.org;network_prefix=""
        matches=[]
        for prefix in db.execute("SELECT prefix,asn,organization FROM routing_prefixes WHERE expires_at IS NULL OR expires_at>?",(int(time.time()),)):
            try:
                network=ipaddress.ip_network(prefix["prefix"],strict=False)
                if address.version==network.version and address in network:matches.append((network.prefixlen,prefix,network))
            except ValueError:continue
        if matches:
            _,mapping,network=max(matches,key=lambda item:item[0]);network_prefix=str(network);asn=asn or mapping["asn"];org=org or mapping["organization"]
        previous=db.execute("SELECT service,product,tls_json FROM services WHERE host_ip=? AND port=? AND proto=?",(r.ip,r.port,r.proto)).fetchone()
        seen_at=r.observed_at or now
        fingerprint=hashlib.sha256(json.dumps([r.ip,r.port,r.proto,r.service,r.product,r.banner,source,seen_at],separators=(",",":"),sort_keys=True).encode()).hexdigest()
        observation=db.execute("INSERT INTO observations(ip,port,proto,hostname,asn,org,country,service,product,banner,source,seen_at,http_json,tls_json,ssh_id,latency_ms,scan_job_id,worker_id,observation_hash,cpe,os_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(r.ip,r.port,r.proto,r.hostname,asn,org,r.country.upper(),r.service,r.product,r.banner,source,seen_at,json.dumps(r.http),json.dumps(r.tls),r.ssh_id,r.latency_ms,jid,wid,fingerprint,r.cpe,r.os_name))
        db.execute("INSERT INTO hosts(ip,hostname,asn,org,country,first_seen,last_seen,last_scan_at,network_prefix,source,ip_version,ip_hex,os_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET hostname=CASE WHEN excluded.hostname!='' THEN excluded.hostname ELSE hosts.hostname END,asn=CASE WHEN excluded.asn!='' THEN excluded.asn ELSE hosts.asn END,org=CASE WHEN excluded.org!='' THEN excluded.org ELSE hosts.org END,country=CASE WHEN excluded.country!='' THEN excluded.country ELSE hosts.country END,first_seen=MIN(hosts.first_seen,excluded.first_seen),last_seen=MAX(hosts.last_seen,excluded.last_seen),last_scan_at=CASE WHEN excluded.last_scan_at!='' AND excluded.last_scan_at>hosts.last_scan_at THEN excluded.last_scan_at ELSE hosts.last_scan_at END,network_prefix=CASE WHEN excluded.network_prefix!='' THEN excluded.network_prefix ELSE hosts.network_prefix END,source=excluded.source,os_name=CASE WHEN excluded.os_name!='' THEN excluded.os_name ELSE hosts.os_name END",(r.ip,r.hostname,asn,org,r.country.upper(),seen_at,seen_at,seen_at if jid else "",network_prefix,source,address.version,f"{int(address):032x}",r.os_name))
        db.execute("INSERT INTO services(host_ip,port,proto,service,product,first_seen,last_seen,last_observation_id,source,banner,http_json,tls_json,cpe) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(host_ip,port,proto) DO UPDATE SET service=CASE WHEN excluded.last_seen>=services.last_seen THEN excluded.service ELSE services.service END,product=CASE WHEN excluded.last_seen>=services.last_seen THEN excluded.product ELSE services.product END,first_seen=MIN(services.first_seen,excluded.first_seen),last_seen=MAX(services.last_seen,excluded.last_seen),last_observation_id=CASE WHEN excluded.last_seen>=services.last_seen THEN excluded.last_observation_id ELSE services.last_observation_id END,source=CASE WHEN excluded.last_seen>=services.last_seen THEN excluded.source ELSE services.source END,banner=CASE WHEN excluded.last_seen>=services.last_seen THEN excluded.banner ELSE services.banner END,http_json=CASE WHEN excluded.last_seen>=services.last_seen THEN excluded.http_json ELSE services.http_json END,tls_json=CASE WHEN excluded.last_seen>=services.last_seen THEN excluded.tls_json ELSE services.tls_json END,cpe=CASE WHEN excluded.cpe!='' THEN excluded.cpe ELSE services.cpe END",(r.ip,r.port,r.proto,r.service,r.product,seen_at,seen_at,observation.lastrowid,source,r.banner,json.dumps(r.http),json.dumps(r.tls),r.cpe))
        if not previous or (previous["product"] != r.product and r.product) or (previous["service"] != r.service and r.service):
            event_type="service_observed" if not previous else "software_changed"
            details={"port":r.port,"protocol":r.proto,"service":r.service,"product":r.product,"previous_product":previous["product"] if previous else "","previous_service":previous["service"] if previous else ""}
            for monitor in db.execute("SELECT * FROM monitor_targets WHERE enabled=1"):
                try:scope=ipaddress.ip_network(monitor["target"],strict=False)
                except ValueError:continue
                if address.version==scope.version and address in scope:create_event(db,monitor,r.ip,event_type,details,source,seen_at)
        if previous:
            try:
                old_tls=json.loads(previous["tls_json"] or "{}");new_tls=r.tls
                def fingerprint(value):
                    cert=value.get("cert",value) if isinstance(value,dict) else {}
                    return cert.get("fingerprint_sha256") or cert.get("sha256_fingerprint") or cert.get("fingerprint") or ""
                old_fp,new_fp=fingerprint(old_tls),fingerprint(new_tls)
                if old_fp and new_fp and old_fp!=new_fp:
                    for monitor in db.execute("SELECT * FROM monitor_targets WHERE enabled=1"):
                        try:scope=ipaddress.ip_network(monitor["target"],strict=False)
                        except ValueError:continue
                        if address.version==scope.version and address in scope:create_event(db,monitor,r.ip,"certificate_changed",{"port":r.port,"protocol":r.proto,"previous_fingerprint":old_fp,"fingerprint":new_fp},source,seen_at)
            except (ValueError,AttributeError):pass
        if r.hostname:db.execute("INSERT INTO hostnames(ip,hostname,source,first_seen,last_seen) VALUES(?,?,?,?,?) ON CONFLICT(ip,hostname,source) DO UPDATE SET last_seen=excluded.last_seen",(r.ip,r.hostname.lower(),source,now,now))
    return len(rows)


def _notify_missing_batch_services(db, job):
    """Mirror v1 service-disappeared monitoring after a complete batched scan."""
    target = ipaddress.ip_network(job["target"], strict=False)
    ports = json.loads(job["ports"])
    start = f"{int(target.network_address):032x}"
    end = f"{int(target.broadcast_address):032x}"
    placeholders = ",".join("?" for _ in ports)
    prior_services = db.execute(
        f"SELECT s.host_ip,s.port,s.proto,s.service,s.product,s.last_seen "
        f"FROM services s JOIN hosts h ON h.ip=s.host_ip "
        f"WHERE h.ip_version=? AND h.ip_hex BETWEEN ? AND ? AND s.port IN ({placeholders})",
        [target.version, start, end, *ports],
    ).fetchall()
    seen = {(row["ip"], row["port"], row["proto"]) for row in db.execute(
        "SELECT DISTINCT ip,port,proto FROM observations WHERE scan_job_id=?", (job["id"],),
    ).fetchall()}
    monitors = [dict(row) for row in db.execute("SELECT * FROM monitor_targets WHERE enabled=1")]
    for service in prior_services:
        if (service["host_ip"], service["port"], service["proto"]) in seen:
            continue
        details = {"port": service["port"], "protocol": service["proto"],
                   "service": service["service"], "product": service["product"],
                   "last_observed_at": service["last_seen"], "scan_job_id": job["id"]}
        for monitor in monitors:
            if service["port"] in ports and ipaddress.ip_address(service["host_ip"]) in ipaddress.ip_network(monitor["target"], strict=False):
                create_event(db, monitor, service["host_ip"], "service_disappeared",
                             details, "active-scan", utc_now())



@app.get("/api/worker/jobs/{jid}/results/batches/status")
def result_batch_status(jid: str, x_worker_token: Annotated[str | None, Header()] = None):
    with connection() as db:
        w = worker(db, x_worker_token)
        job = db.execute("SELECT * FROM scan_jobs WHERE id=? AND assigned_worker_id=?", (jid, w["id"])).fetchone()
        if not job or job["status"] != "running" or (job["lease_expires_at"] or 0) < int(time.time()):
            raise HTTPException(409, "Job lease is invalid or expired")
        if not db.execute("SELECT 1 FROM authorizations WHERE id=? AND enabled=1",
                          (job["authorization_id"],)).fetchone():
            raise HTTPException(409, "Target authorization was revoked")
        state = db.execute("SELECT COUNT(*) AS batch_count,COALESCE(MAX(checks_done),0) AS checks_done "
                           "FROM scan_result_batches WHERE job_id=?", (jid,)).fetchone()
    return {"status": "running", "batch_count": state["batch_count"],
            "checks_done": state["checks_done"], "progress_total": job["progress_total"]}


@app.post("/api/worker/jobs/{jid}/results/batches")
def upload_result_batch(jid: str, p: BatchUpload, x_worker_token: Annotated[str | None, Header()] = None):
    with connection() as db:
        w = worker(db, x_worker_token)
        j = leased(db, jid, w["id"], p.lease_token)
        # Parse observations with the same validation rules as legacy v1.
        observations = [Observation.model_validate(item) for item in p.observations]
        result = accept_batch(db, j, w["id"], p.batch_index, p.checks_done, observations, store, LEASE)
        sync_generation_states(db)
    return result


@app.post("/api/worker/jobs/{jid}/results/complete")
def complete_result_batches(jid: str, p: BatchFinish, x_worker_token: Annotated[str | None, Header()] = None):
    with connection() as db:
        w = worker(db, x_worker_token)
        j = db.execute("SELECT * FROM scan_jobs WHERE id=? AND assigned_worker_id=?", (jid, w["id"])).fetchone()
        if j is None:
            raise HTTPException(409, "Job is not assigned to this worker")
        if j["status"] != "completed":
            j = leased(db, jid, w["id"], p.lease_token)
            if not db.execute("SELECT 1 FROM authorizations WHERE id=? AND enabled=1",
                              (j["authorization_id"],)).fetchone():
                raise HTTPException(409, "Target authorization was revoked")
        result = finish_batches(db, j, w["id"], p.batch_count, p.completed_checks,
                                _notify_missing_batch_services)
        sync_generation_states(db)
    return result


@app.post("/api/worker/jobs/{jid}/results")
def results(jid:str,p:Results,x_worker_token:Annotated[str|None,Header()]=None):
    with connection() as db:
        w=worker(db,x_worker_token);dup=db.execute("SELECT observation_count FROM result_uploads WHERE idempotency_key=?",(p.idempotency_key,)).fetchone()
        if dup:return {"status":"already_processed","indexed":dup[0]}
        j=leased(db,jid,w["id"],p.lease_token);auth=db.execute("SELECT cidr FROM authorizations WHERE id=? AND enabled=1",(j["authorization_id"],)).fetchone()
        if not auth:raise HTTPException(409,"Target authorization was revoked")
        target=ipaddress.ip_network(j["target"]);allowed=ipaddress.ip_network(auth[0]);ports=json.loads(j["ports"])
        if any(ipaddress.ip_address(r.ip) not in target or ipaddress.ip_address(r.ip) not in allowed or r.port not in ports for r in p.observations):raise HTTPException(400,"Result outside authorized job scope")
        if db.execute("SELECT 1 FROM scan_result_batches WHERE job_id=?", (jid,)).fetchone():
            raise HTTPException(409, "This job already uses batched result uploads")
        count=store(db,p.observations,"active-scan",jid,w["id"])
        if p.completed_checks is not None and p.completed_checks==j["progress_total"]:
            start=f"{int(target.network_address):032x}";end=f"{int(target.broadcast_address):032x}"
            placeholders=",".join("?" for _ in ports)
            prior_services=db.execute(f"SELECT s.host_ip,s.port,s.proto,s.service,s.product,s.last_seen FROM services s JOIN hosts h ON h.ip=s.host_ip WHERE h.ip_version=? AND h.ip_hex BETWEEN ? AND ? AND s.port IN ({placeholders})",[target.version,start,end,*ports]).fetchall()
            seen={(row.ip,row.port,row.proto) for row in p.observations}
            monitors=[dict(row) for row in db.execute("SELECT * FROM monitor_targets WHERE enabled=1")]
            for service in prior_services:
                if (service["host_ip"],service["port"],service["proto"]) in seen:continue
                details={"port":service["port"],"protocol":service["proto"],"service":service["service"],"product":service["product"],"last_observed_at":service["last_seen"],"scan_job_id":jid}
                for monitor in monitors:
                    if service["port"] in ports and ipaddress.ip_address(service["host_ip"]) in ipaddress.ip_network(monitor["target"],strict=False):create_event(db,monitor,service["host_ip"],"service_disappeared",details,"active-scan",utc_now())
        db.execute("INSERT INTO result_uploads VALUES(?,?,?,?,?)",(p.idempotency_key,jid,w["id"],utc_now(),count));db.execute("UPDATE scan_jobs SET status='completed',progress_done=progress_total,completed_at=?,updated_at=?,lease_expires_at=NULL,lease_token=NULL WHERE id=?",(utc_now(),utc_now(),jid));db.execute("UPDATE workers SET completed_jobs=completed_jobs+1 WHERE id=?",(w["id"],));sync_generation_states(db)
    return {"status":"completed","indexed":count}
@app.post("/api/worker/jobs/{jid}/fail")
def fail(jid:str,p:LeaseAction,x_worker_token:Annotated[str|None,Header()]=None):
    with connection() as db:
        w=worker(db,x_worker_token);j=leased(db,jid,w["id"],p.lease_token);task=db.execute("SELECT id,attempt_count FROM scan_tasks WHERE scan_job_id=?",(jid,)).fetchone();now=int(time.time());timestamp=utc_now()
        batched=bool(db.execute("SELECT 1 FROM scan_result_batches WHERE job_id=?",(jid,)).fetchone())
        if (task or batched) and j["attempts"]<j["max_attempts"]:
            delay=min(300,5*(2**max(0,int(j["attempts"])-1)))
            db.execute("UPDATE scan_jobs SET status='queued',assigned_worker_id=NULL,error=?,updated_at=?,completed_at=NULL,lease_expires_at=NULL,lease_token=NULL WHERE id=?",(p.error or "Worker reported failure; retry scheduled",timestamp,jid))
            db.execute("UPDATE scan_tasks SET available_at=?,error=?,updated_at=? WHERE id=?",(now+delay,p.error or "Worker reported failure; retry scheduled",timestamp,task["id"]))
            status="queued"
        else:
            db.execute("UPDATE scan_jobs SET status='failed',error=?,completed_at=?,updated_at=?,lease_expires_at=NULL,lease_token=NULL WHERE id=?",(p.error or "Worker reported failure",timestamp,timestamp,jid));status="failed"
        sync_generation_states(db)
    return {"status":status}

class ImportPayload(BaseModel):
    observations:list[Observation]=Field(min_length=1,max_length=1000);provenance:str=Field(default="administrator import",min_length=2,max_length=200)
@app.post("/api/admin/import")
def import_json(p:ImportPayload,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:count=store(db,p.observations,p.provenance);audit(db,"observations.imported",{"count":count,"provenance":p.provenance})
    return {"imported":count,"provenance":p.provenance}
@app.post("/api/admin/import/csv")
def import_csv(provenance:str=Query(...,min_length=2,max_length=200),body:bytes=Body(...,media_type="text/csv"),x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    try:rows=[Observation(**r) for r in csv.DictReader(io.StringIO(body.decode("utf-8-sig")))]
    except Exception as exc:raise HTTPException(400,f"Invalid CSV: {exc}") from exc
    if not 1<=len(rows)<=1000:raise HTTPException(400,"CSV must contain 1 to 1000 rows")
    with connection() as db:count=store(db,rows,provenance);audit(db,"observations.imported",{"count":count,"provenance":provenance,"format":"csv"})
    return {"imported":count,"provenance":provenance}

@app.post("/api/admin/passive/import")
def import_passive(p:PassiveImport,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token);now=int(time.time())
    with connection() as db:
        for row in p.records:
            if row.ip:
                try:ipaddress.ip_address(row.ip)
                except ValueError as exc:raise HTTPException(400,f"Invalid passive IP: {row.ip}") from exc
            if row.network:
                try:ipaddress.ip_network(row.network,strict=False)
                except ValueError as exc:raise HTTPException(400,f"Invalid passive network: {row.network}") from exc
            expires=now+row.ttl_seconds if row.ttl_seconds else None
            db.execute("""INSERT INTO passive_records(subject,subject_type,ip,domain,asn,org,network,record_type,value_json,source,observed_at,expires_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(subject,record_type,source,value_json) DO UPDATE SET observed_at=excluded.observed_at,expires_at=excluded.expires_at""",
              (row.subject,row.subject_type,row.ip,row.domain.lower(),row.asn.upper(),row.org,row.network,row.record_type,json.dumps(row.value,sort_keys=True),row.source,row.observed_at,expires))
            if row.network and row.asn:
                network=ipaddress.ip_network(row.network,strict=False);asn=row.asn.upper();asn=f"AS{int(asn.removeprefix('AS'))}" if asn.removeprefix("AS").isdigit() else asn
                db.execute("INSERT INTO routing_prefixes(prefix,asn,organization,source,first_seen,last_seen,expires_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(prefix,asn,source) DO UPDATE SET organization=excluded.organization,last_seen=excluded.last_seen,expires_at=excluded.expires_at",(str(network),asn,row.org,row.source,row.observed_at,row.observed_at,expires))
                for host in db.execute("SELECT ip,network_prefix FROM hosts").fetchall():
                    address=ipaddress.ip_address(host["ip"])
                    if address.version!=network.version or address not in network:continue
                    current=ipaddress.ip_network(host["network_prefix"],strict=False) if host["network_prefix"] else None
                    if current is None or network.prefixlen>=current.prefixlen:db.execute("UPDATE hosts SET asn=?,org=CASE WHEN ?!='' THEN ? ELSE org END,network_prefix=? WHERE ip=?",(asn,row.org,row.org,str(network),host["ip"]))
            if row.ip:
                value=row.value if isinstance(row.value,dict) else {}
                hostname=row.domain or str(value.get("hostname") or value.get("domain") or "")
                upsert_host_identity(db,row.ip,row.source,row.observed_at,hostname,row.asn,row.org,str(value.get("country_code") or "").upper())
        audit(db,"passive.imported",{"count":len(p.records),"sources":sorted({r.source for r in p.records})})
    return {"imported":len(p.records)}

@app.post("/api/admin/datasets/ingest")
def ingest_dataset_page(p:DatasetPage,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:
        state=db.execute("SELECT * FROM dataset_ingestions WHERE dataset_id=?",(p.dataset_id,)).fetchone()
        if state and state["status"]=="completed":return {"dataset_id":p.dataset_id,"status":"completed","imported":0,"cursor":state["cursor"],"deduplicated":True}
        if state and p.next_cursor and state["cursor"]==p.next_cursor:return {"dataset_id":p.dataset_id,"status":state["status"],"imported":0,"cursor":state["cursor"],"deduplicated":True}
        if state and state["cursor"]!=p.cursor:raise HTTPException(409,f"Expected cursor {state['cursor']!r}")
        before=db.execute("SELECT COUNT(*) FROM services").fetchone()[0];store(db,p.observations,p.source);after=db.execute("SELECT COUNT(*) FROM services").fetchone()[0]
        status="completed" if p.complete else "partial"
        db.execute("INSERT INTO dataset_ingestions(dataset_id,source,cursor,records_processed,status,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(dataset_id) DO UPDATE SET cursor=excluded.cursor,records_processed=dataset_ingestions.records_processed+excluded.records_processed,status=excluded.status,updated_at=excluded.updated_at",(p.dataset_id,p.source,p.next_cursor,len(p.observations),status,utc_now()))
        audit(db,"dataset.page_ingested",{"dataset_id":p.dataset_id,"records":len(p.observations),"new_services":after-before,"status":status})
    return {"dataset_id":p.dataset_id,"status":status,"imported":len(p.observations),"new_services":after-before,"next_cursor":p.next_cursor}

@app.post("/api/admin/indexing/schedules")
def create_index_schedule(p:ScheduleCreate,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    try:
        parsed=parse_query(p.query)
        if enrichment_target(parsed) is None:raise ValueError
    except (QueryError,ValueError) as exc:raise HTTPException(400,"Schedule query must identify one ASN, IP, CIDR, domain or hostname") from exc
    with connection() as db:
        cursor=db.execute("INSERT INTO indexing_schedules(name,query,interval_seconds,enabled,next_run_at,created_at) VALUES(?,?,?,?,?,?)",(p.name,p.query,p.interval_seconds,int(p.enabled),int(time.time()),utc_now()));audit(db,"indexing.schedule_created",{"id":cursor.lastrowid,"query":p.query})
    return {"id":cursor.lastrowid,"name":p.name,"query":p.query,"interval_seconds":p.interval_seconds,"enabled":p.enabled}

@app.get("/api/admin/indexing/schedules")
def list_index_schedules(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:rows=[dict(row) for row in db.execute("SELECT s.*,e.status job_status,e.providers_completed,e.providers_total,e.records_added,e.error job_error FROM indexing_schedules s LEFT JOIN enrichment_jobs e ON e.id=s.last_job_id ORDER BY s.id")]
    return {"schedules":rows}

@app.post("/api/admin/indexing/run-due")
def run_due_indexing(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token);return {"queued":run_due_schedules_once()}

@app.get("/api/admin/passive/providers")
def list_providers(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:rows=[dict(r) for r in db.execute("SELECT * FROM passive_providers ORDER BY name")]
    for row in rows:row["config"]=json.loads(row.pop("config_json"))
    return {"providers":rows}

@app.post("/api/admin/passive/providers")
def create_provider(p:ProviderCreate,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    if any(any(word in key.lower() for word in ("secret","token","password","api_key")) for key in p.config):raise HTTPException(400,"Store provider secrets in environment variables, not provider configuration")
    if p.provider_type=="rdap" and p.config.get("base_url","https://rdap.org/ip/") not in APPROVED_RDAP_BASES:raise HTTPException(400,"RDAP base URL is not on the approved provider allowlist")
    if p.provider_type=="shodan_internetdb" and p.enabled and os.getenv("SHODAN_INTERNETDB_NONCOMMERCIAL_CONSENT","false").lower() not in {"1","true","yes"}:raise HTTPException(403,"Enable SHODAN_INTERNETDB_NONCOMMERCIAL_CONSENT only after confirming applicable Shodan terms or a commercial license")
    now=utc_now()
    with connection() as db:
        try:cursor=db.execute("INSERT INTO passive_providers(name,provider_type,enabled,config_json,requests_per_minute,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",(p.name,p.provider_type,int(p.enabled),json.dumps(p.config),p.requests_per_minute,now,now))
        except Exception as exc:raise HTTPException(409,"Provider name already exists") from exc
        audit(db,"passive.provider_created",{"provider_id":cursor.lastrowid,"type":p.provider_type,"enabled":p.enabled})
    return {"id":cursor.lastrowid,"name":p.name,"provider_type":p.provider_type,"enabled":p.enabled}

@app.put("/api/admin/passive/providers/{provider_id}")
def update_provider(provider_id:int,p:ProviderUpdate,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:
        row=db.execute("SELECT provider_type FROM passive_providers WHERE id=?",(provider_id,)).fetchone()
        if row is None:raise HTTPException(404,"Provider not found")
        if row["provider_type"]=="shodan_internetdb" and p.enabled and os.getenv("SHODAN_INTERNETDB_NONCOMMERCIAL_CONSENT","false").lower() not in {"1","true","yes"}:raise HTTPException(403,"Enable SHODAN_INTERNETDB_NONCOMMERCIAL_CONSENT only after confirming applicable Shodan terms or a commercial license")
        db.execute("UPDATE passive_providers SET enabled=?,requests_per_minute=?,updated_at=? WHERE id=?",(int(p.enabled),p.requests_per_minute,utc_now(),provider_id));audit(db,"passive.provider_updated",{"provider_id":provider_id,"enabled":p.enabled,"requests_per_minute":p.requests_per_minute})
    return {"id":provider_id,"enabled":p.enabled,"requests_per_minute":p.requests_per_minute}

class AuthCreate(BaseModel):name:str=Field(min_length=2,max_length=100);cidr:str
@app.post("/api/admin/authorizations")
def create_auth(p:AuthCreate,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    try:net=ipaddress.ip_network(p.cidr,strict=False)
    except ValueError as exc:raise HTTPException(400,"Invalid CIDR") from exc
    with connection() as db:
        try:cur=db.execute("INSERT INTO authorizations(name,cidr,created_at) VALUES(?,?,?)",(p.name,str(net),utc_now()))
        except Exception as exc:raise HTTPException(409,"Authorization already exists") from exc
        audit(db,"authorization.created",{"id":cur.lastrowid,"cidr":str(net)})
    return {"id":cur.lastrowid,"name":p.name,"cidr":str(net),"enabled":True}
@app.get("/api/admin/authorizations")
def auths(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:return {"authorizations":[dict(r) for r in db.execute("SELECT * FROM authorizations ORDER BY id DESC")]}

@app.get("/api/admin/hosts/{ip}/authorization")
def host_authorization(ip:str,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    try:address=ipaddress.ip_address(ip)
    except ValueError as exc:raise HTTPException(400,"Invalid IP address") from exc
    with connection() as db:rows=[dict(row) for row in db.execute("SELECT id,name,cidr FROM authorizations WHERE enabled=1 ORDER BY id")]
    for row in rows:
        try:network=ipaddress.ip_network(row["cidr"],strict=False)
        except ValueError:continue
        if address.version==network.version and address in network:
            return {"authorized":True,"authorization_id":row["id"],"name":row["name"],"cidr":row["cidr"]}
    return {"authorized":False,"authorization_id":None,"name":None,"cidr":None}

def _require_authorized_indexed_host(db,address):
    host=db.execute("SELECT ip FROM hosts WHERE ip=?",(str(address),)).fetchone()
    if not host:raise HTTPException(404,"Screenshots can only be attached to an indexed host")
    for row in db.execute("SELECT id,cidr FROM authorizations WHERE enabled=1"):
        try:network=ipaddress.ip_network(row["cidr"],strict=False)
        except ValueError:continue
        if address.version==network.version and address in network:return row["id"]
    raise HTTPException(403,"A currently enabled authorization must cover this host")

@app.post("/api/admin/hosts/{ip}/screenshots")
async def upload_host_screenshot(ip:str,request:Request,
        x_screenshot_name:Annotated[str,Header(min_length=1,max_length=120)],
        x_screenshot_note:Annotated[str,Header(max_length=500)]="",
        x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    try:address=ipaddress.ip_address(ip)
    except ValueError as exc:raise HTTPException(400,"Invalid IP address") from exc
    declared=request.headers.get("content-type","").split(";",1)[0].lower()
    if declared not in {"image/png","image/jpeg"}:raise HTTPException(415,"Only PNG and JPEG screenshots are accepted")
    content=bytearray()
    async for chunk in request.stream():
        content.extend(chunk)
        if len(content)>MAX_SCREENSHOT_BYTES:raise HTTPException(413,"Screenshot exceeds the configured size limit")
    image=bytes(content)
    if not image:raise HTTPException(400,"Screenshot file is empty")
    valid=(declared=="image/png" and image.startswith(b"\x89PNG\r\n\x1a\n")) or (declared=="image/jpeg" and image.startswith(b"\xff\xd8\xff"))
    if not valid:raise HTTPException(415,"File contents do not match PNG or JPEG image data")
    filename=Path(unquote(x_screenshot_name).replace("\\","/")).name.strip()[:120] or "screenshot"
    with connection() as db:
        auth_id=_require_authorized_indexed_host(db,address)
        created=utc_now();checksum=hashlib.sha256(image).hexdigest()
        note=unquote(x_screenshot_note)[:500]
        cur=db.execute("INSERT INTO host_screenshots(ip,filename,media_type,sha256,image,note,created_at,created_by) VALUES(?,?,?,?,?,?,?,'admin')",(str(address),filename,declared,checksum,image,note,created))
        audit(db,"screenshot.uploaded",{"screenshot_id":cur.lastrowid,"ip":str(address),"authorization_id":auth_id,"sha256":checksum})
    return {"id":cur.lastrowid,"ip":str(address),"filename":filename,"media_type":declared,"sha256":checksum,"note":note,"created_at":created}

@app.get("/api/admin/screenshots")
def list_host_screenshots(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token);results=[]
    with connection() as db:
        rows=db.execute("SELECT id,ip,filename,media_type,sha256,note,created_at uploaded_at FROM host_screenshots ORDER BY id DESC LIMIT 500").fetchall()
        authorized=[dict(row) for row in db.execute("SELECT cidr FROM authorizations WHERE enabled=1")]
    for row in rows:
        address=ipaddress.ip_address(row["ip"])
        for scope in authorized:
            try:network=ipaddress.ip_network(scope["cidr"],strict=False)
            except ValueError:continue
            if address.version==network.version and address in network:
                results.append(dict(row));break
    return {"screenshots":results,"privacy":"Administrator-only; assets are listed and served only while covered by an enabled authorization.","maximum_bytes":MAX_SCREENSHOT_BYTES}

@app.get("/api/admin/screenshots/{screenshot_id}/content")
def get_host_screenshot(screenshot_id:int,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:
        row=db.execute("SELECT * FROM host_screenshots WHERE id=?",(screenshot_id,)).fetchone()
        if not row:raise HTTPException(404,"Screenshot not found")
        _require_authorized_indexed_host(db,ipaddress.ip_address(row["ip"]))
    return Response(content=row["image"],media_type=row["media_type"],headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff","Content-Disposition":f'inline; filename="{row["filename"]}"'})

@app.post("/api/admin/authorizations/{auth_id}/revoke")
def revoke_auth(auth_id:int,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:
        if db.execute("SELECT 1 FROM authorizations WHERE id=?",(auth_id,)).fetchone() is None:raise HTTPException(404,"Authorization not found")
        now=utc_now();db.execute("UPDATE authorizations SET enabled=0 WHERE id=?",(auth_id,));db.execute("UPDATE scan_jobs SET status='cancelled',error='Target authorization revoked',lease_token=NULL,lease_expires_at=NULL,updated_at=?,completed_at=? WHERE authorization_id=? AND status IN ('queued','assigned','running')",(now,now,auth_id));sync_generation_states(db);audit(db,"authorization.revoked",{"id":auth_id})
    return {"enabled":False}
@app.get("/api/admin/profiles")
def profiles(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:rows=[dict(r) for r in db.execute("SELECT * FROM scan_profiles ORDER BY id")]
    for r in rows:r["ports"]=[int(x) for x in r["ports"].split(",")]
    return {"profiles":rows}

@app.post("/api/admin/profiles")
def create_profile(p:ProfileCreate,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token);ports=sorted(set(p.ports))
    if any(not 1<=port<=65535 for port in ports):raise HTTPException(400,"Profile contains an invalid port")
    with connection() as db:
        try:cursor=db.execute("INSERT INTO scan_profiles(name,ports,connect_timeout,banner_timeout,max_concurrency,rate_per_second,created_at) VALUES(?,?,?,?,?,?,?)",(p.name,",".join(map(str,ports)),p.connect_timeout,p.banner_timeout,p.max_concurrency,p.rate_per_second,utc_now()))
        except Exception as exc:raise HTTPException(409,"Profile name already exists") from exc
        audit(db,"profile.created",{"profile_id":cursor.lastrowid,"name":p.name,"ports":ports})
    return {"id":cursor.lastrowid,"name":p.name,"ports":ports}

class JobCreate(BaseModel):target:str;profile_id:int;ports:list[int]|None=None;worker_id:str|None=None

class RefreshCreate(BaseModel):
    query:str=Field(min_length=1,max_length=500)
    profile_id:int
    ports:list[int]|None=Field(default=None,max_length=MAX_PORTS)

@app.post("/api/admin/refresh-requests",status_code=202)
def create_refresh(p:RefreshCreate,x_admin_token:Annotated[str|None,Header()]=None,
                   idempotency_key:Annotated[str|None,Header(alias="Idempotency-Key")]=None):
    admin(x_admin_token)
    with connection() as db:
        request=create_refresh_request(db,query=p.query,profile_id=p.profile_id,requested_ports=p.ports,
            idempotency_key=idempotency_key,requested_by="administrator",max_targets=MAX_REFRESH_TARGETS,max_ports=MAX_PORTS,max_checks=MAX_REFRESH_CHECKS)
        schedule(db)
        audit(db,"scan.refresh_requested",{"request_id":request["id"],"generation_id":request["generation"]["generation_id"],"query":p.query,"tasks":request["generation"]["task_count"]})
        request=get_refresh_request(db,request["id"])
    return request

@app.get("/api/admin/refresh-requests")
def refresh_requests(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:schedule(db);return {"requests":list_refresh_requests(db)}

@app.get("/api/admin/refresh-requests/{request_id}")
def refresh_request_status(request_id:str,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:schedule(db);return get_refresh_request(db,request_id)

@app.get("/api/admin/scan-generations")
def scan_generations(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:schedule(db);return {"generations":list_generations(db)}

@app.get("/api/admin/scan-tasks")
def scan_tasks(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:schedule(db);return {"tasks":list_tasks(db)}

@app.post("/api/admin/scan-generations/{generation_id}/cancel")
def cancel_generation(generation_id:str,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:
        generation=db.execute("SELECT id,status FROM scan_generations WHERE id=?",(generation_id,)).fetchone()
        if not generation:raise HTTPException(404,"Scan generation not found")
        if generation["status"] in {"completed","partial","failed","cancelled"}:raise HTTPException(409,"Generation is already terminal")
        now=utc_now()
        db.execute("UPDATE scan_jobs SET status='cancelled',updated_at=?,completed_at=?,lease_expires_at=NULL,lease_token=NULL WHERE id IN (SELECT scan_job_id FROM scan_tasks WHERE generation_id=?) AND status IN ('queued','assigned','running')",(now,now,generation_id))
        sync_generation_states(db)
        audit(db,"scan.generation_cancelled",{"generation_id":generation_id})
        request=db.execute("SELECT id FROM scan_refresh_requests WHERE generation_id=?",(generation_id,)).fetchone()
        result=get_refresh_request(db,request[0])
    return result

class DeepReconPreview(BaseModel):
    query:str=Field(min_length=1,max_length=500)
    profile_id:int
    ports:list[int]|None=None

class DeepReconLaunch(DeepReconPreview):
    targets:list[str]=Field(min_length=1,max_length=500)
@app.post("/api/admin/jobs")
def create_job(p:JobCreate,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    try:target=ipaddress.ip_network(p.target,strict=False)
    except ValueError as exc:raise HTTPException(400,"Target must be an IP address or CIDR") from exc
    if target.num_addresses>MAX_TARGETS:raise HTTPException(400,f"Target exceeds maximum of {MAX_TARGETS} addresses")
    with connection() as db:
        auth=next((r for r in db.execute("SELECT * FROM authorizations WHERE enabled=1") if target.subnet_of(ipaddress.ip_network(r["cidr"]))),None)
        if auth is None:raise HTTPException(403,"Target is not within an enabled authorization")
        profile=db.execute("SELECT * FROM scan_profiles WHERE id=?",(p.profile_id,)).fetchone()
        if profile is None:raise HTTPException(404,"Scan profile not found")
        ports=sorted(set(p.ports if p.ports is not None else [int(x) for x in profile["ports"].split(",")]))
        if not ports or len(ports)>MAX_PORTS or any(not 1<=x<=65535 for x in ports):raise HTTPException(400,"Invalid or excessive port selection")
        if p.worker_id and db.execute("SELECT 1 FROM workers WHERE id=?",(p.worker_id,)).fetchone() is None:raise HTTPException(404,"Worker not found")
        jid=str(uuid.uuid4());now=utc_now();db.execute("INSERT INTO scan_jobs(id,target,authorization_id,profile_id,ports,requested_worker_id,status,progress_total,created_at,updated_at) VALUES(?,?,?,?,?,?,'queued',?,?,?)",(jid,str(target),auth["id"],profile["id"],json.dumps(ports),p.worker_id,int(target.num_addresses)*len(ports),now,now));audit(db,"job.created",{"job_id":jid,"target":str(target),"ports":ports});schedule(db);job=dict(db.execute("SELECT * FROM scan_jobs WHERE id=?",(jid,)).fetchone())
    job["ports"]=ports;job.pop("lease_token",None);return job

def _deep_candidates(db,query:str)->tuple[str,list[str]]:
    try:parsed=parse_query(query)
    except QueryError as exc:raise HTTPException(400,str(exc)) from exc
    target=enrichment_target(parsed)
    if target is None:raise HTTPException(400,"Deep Recon requires one IP, CIDR, ASN, domain or hostname")
    kind,value=target
    if kind=="ip":return kind,[str(ipaddress.ip_network(value,strict=False))]
    if kind=="net":return kind,[str(ipaddress.ip_network(value,strict=False))]
    if kind=="asn":
        rows=db.execute("SELECT DISTINCT network FROM passive_records WHERE asn=? AND record_type='announced-prefix' AND network!='' ORDER BY network",(value.upper(),)).fetchall()
        return kind,[row[0] for row in rows]
    rows=db.execute("SELECT DISTINCT ip FROM passive_records WHERE domain=? AND ip!='' ORDER BY ip",(value.lower(),)).fetchall()
    return kind,[str(ipaddress.ip_network(row[0],strict=False)) for row in rows]

def _authorization_for(db,network):
    return next((row for row in db.execute("SELECT * FROM authorizations WHERE enabled=1") if network.subnet_of(ipaddress.ip_network(row["cidr"]))),None)

def _campaign_ports(profile,requested):
    ports=sorted(set(requested if requested is not None else [int(x) for x in profile["ports"].split(",")]))
    if not ports or len(ports)>MAX_PORTS or any(not 1<=p<=65535 for p in ports):raise HTTPException(400,"Invalid or excessive port selection")
    return ports

def _split_network(network):
    if network.num_addresses<=MAX_BATCH_TARGETS:return [network]
    extra=math.ceil(math.log2(network.num_addresses/MAX_BATCH_TARGETS));prefix=min(network.max_prefixlen,network.prefixlen+extra)
    return list(network.subnets(new_prefix=prefix))

@app.post("/api/admin/deep-recon/preview")
def deep_recon_preview(p:DeepReconPreview,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:
        profile=db.execute("SELECT * FROM scan_profiles WHERE id=?",(p.profile_id,)).fetchone()
        if profile is None:raise HTTPException(404,"Scan profile not found")
        ports=_campaign_ports(profile,p.ports);kind,candidates=_deep_candidates(db,p.query);items=[]
        for value in candidates:
            network=ipaddress.ip_network(value,strict=False);authorization=_authorization_for(db,network)
            items.append({"target":str(network),"addresses":int(network.num_addresses),"authorized":authorization is not None,"authorization":authorization["cidr"] if authorization else None,"batches":len(_split_network(network)) if authorization and network.num_addresses<=MAX_CAMPAIGN_TARGETS else 0})
    return {"query":p.query,"query_type":kind,"profile":{"id":profile["id"],"name":profile["name"],"ports":ports,"rate_per_second":profile["rate_per_second"]},"candidates":items,"target_count":sum(item["addresses"] for item in items if item["authorized"]),"estimated_connections":sum(item["addresses"] for item in items if item["authorized"])*len(ports),"notice":"Only explicitly authorized candidates may be selected. ASN prefixes are never automatically authorized."}

@app.post("/api/admin/deep-recon/launch")
def deep_recon_launch(p:DeepReconLaunch,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token);campaign_id=str(uuid.uuid4());now=utc_now()
    with connection() as db:
        profile=db.execute("SELECT * FROM scan_profiles WHERE id=?",(p.profile_id,)).fetchone()
        if profile is None:raise HTTPException(404,"Scan profile not found")
        ports=_campaign_ports(profile,p.ports);allowed_kind,available=_deep_candidates(db,p.query);available_networks={str(ipaddress.ip_network(x,strict=False)) for x in available}
        selected=[ipaddress.ip_network(x,strict=False) for x in p.targets]
        if any(str(network) not in available_networks for network in selected):raise HTTPException(400,"Selected target was not derived from the current search result")
        total=sum(int(network.num_addresses) for network in selected)
        if total>MAX_CAMPAIGN_TARGETS:raise HTTPException(400,f"Campaign exceeds maximum of {MAX_CAMPAIGN_TARGETS} addresses")
        batches=[]
        for network in selected:
            authorization=_authorization_for(db,network)
            if authorization is None:raise HTTPException(403,f"Target {network} is outside enabled authorizations")
            batches.extend((batch,authorization) for batch in _split_network(network))
        db.execute("INSERT INTO scan_campaigns(id,source_query,profile_id,status,target_count,job_count,created_at) VALUES(?,?,?,'queued',?,?,?)",(campaign_id,p.query,profile["id"],total,len(batches),now))
        job_ids=[]
        for batch,authorization in batches:
            job_id=str(uuid.uuid4());job_ids.append(job_id)
            db.execute("INSERT INTO scan_jobs(id,target,authorization_id,profile_id,ports,status,progress_total,created_at,updated_at) VALUES(?,?,?,?,?,'queued',?,?,?)",(job_id,str(batch),authorization["id"],profile["id"],json.dumps(ports),int(batch.num_addresses)*len(ports),now,now))
            db.execute("INSERT INTO campaign_jobs(campaign_id,job_id) VALUES(?,?)",(campaign_id,job_id))
        audit(db,"deep_recon.launched",{"campaign_id":campaign_id,"query":p.query,"jobs":len(job_ids),"addresses":total});schedule(db)
    return {"campaign_id":campaign_id,"status":"queued","job_ids":job_ids,"job_count":len(job_ids),"target_count":total,"query_type":allowed_kind}
@app.get("/api/admin/jobs")
def jobs(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:schedule(db);rows=[dict(r) for r in db.execute("SELECT j.*,w.name worker_name,p.name profile_name FROM scan_jobs j LEFT JOIN workers w ON w.id=j.assigned_worker_id JOIN scan_profiles p ON p.id=j.profile_id ORDER BY j.created_at DESC LIMIT 200")]
    for r in rows:r["ports"]=json.loads(r["ports"]);r.pop("lease_token",None)
    return {"jobs":rows}
@app.post("/api/admin/jobs/{jid}/cancel")
def cancel(jid:str,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:
        row=db.execute("SELECT status FROM scan_jobs WHERE id=?",(jid,)).fetchone()
        if row is None:raise HTTPException(404,"Job not found")
        if row["status"] not in {"queued","assigned","running"}:raise HTTPException(409,f"Cannot cancel a {row['status']} job")
        db.execute("UPDATE scan_jobs SET status='cancelled',updated_at=?,completed_at=?,lease_expires_at=NULL WHERE id=?",(utc_now(),utc_now(),jid));audit(db,"job.cancelled",{"job_id":jid})
    return {"status":"cancelled"}
@app.get("/api/admin/workers")
def workers(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:schedule(db);rows=[dict(r) for r in db.execute("SELECT id,name,capabilities,cpu_pct,memory_pct,active_jobs,completed_jobs,max_concurrent,version,created_at,last_seen,last_error FROM workers ORDER BY created_at DESC")];counts={r["assigned_worker_id"]:r["c"] for r in db.execute("SELECT assigned_worker_id,COUNT(*) c FROM scan_jobs WHERE status IN ('assigned','running') GROUP BY assigned_worker_id")}
    for r in rows:r["online"]=r["last_seen"]>int(time.time())-OFFLINE;r["capabilities"]=json.loads(r["capabilities"]);r["running_jobs"]=counts.get(r["id"],0)
    return {"workers":rows}

@app.post("/api/admin/workers/{worker_id}/rotate-token")
def rotate_worker_token(worker_id:str,x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token);new_token=secrets.token_urlsafe(48)
    with connection() as db:
        if db.execute("SELECT 1 FROM workers WHERE id=?",(worker_id,)).fetchone() is None:raise HTTPException(404,"Worker not found")
        db.execute("UPDATE workers SET token_hash=? WHERE id=?",(digest(new_token),worker_id));audit(db,"worker.credential_rotated",{"worker_id":worker_id})
    return {"worker_id":worker_id,"worker_token":new_token,"notice":"Update the worker state securely; the previous token is now invalid."}
@app.get("/api/admin/audit")
def logs(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    with connection() as db:return {"logs":[dict(r) for r in db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200")]}

@app.get("/api/admin/settings")
def settings(x_admin_token:Annotated[str|None,Header()]=None):
    admin(x_admin_token)
    return {"active_scanning_on_control_plane":False,"max_job_targets":MAX_TARGETS,"max_job_ports":MAX_PORTS,"job_lease_seconds":LEASE,"worker_offline_seconds":OFFLINE,"database":"sqlite","configuration_source":"environment"}
