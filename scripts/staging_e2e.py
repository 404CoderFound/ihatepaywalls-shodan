#!/usr/bin/env python3
"""Local-only, non-probing ScanLattice release E2E against an isolated staging app."""
from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "release_e2e_hosts.json"
PNG_1PX = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/FZkAAAAASUVORK5CYII=")


class LocalAPI:
    def __init__(self, base_url: str):
        parsed=urllib.parse.urlsplit(base_url)
        if parsed.scheme!="http" or parsed.hostname not in {"127.0.0.1","localhost","::1"}:
            raise SystemExit("Staging E2E refuses non-loopback URLs; use the isolated local staging port.")
        self.base=base_url.rstrip("/")
        self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self,method,path,*,payload=None,body=None,headers=None):
        actual_headers={"Accept":"application/json",**(headers or {})}
        if payload is not None:
            body=json.dumps(payload,separators=(",",":")).encode()
            actual_headers.setdefault("Content-Type","application/json")
        request=urllib.request.Request(self.base+path,data=body,headers=actual_headers,method=method)
        try:
            with self.opener.open(request,timeout=30) as response:
                content=response.read();status=response.status;response_headers=response.headers
        except urllib.error.HTTPError as exc:
            content=exc.read();status=exc.code;response_headers=exc.headers
        if "json" in response_headers.get("Content-Type",""):
            try:content=json.loads(content)
            except json.JSONDecodeError:pass
        return status,content,response_headers

    def expect(self,method,path,status=200,**kwargs):
        actual,result,_=self.call(method,path,**kwargs)
        if actual!=status:
            raise AssertionError(f"{method} {path}: expected HTTP {status}, got {actual}: {result!r}")
        return result


def main():
    base=os.getenv("STAGING_URL","http://127.0.0.1:18080")
    admin=os.getenv("STAGING_ADMIN_TOKEN","")
    enrollment=os.getenv("STAGING_ENROLLMENT_TOKEN","")
    if not admin or not enrollment:raise SystemExit("Set staging-only STAGING_ADMIN_TOKEN and STAGING_ENROLLMENT_TOKEN.")
    api=LocalAPI(base);admin_h={"X-Admin-Token":admin};run_id=uuid.uuid4().hex[:10]
    health=api.expect("GET","/api/health")
    assert health["version"]=="1.0.0" and health["active_scanning"] is False
    api.expect("GET","/api/docs")

    # Upload the labeled Shodan-shaped fixture in small chunks to exercise resume offsets.
    raw=FIXTURE.read_bytes();import_id="release-e2e-"+run_id;source="ScanLattice release E2E fixture "+run_id
    offset=0
    while offset<len(raw):
        end=min(offset+256,len(raw));chunk=raw[offset:end]
        status,result,_=api.call("POST","/api/admin/datasets/imports",body=chunk,headers={**admin_h,"X-Import-Id":import_id,"X-Import-Source":source,"X-Import-Format":"json","X-Import-Encoding":"identity","Content-Range":f"bytes {offset}-{end-1}/{len(raw)}","Content-Type":"application/octet-stream"})
        if status not in {200,202}:raise AssertionError(f"dataset chunk upload failed ({status}): {result!r}")
        offset=result.get("resume_offset",result.get("uploaded_bytes",end))
    assert result["status"]=="completed" and result["records_processed"]==2

    # Public search stays passive, supports advanced filters, and never creates scan jobs.
    prior_jobs={row["id"] for row in api.expect("GET","/api/admin/jobs",headers=admin_h)["jobs"]}
    query=urllib.parse.urlencode({"q":"asn:AS64496 port:443 http.title:\"Fixture Admin Console\""})
    indexed=api.expect("GET","/api/search?"+query)
    assert indexed["total"]==1 and indexed["hosts"][0]["ip"]=="198.51.100.40"
    by_asn=api.expect("GET","/api/search?"+urllib.parse.urlencode({"q":"asn:64496 ip:198.51.100.41"}))
    assert by_asn["total"]==1 and by_asn["hosts"][0]["services"]==[]
    assert api.expect("GET","/api/hosts/198.51.100.40")["latest_by_port"]
    assert api.expect("GET","/api/hosts/198.51.100.40/observations?page=1&limit=50")["total"]>=2

    # Add passive-only intelligence; no services or active scan jobs are fabricated.
    now=datetime.now(timezone.utc).isoformat(timespec="seconds")
    passive={"records":[{"subject":"203.0.113.71","subject_type":"ip","ip":"203.0.113.71","asn":"AS64497","org":"ScanLattice E2E Passive Fixture","network":"203.0.113.0/24","record_type":"rdap","value":{"handle":"E2E-NET-71"},"source":source+" RDAP","observed_at":now}]}
    api.expect("POST","/api/admin/passive/import",payload=passive,headers=admin_h)
    passive_search=api.expect("GET","/api/search?"+urllib.parse.urlencode({"q":"ip:203.0.113.71"}))
    assert passive_search["has_information"] and passive_search["passive_total"]>=1
    passive_host=api.expect("GET","/api/hosts/203.0.113.71")
    assert passive_host["services"]==[] and passive_host["passive_intelligence"]
    after_public_jobs={row["id"] for row in api.expect("GET","/api/admin/jobs",headers=admin_h)["jobs"]}
    assert after_public_jobs==prior_jobs,"Public search created an active scan job"

    # Create an enabled scope and verify session + CSRF handling, including the bad-header bypass regression.
    authorizations=api.expect("GET","/api/admin/authorizations",headers=admin_h)["authorizations"]
    auth=next((row for row in authorizations if row["cidr"]=="198.51.100.0/24" and row["enabled"]),None)
    if auth is None:
        auth=api.expect("POST","/api/admin/authorizations",payload={"name":"Release E2E TEST-NET scope","cidr":"198.51.100.0/24"},headers=admin_h)
    session=api.expect("POST","/api/admin/session",payload={"admin_token":admin})
    csrf=session["csrf_token"];csrf_h={"X-CSRF-Token":csrf}
    api.expect("POST","/api/admin/saved-searches",payload={"name":"Release E2E "+run_id,"query":"asn:AS64496"},headers=csrf_h)
    api.expect("POST","/api/admin/saved-searches",status=403,payload={"name":"Missing CSRF","query":"port:443"})
    api.expect("POST","/api/admin/saved-searches",status=401,payload={"name":"Bad header bypass","query":"port:443"},headers={"X-Admin-Token":"invalid-staging-header"})

    profiles=api.expect("GET","/api/admin/profiles",headers=admin_h)["profiles"]
    profile=next(row for row in profiles if row["name"]=="Quick Recon")
    # A fresh staging project has no workers: session-authorized jobs must stay queued.
    session_job=api.expect("POST","/api/admin/jobs",payload={"target":"198.51.100.97/32","profile_id":profile["id"],"ports":[9443]},headers=csrf_h)
    assert session_job["status"]=="queued", "Jobs must remain queued until a suitable registered worker heartbeats"
    assert api.expect("GET","/api/admin/hosts/198.51.100.40/authorization",headers=admin_h)["authorized"]
    api.expect("POST","/api/admin/jobs",status=403,payload={"target":"203.0.113.71/32","profile_id":profile["id"],"ports":[9443]},headers=admin_h)
    worker_name="release-e2e-worker-"+run_id
    worker=api.expect("POST","/api/worker/register",payload={"name":worker_name,"capabilities":["tcp-connect"],"version":"0.4.0","max_concurrent":1},headers={"X-Enrollment-Token":enrollment})
    wh={"X-Worker-Token":worker["worker_token"]}
    heartbeat=api.expect("POST","/api/worker/heartbeat",payload={"cpu_pct":2,"memory_pct":8,"active_jobs":0,"version":"0.4.0","capabilities":["tcp-connect"],"max_concurrent":1},headers=wh)
    assert heartbeat["jobs_available"]==1

    # Create the monitoring scope before importing the CVE so first-time
    # evidence correlation can raise the vulnerability-change event.
    targets=api.expect("GET","/api/admin/monitor/targets",headers=admin_h)["targets"]
    monitor=next((row for row in targets if row["name"]=="Release E2E monitor" and row["target"]=="198.51.100.40/32" and row["enabled"]),None)
    if monitor is None:
        monitor=api.expect("POST","/api/admin/monitor/targets",payload={"name":"Release E2E monitor","target":"198.51.100.40/32","authorization_id":auth["id"],"cooldown_seconds":60},headers=admin_h)

    # CPE-based potential correlation from a deterministic vulnerability fixture.
    cve="CVE-2099-"+str(int(run_id[:4],16)%10000).zfill(4)
    cpe_match={"criteria":"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*","vulnerable":True,"versionStartIncluding":"1.24.0","versionEndExcluding":"1.25.0"}
    api.expect("POST","/api/admin/vulnerabilities/import",payload={"source":source+" NVD fixture","records":[{"cve":cve,"description":"Clearly labeled ScanLattice E2E fixture CVE; not a real advisory.","severity":"MEDIUM","cvss":5.0,"cpes":[cpe_match]}]},headers=admin_h)
    assert api.expect("GET","/api/search?"+urllib.parse.urlencode({"q":"vuln:"+cve}))["total"]==1
    host_vulns=api.expect("GET","/api/hosts/198.51.100.40")["potential_vulnerabilities"]
    assert any(row["cve"]==cve and row["confidence"]=="potential" for row in host_vulns)
    assert api.expect("GET","/api/vulnerabilities/stats")["potential_host_matches"]>=1

    # Monitoring data changes, certificate expiry checks, and queued notification outbox are exercised without SMTP/webhook delivery.
    targets=api.expect("GET","/api/admin/monitor/targets",headers=admin_h)["targets"]
    monitor=next((row for row in targets if row["name"]=="Release E2E monitor" and row["target"]=="198.51.100.40/32" and row["enabled"]),None)
    if monitor is None:
        monitor=api.expect("POST","/api/admin/monitor/targets",payload={"name":"Release E2E monitor","target":"198.51.100.40/32","authorization_id":auth["id"],"cooldown_seconds":60},headers=admin_h)
    destinations=api.expect("GET","/api/admin/monitor/destinations",headers=admin_h)["destinations"]
    if not any(row["name"]=="Release E2E outbox" and row["enabled"] for row in destinations):
        api.expect("POST","/api/admin/monitor/destinations",payload={"name":"Release E2E outbox","kind":"email","endpoint":"alerts@fixture.example.test"},headers=admin_h)
    expiry=(datetime.now(timezone.utc)+timedelta(days=10)).isoformat(timespec="seconds")
    api.expect("POST","/api/admin/import",payload={"provenance":source+" monitor update","observations":[{"ip":"198.51.100.40","port":443,"proto":"tcp","asn":"AS64496","org":"ScanLattice E2E Fictional Transit","country":"NL","hostname":"edge.fixture.example.test","service":"https","product":"nginx release fixture update "+run_id,"cpe":"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*","banner":"[TEST FIXTURE ONLY] monitor update","tls":{"cert":{"not_after":expiry,"fingerprint_sha256":"fixture-certificate-fingerprint"}},"observed_at":now}]},headers=admin_h)
    check=api.expect("POST","/api/admin/monitor/run-once",headers=admin_h)
    event_rows=api.expect("GET","/api/admin/monitor/events",headers=admin_h)["results"]
    event_types={row["event_type"] for row in event_rows}
    assert {"software_changed","certificate_expiring","vulnerability_new"}.issubset(event_types)
    notifications=api.expect("GET","/api/admin/monitor/notifications",headers=admin_h)
    assert notifications["total"]>=1 and notifications["results"]
    assert api.expect("GET","/api/admin/monitor/destinations",headers=admin_h)["notification_status"]

    # Local-only screenshot upload and privacy headers; no remote host is contacted.
    screenshots=api.expect("GET","/api/admin/screenshots",headers=admin_h)["screenshots"]
    screenshot=next((row for row in screenshots if row["ip"]=="198.51.100.40" and row["filename"]=="release-e2e.png"),None)
    if screenshot is None:
        _,uploaded,_=api.call("POST","/api/admin/hosts/198.51.100.40/screenshots",body=PNG_1PX,headers={**admin_h,"Content-Type":"image/png","X-Screenshot-Name":"release-e2e.png","X-Screenshot-Note":"TEST FIXTURE ONLY; not captured from a remote host"})
        screenshot=uploaded
    status,image,image_headers=api.call("GET",f"/api/admin/screenshots/{screenshot['id']}/content",headers=admin_h)
    assert status==200 and image==PNG_1PX and image_headers.get("Cache-Control")=="private, no-store"

    # Aggregates, reports, docs inventory, API-key scope, Python SDK/CLI path.
    analytics=api.expect("GET","/api/analytics/summary")
    assert any(row["country"]=="NL" for row in analytics["countries"])
    status,csv_bytes,_=api.call("GET","/api/reports/export.csv")
    assert status==200 and b"source,observed_at" in csv_bytes and source.encode() in csv_bytes
    docs=api.expect("GET","/api/docs")
    assert any(row["path"]=="/api/admin/monitor/run-once" for row in docs["route_inventory"])
    key=api.expect("POST","/api/admin/api-keys",payload={"name":"Release E2E read key "+run_id,"scopes":["search:read"]},headers=admin_h)
    keyed_query=urllib.parse.urlencode({"q":"asn:AS64496 port:443"})
    keyed=api.expect("GET","/api/search?"+keyed_query,headers={"Authorization":"Bearer "+key["token"]})
    assert keyed["total"]>=1 and keyed["hosts"], f"Read-scoped API key search returned no indexed results: {keyed!r}"
    cli_env={**os.environ,"SCANLATTICE_URL":base,"SCANLATTICE_API_KEY":key["token"]}
    cli=subprocess.run([sys.executable,str(ROOT/"cli.py"),"search","asn:AS64496 port:443"],cwd=ROOT,env=cli_env,capture_output=True,text=True,timeout=45)
    if cli.returncode!=0:raise AssertionError(f"CLI failed: {cli.stderr}")
    assert json.loads(cli.stdout)["total"]>=1

    # Worker protocol compatibility: the queued session job is assigned after heartbeat; no scanner module runs.
    assigned_job=next(row for row in api.expect("GET","/api/admin/jobs",headers=admin_h)["jobs"] if row["id"]==session_job["id"])
    assert assigned_job["status"]=="assigned"
    claims=api.expect("POST","/api/worker/jobs/claim",headers=wh)["jobs"]
    claim=next(row for row in claims if row["id"]==session_job["id"])
    api.expect("POST",f"/api/worker/jobs/{session_job['id']}/start",payload={"lease_token":claim["lease_token"]},headers=wh)
    api.expect("POST",f"/api/worker/jobs/{session_job['id']}/progress",payload={"lease_token":claim["lease_token"],"progress_done":1},headers=wh)
    bad={"lease_token":claim["lease_token"],"idempotency_key":"release-e2e-out-of-scope-"+run_id,"completed_checks":1,"observations":[{"ip":"198.51.100.98","port":9443,"service":"https","banner":"[TEST FIXTURE ONLY] rejected out-of-job result"}]}
    api.expect("POST",f"/api/worker/jobs/{session_job['id']}/results",status=400,payload=bad,headers=wh)
    good={"lease_token":claim["lease_token"],"idempotency_key":"release-e2e-valid-result-"+run_id,"completed_checks":1,"observations":[{"ip":"198.51.100.97","port":9443,"asn":"AS64496","org":"ScanLattice E2E Fictional Transit","service":"https","product":"E2E worker result","banner":"[TEST FIXTURE ONLY] simulated worker protocol result"}]}
    completed=api.expect("POST",f"/api/worker/jobs/{session_job['id']}/results",payload=good,headers=wh)
    assert completed["status"]=="completed" and completed["indexed"]==1
    assert api.expect("GET","/api/hosts/198.51.100.97")["services"]
    # Verify administrator cancellation through the v1 control API while the
    # enrolled worker remains available. The job is scoped to a TEST-NET host
    # and cancellation happens before the worker claims it.
    cancel_job=api.expect("POST","/api/admin/jobs",payload={"target":"198.51.100.96/32","profile_id":profile["id"],"ports":[9444]},headers=admin_h)
    assert cancel_job["status"] in {"queued","assigned"}
    assert api.expect("POST",f"/api/admin/jobs/{cancel_job['id']}/cancel",headers=admin_h)["status"]=="cancelled"
    cancelled_rows=api.expect("GET","/api/admin/jobs",headers=admin_h)["jobs"]
    assert next(row for row in cancelled_rows if row["id"]==cancel_job["id"])["status"]=="cancelled"
    scope_status,scope_result,_=api.call("GET","/api/admin/hosts/198.51.100.40/authorization",headers=admin_h)
    assert scope_status==200 and scope_result["authorized"]
    print("PASS release E2E: imports, public/passive search, ASN indexing, host history, CVE correlation, monitor events/outbox, map analytics, screenshot access, docs/API/CLI, CSRF sessions, worker queue/lease/result scope.")
    print("No target connection was made; worker output was a labeled fixture. No provider, SMTP, webhook, Docker registry, or production system was contacted by this script.")


if __name__=="__main__":main()
