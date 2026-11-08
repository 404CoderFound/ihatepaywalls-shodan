import json,time
from conftest import authorize,create_job,enroll

def test_authentication_and_registration(system,admin_headers):
    client,_,_=system
    assert client.get("/api/admin/workers").status_code==401
    data,_=enroll(client)
    workers=client.get("/api/admin/workers",headers=admin_headers).json()["workers"]
    assert workers[0]["id"]==data["worker_id"] and workers[0]["online"]
    assert client.get("/api/health").json()["active_scanning"] is False

def test_query_parser_pagination_and_validation(system,admin_headers):
    client,_,_=system
    payload={"provenance":"licensed test fixture","observations":[
      {"ip":"192.0.2.10","port":443,"country":"NL","asn":"AS64500","org":"Example Organization","product":"nginx","service":"https","banner":"server nginx"},
      {"ip":"192.0.2.11","port":22,"country":"US","service":"ssh","banner":"SSH-2.0-Test"}]}
    assert client.post("/api/admin/import",headers=admin_headers,json=payload).status_code==200
    assert client.get('/api/search',params={"q":'port:443 country:NL org:"Example Organization"'}).json()["total"]==1
    page=client.get('/api/search',params={"q":"net:192.0.2.0/24"}).json();assert page["total"]==2 and page["per_page"]==10 and page["pages"]==1
    assert client.get('/api/search',params={"q":"unknown:value"}).status_code==400
    assert client.get('/api/search',params={"q":"port:99999"}).status_code==400

def test_authorization_job_assignment_cancel_and_no_worker(system,admin_headers):
    client,_,_=system;authorize(client,admin_headers)
    queued=create_job(client,admin_headers);assert queued.status_code==200 and queued.json()["status"]=="queued"
    _,wh=enroll(client)
    client.post("/api/worker/heartbeat",headers=wh,json={"cpu_pct":5,"memory_pct":5,"active_jobs":0,"capabilities":["tcp-connect"]})
    jobs=client.get("/api/admin/jobs",headers=admin_headers).json()["jobs"];assert jobs[0]["status"]=="assigned"
    assert client.post(f'/api/admin/jobs/{jobs[0]["id"]}/cancel',headers=admin_headers).json()["status"]=="cancelled"
    assert create_job(client,admin_headers,target="198.51.100.1/32").status_code==403

def test_claim_result_index_and_idempotency(system,admin_headers):
    client,_,_=system;authorize(client,admin_headers);_,wh=enroll(client);created=create_job(client,admin_headers,ports=[43210]).json()
    job=client.post("/api/worker/jobs/claim",headers=wh,json={}).json()["jobs"][0]
    assert client.post(f'/api/worker/jobs/{job["id"]}/start',headers=wh,json={"lease_token":job["lease_token"]}).status_code==200
    result={"lease_token":job["lease_token"],"idempotency_key":"fixed-result-key","observations":[{"ip":"127.0.0.1","port":43210,"service":"tcp","banner":"test banner"}]}
    first=client.post(f'/api/worker/jobs/{job["id"]}/results',headers=wh,json=result);assert first.json()["indexed"]==1
    second=client.post(f'/api/worker/jobs/{job["id"]}/results',headers=wh,json=result);assert second.json()["status"]=="already_processed"
    assert client.get("/api/search",params={"q":"ip:127.0.0.1 port:43210"}).json()["total"]==1
    host=client.get("/api/hosts/127.0.0.1").json();assert host["host"]["last_scan_at"]

def test_worker_cannot_upload_out_of_scope(system,admin_headers):
    client,_,_=system;authorize(client,admin_headers);_,wh=enroll(client);create_job(client,admin_headers,ports=[80]);job=client.post("/api/worker/jobs/claim",headers=wh,json={}).json()["jobs"][0]
    response=client.post(f'/api/worker/jobs/{job["id"]}/results',headers=wh,json={"lease_token":job["lease_token"],"idempotency_key":"outside-scope","observations":[{"ip":"127.0.0.2","port":80}]})
    assert response.status_code==400

def test_lease_recovery_and_persistence(system,admin_headers):
    client,main,database=system;authorize(client,admin_headers);_,wh=enroll(client);created=create_job(client,admin_headers).json()
    with database.connection() as db:db.execute("UPDATE scan_jobs SET lease_expires_at=?,max_attempts=3 WHERE id=?",(int(time.time())-1,created["id"]))
    client.get("/api/admin/jobs",headers=admin_headers)
    with database.connection() as db:row=db.execute("SELECT * FROM scan_jobs WHERE id=?",(created["id"],)).fetchone();assert row is not None and row["attempts"]>=2
    database.init_db(False)
    with database.connection() as db:assert db.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0]==1

def test_multiple_workers_best_health_and_manual_assignment(system,admin_headers):
    client,_,_=system;authorize(client,admin_headers);bad,_=enroll(client,"busy",90,90);good,_=enroll(client,"healthy",5,10)
    auto=create_job(client,admin_headers).json();assert auto["assigned_worker_id"]==good["worker_id"]
    manual=create_job(client,admin_headers,ports=[443],worker_id=bad["worker_id"]).json();assert manual["assigned_worker_id"]==bad["worker_id"]

def test_csv_import_and_audit(system,admin_headers):
    client,_,_=system
    body=b"ip,port,service,product,banner\n192.0.2.55,80,http,nginx,HTTP test\n"
    r=client.post("/api/admin/import/csv?provenance=test-dataset",headers={**admin_headers,"Content-Type":"text/csv"},content=body)
    assert r.status_code==200 and r.json()["imported"]==1
    assert client.get("/api/admin/audit",headers=admin_headers).json()["logs"][0]["action"]=="observations.imported"
