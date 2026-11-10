import importlib
import os
import re
import pytest
from fastapi.testclient import TestClient

os.environ.update({"ADMIN_TOKEN":"admin-test-token","ENROLLMENT_TOKEN":"enroll-test-token","SEED_DEMO":"false"})

@pytest.fixture
def system(tmp_path,monkeypatch):
    import app.database as database
    monkeypatch.setattr(database,"DB_PATH",tmp_path/"test.db")
    postgres_schema = None
    postgres_dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_DSN")
    if os.getenv("DATABASE_BACKEND", "sqlite").lower() in {"postgres", "postgresql"}:
        postgres_schema = "test_" + re.sub(r"[^a-z0-9_]", "_", tmp_path.name.lower())[:54]
        monkeypatch.setenv("DATABASE_SCHEMA", postgres_schema)
    import app.main as main
    main.ADMIN_TOKEN="admin-test-token";main.ENROLLMENT_TOKEN="enroll-test-token";main.OFFLINE=45;main.LEASE=90;main.COOKIE_SECURE=False;main.PUBLIC_RATE_LIMIT=60;main.ENRICHMENT_ENABLED=False;main.RATE_LIMITER.clear()
    try:
        with TestClient(main.app) as client:
            yield client,main,database
    finally:
        if postgres_schema:
            import psycopg
            with psycopg.connect(postgres_dsn) as db:
                db.execute(f'DROP SCHEMA IF EXISTS "{postgres_schema}" CASCADE')

@pytest.fixture
def admin_headers():return {"X-Admin-Token":"admin-test-token"}

def enroll(client,name="worker-1",cpu=10,memory=20,max_concurrent=1):
    r=client.post("/api/worker/register",headers={"X-Enrollment-Token":"enroll-test-token"},json={"name":name,"capabilities":["tcp-connect","http-headers"],"version":"0.2.0","max_concurrent":max_concurrent})
    assert r.status_code==200
    data=r.json();headers={"X-Worker-Token":data["worker_token"]}
    assert client.post("/api/worker/heartbeat",headers=headers,json={"cpu_pct":cpu,"memory_pct":memory,"active_jobs":0,"version":"0.2.0","capabilities":["tcp-connect","http-headers"],"max_concurrent":max_concurrent}).status_code==200
    return data,headers

def authorize(client,headers,cidr="127.0.0.0/24"):
    r=client.post("/api/admin/authorizations",headers=headers,json={"name":"local test","cidr":cidr});assert r.status_code==200;return r.json()

def create_job(client,headers,target="127.0.0.1/32",ports=None,worker_id=None):
    profiles=client.get("/api/admin/profiles",headers=headers).json()["profiles"]
    body={"target":target,"profile_id":profiles[0]["id"],"ports":ports or [8080]}
    if worker_id:body["worker_id"]=worker_id
    return client.post("/api/admin/jobs",headers=headers,json=body)
