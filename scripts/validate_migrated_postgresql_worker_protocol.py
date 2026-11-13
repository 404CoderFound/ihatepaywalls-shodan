#!/usr/bin/env python3
"""Fake worker API contract on disposable PostgreSQL with zero scan capabilities."""
from __future__ import annotations
import os
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from app.database import connection
from app.main import app
from worker.agent.batches import run_batched_job

assert os.getenv("DATABASE_BACKEND") == "postgresql"
assert os.getenv("DATABASE_SCHEMA") == "rehearsal"
assert os.getenv("ACTIVE_SCANNING_ENABLED") == "true", "Only the isolated protocol harness may enable job APIs"
from psycopg.conninfo import conninfo_to_dict
target = conninfo_to_dict(os.getenv("DATABASE_URL", ""))
assert target.get("host") == "postgres" and target.get("dbname") == "scanlattice", "Refusing a non-disposable PostgreSQL endpoint"
for name in ("SEED_DEMO", "PASSIVE_ENRICHMENT_ENABLED", "MONITORING_AUTO_CHECKS", "VULNERABILITY_AUTO_REFRESH"):
    assert os.getenv(name) == "false", f"{name} must be false"
enrollment = os.environ["ENROLLMENT_TOKEN"]
assert len(enrollment) >= 32, "Fresh staging-only enrollment token required"

with connection() as db:
    before_workers = db.execute("SELECT COUNT(*) FROM workers").fetchone()[0]
    before_jobs = db.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0]
    before_observations = db.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    before_services = db.execute("SELECT COUNT(*) FROM services").fetchone()[0]

with TestClient(app) as client:
    r = client.post(
        "/api/worker/register",
        json={"name": "staging-fake-no-scanning", "capabilities": [], "version": "0.7.0", "max_concurrent": 1},
        headers={"X-Enrollment-Token": enrollment},
    )
    assert r.status_code == 200, f"Registration HTTP {r.status_code}"
    data = r.json()
    assert data.get("worker_id") and data.get("worker_token")
    headers = {"X-Worker-Token": data["worker_token"]}
    r = client.post(
        "/api/worker/heartbeat",
        json={"cpu_pct": 0, "memory_pct": 0, "active_jobs": 0, "version": "0.7.0", "capabilities": [], "max_concurrent": 1},
        headers=headers,
    )
    assert r.status_code == 200, f"Heartbeat HTTP {r.status_code}"
    assert r.json()["status"] == "ok"
    assert r.json()["jobs_available"] == 0

    r = client.post("/api/worker/jobs/claim", headers=headers)
    assert r.status_code == 200, f"Claim HTTP {r.status_code}"
    assert r.json()["jobs"] == [], "Incapable fake worker must never receive work"

    r = client.get("/api/worker/jobs", headers=headers)
    assert r.status_code == 200 and r.json()["upgrade_required"] is True

    r = client.post("/api/worker/heartbeat", headers={"X-Worker-Token": "invalid"}, json={
        "cpu_pct": 0, "memory_pct": 0, "active_jobs": 0,
    })
    assert r.status_code == 401, "Invalid worker token was accepted"

    # End-to-end durable job test against the migrated PostgreSQL database.
    # The worker callback is synthetic and asserts its only endpoint is a
    # TEST-NET documentation address; no scanner or socket is invoked.
    auth_response = client.post("/api/admin/authorizations", headers={"X-Admin-Token": os.environ["ADMIN_TOKEN"]},
                                json={"name": "Disposable PostgreSQL fake-worker test", "cidr": "198.51.100.77/32"})
    assert auth_response.status_code == 200, f"Synthetic authorization HTTP {auth_response.status_code}"
    profile_response = client.get("/api/admin/profiles", headers={"X-Admin-Token": os.environ["ADMIN_TOKEN"]})
    assert profile_response.status_code == 200
    profile_id = profile_response.json()["profiles"][0]["id"]
    created = client.post("/api/admin/jobs", headers={"X-Admin-Token": os.environ["ADMIN_TOKEN"]}, json={
        "target": "198.51.100.77/32", "profile_id": profile_id, "ports": [80],
    })
    assert created.status_code == 200, f"Synthetic job creation HTTP {created.status_code}: {created.text}"
    registered = client.post("/api/worker/register", json={
        "name": "staging-fake-durable-worker", "capabilities": ["tcp-connect", "http-headers", "durable-batched-results"],
        "version": "0.7.0", "max_concurrent": 1,
    }, headers={"X-Enrollment-Token": enrollment})
    assert registered.status_code == 200
    active_headers = {"X-Worker-Token": registered.json()["worker_token"]}
    heartbeat = client.post("/api/worker/heartbeat", json={
        "cpu_pct": 0, "memory_pct": 0, "active_jobs": 0, "version": "0.7.0",
        "capabilities": ["tcp-connect", "http-headers", "durable-batched-results"], "max_concurrent": 1,
    }, headers=active_headers)
    assert heartbeat.status_code == 200
    claim = client.post("/api/worker/jobs/claim", json={}, headers=active_headers)
    assert claim.status_code == 200 and len(claim.json()["jobs"]) == 1
    job = claim.json()["jobs"][0]
    assert job["target"] == "198.51.100.77/32" and job["ports"] == [80]

    def request(path, payload=None, headers=None):
        response = (client.post(path, json=payload, headers=headers) if payload is not None
                    else client.get(path, headers=headers))
        assert response.status_code == 200, f"{path}: HTTP {response.status_code}: {response.text}"
        return response.json()

    probed = []

    def synthetic_probe(ip, port, connect_timeout, banner_timeout):
        assert (ip, port) == ("198.51.100.77", 80), "fake worker escaped TEST-NET test scope"
        probed.append((ip, port))
        banner = "HTTP/1.1 200 OK\\r\\nServer: ScanLattice-Rehearsal\\r\\n\\r\\n"
        return {"ip": ip, "port": port, "proto": "tcp", "service": "http",
                "product": "ScanLattice-Rehearsal", "banner": banner}

    dropped_ack = {"value": False}

    def lose_first_batch_ack(path, payload=None, headers=None):
        result = request(path, payload, headers)
        if path.endswith("/results/batches") and not dropped_ack["value"]:
            dropped_ack["value"] = True
            raise TimeoutError("synthetic lost acknowledgement after PostgreSQL commit")
        return result

    with tempfile.TemporaryDirectory(prefix="scanlattice-pg-fake-worker-") as spool:
        try:
            run_batched_job(job, active_headers, lose_first_batch_ack, synthetic_probe, Path(spool))
        except TimeoutError as exc:
            assert "synthetic lost acknowledgement" in str(exc)
        else:
            raise AssertionError("lost worker acknowledgement was not simulated")
        failed = client.post(f"/api/worker/jobs/{job['id']}/fail", json={
            "lease_token": job["lease_token"], "error": "synthetic worker restart after lost response",
        }, headers=active_headers)
        assert failed.status_code == 200 and failed.json()["status"] == "queued"
        reclaimed = client.post("/api/worker/jobs/claim", json={}, headers=active_headers)
        assert reclaimed.status_code == 200 and len(reclaimed.json()["jobs"]) == 1
        resumed = reclaimed.json()["jobs"][0]
        assert resumed["id"] == job["id"] and resumed["lease_token"] != job["lease_token"]
        result = run_batched_job(resumed, active_headers, request, synthetic_probe, Path(spool))
        assert result["status"] == "completed"
    assert dropped_ack["value"] and probed == [("198.51.100.77", 80)]
    search = client.get("/api/search", params={"q": "ip:198.51.100.77 port:80 service:http"})
    assert search.status_code == 200 and search.json()["total"] == 1
    with connection() as db:
        assert db.execute("SELECT COUNT(*) FROM scan_result_batches WHERE job_id=?", (job["id"],)).fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM observations WHERE scan_job_id=?", (job["id"],)).fetchone()[0] == 1
        assert db.execute("SELECT status FROM scan_jobs WHERE id=?", (job["id"],)).fetchone()[0] == "completed"

with connection() as db:
    assert db.execute("SELECT COUNT(*) FROM workers").fetchone()[0] == before_workers + 2
    assert db.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0] == before_jobs + 1
    assert db.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == before_observations + 1
    assert db.execute("SELECT COUNT(*) FROM services").fetchone()[0] == before_services + 1

print("PASS: fake worker registration, heartbeat, empty claim, legacy route and invalid-token rejection")
print("PASS: synthetic TEST-NET job claim/start, durable batch commit, lost-ack recovery, retry and PostgreSQL search")
print("PASS: fake callback made no external probes; all test data exists only in disposable PostgreSQL")
