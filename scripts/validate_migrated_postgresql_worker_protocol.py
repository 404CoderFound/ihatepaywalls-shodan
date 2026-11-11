#!/usr/bin/env python3
"""Fake worker API contract on disposable PostgreSQL with zero scan capabilities."""
from __future__ import annotations
import os
from fastapi.testclient import TestClient
from app.database import connection
from app.main import app

assert os.getenv("DATABASE_BACKEND") == "postgresql"
assert os.getenv("DATABASE_SCHEMA") == "rehearsal"
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

with connection() as db:
    assert db.execute("SELECT COUNT(*) FROM workers").fetchone()[0] == before_workers + 1
    assert db.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0] == before_jobs
    assert db.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == before_observations
    assert db.execute("SELECT COUNT(*) FROM services").fetchone()[0] == before_services

print("PASS: fake worker registration, heartbeat, empty claim, legacy route and invalid-token rejection")
print("PASS: no scans or scan jobs; fake identity exists only in disposable PostgreSQL")
