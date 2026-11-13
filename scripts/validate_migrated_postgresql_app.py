#!/usr/bin/env python3
"""API smoke checks against an already migrated, disposable PostgreSQL copy.

Runs only from the isolated migration rehearsal on a private Mac Docker network.
It uses fresh staging credentials and never submits, claims or starts scan jobs.
"""
from __future__ import annotations

import os

from fastapi.testclient import TestClient

from app.database import connection
from app.main import app

assert os.environ.get("DATABASE_BACKEND") == "postgresql", "PostgreSQL is required"
assert os.environ.get("DATABASE_SCHEMA") == "rehearsal", "Refusing a non-rehearsal schema"
assert os.environ.get("PASSIVE_ENRICHMENT_ENABLED") == "false", "Passive enrichment must be disabled"
assert os.environ.get("VULNERABILITY_AUTO_REFRESH") == "false", "Vulnerability refresh must be disabled"
assert os.environ.get("MONITORING_AUTO_CHECKS") == "false", "Monitoring checks must be disabled"
assert os.environ.get("SEED_DEMO") == "false", "Demo seed must be disabled"
admin = os.environ["ADMIN_TOKEN"]
assert len(admin) >= 32, "Only fresh random staging credentials are allowed"
assert len(os.environ.get("ENROLLMENT_TOKEN", "")) >= 32

with connection() as db:
    before = {
        table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("hosts", "observations", "services", "scan_jobs", "workers", "passive_records", "scan_exclusions")
    }
    host = db.execute("SELECT ip FROM hosts ORDER BY ip LIMIT 1").fetchone()
    expected_auth = db.execute("SELECT COUNT(*) FROM authorizations").fetchone()[0]
    expected_profiles = db.execute("SELECT COUNT(*) FROM scan_profiles").fetchone()[0]
    expected_workers = before["workers"]

headers = {"X-Admin-Token": admin}


def get_ok(client: TestClient, path: str, *, params: dict | None = None, authenticated: bool = False) -> dict:
    response = client.get(path, params=params, headers=headers if authenticated else None)
    assert response.status_code == 200, (
        f"API endpoint {path} returned HTTP {response.status_code}"
    )
    return response.json()


with TestClient(app, base_url="https://testserver") as client:
    ui = client.get("/")
    assert ui.status_code == 200 and "SCANLATTICE" in ui.text
    for asset in ("/static/app.js", "/static/insights.js", "/static/style.css"):
        response = client.get(asset)
        assert response.status_code == 200 and response.content, f"UI asset unavailable: {asset}"
    health = get_ok(client, "/api/health")
    assert health["status"] == "ok" and health["active_scanning"] is False
    stats = get_ok(client, "/api/stats")
    for key in ("observations", "services", "passive_records"):
        assert stats[key] == before[key], f"{key} count differs in API stats"
    docs = get_ok(client, "/api/docs")
    assert docs is not None
    search = get_ok(client, "/api/search", params={"q": f"ip:{host[0]}" if host else ""})
    assert "hosts" in search and "total" in search
    if host:
        assert search["total"] >= 1, "Imported host is missing from PostgreSQL search"
        detail = get_ok(client, f"/api/hosts/{host[0]}")
        assert detail["host"]["ip"] == host[0], "Host detail IP differs"

    assert client.get("/api/admin/profiles").status_code in (401, 403), "Admin route accepted anonymous request"
    login = client.post("/api/admin/session", json={"admin_token": admin})
    assert login.status_code == 200 and login.json()["authenticated"] is True
    assert client.get("/api/admin/session").json()["authenticated"] is True
    assert client.get("/api/admin/profiles").status_code == 200, "Cookie-authenticated admin UI request failed"
    assert client.post("/api/admin/authorizations", json={"name": "CSRF must block", "cidr": "192.0.2.0/24"}).status_code == 403
    authorizations = get_ok(client, "/api/admin/authorizations", authenticated=True)
    profiles = get_ok(client, "/api/admin/profiles", authenticated=True)
    assert len(authorizations["authorizations"]) == expected_auth
    assert len(profiles["profiles"]) == expected_profiles

    # These admin endpoints exercise imported jobs and workers. Their internal
    # scheduler may update the disposable database but no real worker is present.
    jobs = get_ok(client, "/api/admin/jobs", authenticated=True)
    workers = get_ok(client, "/api/admin/workers", authenticated=True)
    generations = get_ok(client, "/api/admin/scan-generations", authenticated=True)
    tasks = get_ok(client, "/api/admin/scan-tasks", authenticated=True)
    exclusions = get_ok(client, "/api/admin/scan-exclusions", authenticated=True)
    assert len(exclusions["exclusions"]) == before["scan_exclusions"]
    assert len(workers["workers"]) == expected_workers
    assert "jobs" in jobs and "generations" in generations and "tasks" in tasks
    print("PASS: PostgreSQL-backed UI assets, health, stats, search, host detail, admin session/CSRF, scan history, jobs and worker listings")

with connection() as db:
    after = {
        table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in before
    }
assert before == after, "API smoke check unexpectedly added or removed indexed data or jobs"
print("PASS: no indexed records, worker registrations or scan jobs added/removed by API smoke checks")
