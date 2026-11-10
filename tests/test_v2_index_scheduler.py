import json
import time

import pytest

from conftest import authorize, enroll


def _seed(client, admin_headers):
    authorize(client, admin_headers, "198.51.100.0/24")
    response = client.post("/api/admin/import", headers=admin_headers, json={
        "provenance":"v2-scheduler-fixture",
        "observations":[
            {"ip":"198.51.100.10","port":8443,"asn":"as064496","service":"https","product":"fixture"},
            {"ip":"198.51.100.11","port":8443,"asn":"AS64496","service":"https","product":"fixture"},
        ],
    })
    assert response.status_code == 200
    return client.get("/api/admin/profiles", headers=admin_headers).json()["profiles"][0]["id"]


def _create(client, headers, profile_id, query="asn:64496 port:8443", key="v2-idempotent-test"):
    return client.post("/api/admin/refresh-requests", headers={**headers, "Idempotency-Key":key}, json={
        "query":query,"profile_id":profile_id,
    })


def test_database_backend_seam_defaults_to_legacy_sqlite(system, monkeypatch):
    _, _, database = system
    from app.db_backend import PostgreSQLBackend, SQLiteBackend, configured_backend
    assert isinstance(configured_backend("sqlite"), SQLiteBackend)
    with database.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0] == 0
    assert isinstance(configured_backend("postgresql"), PostgreSQLBackend)
    monkeypatch.setenv("DATABASE_BACKEND", "postgresql")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_DSN", raising=False)
    with pytest.raises(RuntimeError, match="DATABASE_URL is required"):
        with database.connection():
            pass


def test_admin_panel_contains_refresh_submission_and_task_status():
    from pathlib import Path
    root = Path(__file__).parents[1]
    markup = (root / "app/static/index.html").read_text()
    script = (root / "app/static/app.js").read_text()
    assert 'id="refresh-form"' in markup and 'id="scan-task-table"' in markup
    assert '"/api/admin/refresh-requests"' in script and '"/api/admin/scan-tasks"' in script
    assert "cancel-generation" in script


def test_refresh_requests_are_separate_idempotent_and_admin_only(system, admin_headers):
    client, _, database = system
    profile_id = _seed(client, admin_headers)
    assert client.post("/api/admin/refresh-requests", json={"query":"asn:64496","profile_id":profile_id}).status_code == 401
    with database.connection() as db:
        jobs_before = db.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0]
        requests_before = db.execute("SELECT COUNT(*) FROM scan_refresh_requests").fetchone()[0]
    assert client.get("/api/search", params={"q":"asn:64496"}).status_code == 200
    with database.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0] == jobs_before
        assert db.execute("SELECT COUNT(*) FROM scan_refresh_requests").fetchone()[0] == requests_before

    first = _create(client, admin_headers, profile_id)
    assert first.status_code == 202
    again = _create(client, admin_headers, profile_id)
    assert again.status_code == 202 and again.json()["id"] == first.json()["id"]
    assert first.json()["generation"]["query_kind"] == "asn"
    assert first.json()["generation"]["target_count"] == 2
    with database.connection() as db:
        jobs = db.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0]
        tasks = db.execute("SELECT COUNT(*) FROM scan_tasks").fetchone()[0]
        assert jobs == 2 and tasks == 2
        assert {row[0] for row in db.execute("SELECT target_ip FROM scan_tasks")} == {"198.51.100.10","198.51.100.11"}
        assert {row[0] for row in db.execute("SELECT ports_json FROM scan_tasks")} == {'[8443]'}
        assert db.execute("SELECT asn FROM hosts WHERE ip='198.51.100.10'").fetchone()[0] == "AS64496"

    conflict = _create(client, admin_headers, profile_id, query="ip:198.51.100.10 port:8443")
    assert conflict.status_code == 409
    assert client.get("/api/admin/refresh-requests", headers=admin_headers).json()["requests"][0]["status"] == "queued"


def test_admin_session_with_csrf_can_create_refresh_request(system):
    client, _, _ = system
    profile_id = _seed(client, {"X-Admin-Token":"admin-test-token"})
    login = client.post("/api/admin/session", json={"admin_token":"admin-test-token"})
    assert login.status_code == 200
    response = client.post("/api/admin/refresh-requests", headers={
        "X-CSRF-Token":login.json()["csrf_token"],"Idempotency-Key":"session-refresh",
    }, json={"query":"ip:198.51.100.10 port:8443","profile_id":profile_id})
    assert response.status_code == 202 and response.json()["requested_by"] == "administrator"


def test_cidr_plan_only_uses_indexed_hosts_and_enforces_authorization(system, admin_headers):
    client, _, database = system
    profile_id = _seed(client, admin_headers)
    result = client.post("/api/admin/refresh-requests", headers={**admin_headers,"Idempotency-Key":"cidr-plan"}, json={
        "query":"net:198.51.100.0/24 port:8443","profile_id":profile_id,
    })
    assert result.status_code == 202 and result.json()["generation"]["target_count"] == 2
    with database.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM scan_tasks").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM scan_jobs WHERE target LIKE '%/24'").fetchone()[0] == 0

    blocked = client.post("/api/admin/refresh-requests", headers={**admin_headers,"Idempotency-Key":"blocked-ip"}, json={
        "query":"ip:203.0.113.12 port:443","profile_id":profile_id,
    })
    assert blocked.status_code == 403


def test_refresh_planner_rejects_over_limit_without_expanding_cidr(system, admin_headers, monkeypatch):
    client, main, database = system
    profile_id = _seed(client, admin_headers)
    monkeypatch.setattr(main, "MAX_REFRESH_TARGETS", 1)
    response = client.post("/api/admin/refresh-requests", headers={**admin_headers,"Idempotency-Key":"over-limit"}, json={
        "query":"net:198.51.100.0/24","profile_id":profile_id,
    })
    assert response.status_code == 413
    with database.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM scan_refresh_requests").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM scan_tasks").fetchone()[0] == 0


def test_worker_lease_expiry_retries_v2_task_and_v1_result_completes_generation(system, admin_headers):
    client, _, database = system
    profile_id = _seed(client, admin_headers)
    request = _create(client, admin_headers, profile_id, query="ip:198.51.100.10 port:8443", key="lease-request").json()
    generation_id = request["generation"]["generation_id"]
    worker_data, worker_headers = enroll(client, name="v2-lease-worker")
    job = client.post("/api/worker/jobs/claim", headers=worker_headers, json={}).json()["jobs"][0]
    task_id = client.get("/api/admin/scan-tasks", headers=admin_headers).json()["tasks"][0]["id"]
    assert job["target"] == "198.51.100.10/32"
    with database.connection() as db:
        db.execute("UPDATE scan_jobs SET lease_expires_at=? WHERE id=?", (int(time.time())-1, job["id"]))
    client.get("/api/admin/scan-tasks", headers=admin_headers)  # status read runs lease recovery through the shared scheduler
    task = next(row for row in client.get("/api/admin/scan-tasks", headers=admin_headers).json()["tasks"] if row["id"] == task_id)
    assert task["status"] == "queued" and task["attempt_count"] == 1 and "lease_token" not in task
    with database.connection() as db:
        db.execute("UPDATE scan_tasks SET available_at=0 WHERE id=?", (task_id,))
    client.post("/api/worker/heartbeat", headers=worker_headers, json={"cpu_pct":1,"memory_pct":1,"active_jobs":0,"version":"0.4.0","capabilities":["tcp-connect"],"max_concurrent":1})
    assigned = client.post("/api/worker/jobs/claim", headers=worker_headers, json={}).json()["jobs"][0]
    assert assigned["id"] == job["id"] and assigned["lease_token"] != job["lease_token"]
    started = client.post(f"/api/worker/jobs/{job['id']}/start", headers=worker_headers, json={"lease_token":assigned["lease_token"]})
    assert started.status_code == 200
    result = client.post(f"/api/worker/jobs/{job['id']}/results", headers=worker_headers, json={
        "lease_token":assigned["lease_token"],"idempotency_key":"v2-lease-valid-result",
        "completed_checks":1,"observations":[{"ip":"198.51.100.10","port":8443,"service":"https","banner":"fixture result"}],
    })
    assert result.status_code == 200
    status = client.get(f"/api/admin/refresh-requests/{request['id']}", headers=admin_headers).json()
    assert status["status"] == "completed" and status["generation"]["completed_tasks"] == 1
    assert client.get("/api/admin/scan-generations", headers=admin_headers).json()["generations"][0]["id"] == generation_id
    assert client.get("/api/admin/scan-tasks").status_code == 401


def test_v2_failed_worker_attempt_is_retried_without_changing_v1_failures(system, admin_headers):
    client, _, database = system
    profile_id = _seed(client, admin_headers)
    request = _create(client, admin_headers, profile_id, query="ip:198.51.100.11 port:8443", key="fail-retry-request").json()
    _, worker_headers = enroll(client, name="v2-fail-worker")
    job = client.post("/api/worker/jobs/claim", headers=worker_headers, json={}).json()["jobs"][0]
    response = client.post(f"/api/worker/jobs/{job['id']}/fail", headers=worker_headers, json={"lease_token":job["lease_token"],"error":"fixture failure"})
    assert response.status_code == 200 and response.json()["status"] == "queued"
    with database.connection() as db:
        state = db.execute("SELECT status,attempt_count,available_at FROM scan_tasks WHERE scan_job_id=?", (job["id"],)).fetchone()
        assert state["status"] == "queued" and state["attempt_count"] == 1 and state["available_at"] > int(time.time())
    assert client.get(f"/api/admin/refresh-requests/{request['id']}", headers=admin_headers).json()["status"] == "queued"


def test_generation_cancel_uses_existing_v1_job_cancellation(system, admin_headers):
    client, _, database = system
    profile_id = _seed(client, admin_headers)
    request = client.post("/api/admin/refresh-requests", headers={**admin_headers,"Idempotency-Key":"cancel-generation"}, json={
        "query":"net:198.51.100.0/24 port:8443","profile_id":profile_id,
    })
    assert request.status_code == 202
    generation_id = request.json()["generation"]["generation_id"]
    cancelled = client.post(f"/api/admin/scan-generations/{generation_id}/cancel", headers=admin_headers)
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    with database.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM scan_jobs WHERE status='cancelled'").fetchone()[0] == 2


def test_revoked_authorization_cancels_pending_v2_tasks(system, admin_headers):
    client, _, database = system
    profile_id = _seed(client, admin_headers)
    request = _create(client, admin_headers, profile_id, query="ip:198.51.100.10 port:8443", key="revoke-generation").json()
    auth_id = client.get("/api/admin/authorizations", headers=admin_headers).json()["authorizations"][0]["id"]
    assert client.post(f"/api/admin/authorizations/{auth_id}/revoke", headers=admin_headers).status_code == 200
    status = client.get(f"/api/admin/refresh-requests/{request['id']}", headers=admin_headers).json()
    assert status["status"] == "cancelled"
    with database.connection() as db:
        assert db.execute("SELECT status FROM scan_tasks WHERE generation_id=?", (request["generation"]["generation_id"],)).fetchone()[0] == "cancelled"
