"""Result batches use only local TestClient database fixtures."""
import time

from conftest import authorize, create_job, enroll


def _running_job(system, headers, ports=(80, 443)):
    client, _, _ = system
    authorize(client, headers)
    _, worker_headers = enroll(client)
    created = create_job(client, headers, ports=list(ports))
    assert created.status_code == 200
    job = client.post("/api/worker/jobs/claim", headers=worker_headers, json={}).json()["jobs"][0]
    started = client.post(f"/api/worker/jobs/{job['id']}/start", headers=worker_headers,
                          json={"lease_token": job["lease_token"]})
    assert started.status_code == 200
    return job, worker_headers


def _post(client, job, headers, index, checks, observations=()):
    return client.post(f"/api/worker/jobs/{job['id']}/results/batches", headers=headers, json={
        "lease_token": job["lease_token"], "batch_index": index,
        "checks_done": checks, "observations": list(observations),
    })


def _status(client, job, headers):
    return client.get(f"/api/worker/jobs/{job['id']}/results/batches/status", headers=headers)


def _finish(client, job, headers, count, checks):
    return client.post(f"/api/worker/jobs/{job['id']}/results/complete", headers=headers, json={
        "lease_token": job["lease_token"], "batch_count": count, "completed_checks": checks,
    })


def test_two_batches_finish_and_duplicate_ack_are_exactly_once(system, admin_headers):
    client, _, database = system
    job, wh = _running_job(system, admin_headers)
    assert _status(client, job, wh).json()["batch_count"] == 0
    first = _post(client, job, wh, 0, 1, [
        {"ip": "127.0.0.1", "port": 80, "service": "http",
         "product": "TestServer", "banner": "HTTP/1.1 200 OK"},
    ])
    assert first.status_code == 200 and first.json()["status"] == "accepted"
    replay = _post(client, job, wh, 0, 1, [
        {"ip": "127.0.0.1", "port": 80, "service": "http",
         "product": "TestServer", "banner": "HTTP/1.1 200 OK"},
    ])
    assert replay.status_code == 200 and replay.json()["status"] == "already_processed"
    assert _status(client, job, wh).json()["checks_done"] == 1
    second = _post(client, job, wh, 1, 2, [])
    assert second.status_code == 200 and second.json()["status"] == "accepted"
    finished = _finish(client, job, wh, 2, 2)
    assert finished.status_code == 200 and finished.json() == {"status": "completed", "indexed": 1}
    repeat = _finish(client, job, wh, 2, 2)
    assert repeat.status_code == 200 and repeat.json()["status"] == "already_completed"
    with database.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM observations WHERE scan_job_id=?", (job["id"],)).fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM scan_result_batches WHERE job_id=?", (job["id"],)).fetchone()[0] == 2
        assert db.execute("SELECT progress_done,status FROM scan_jobs WHERE id=?", (job["id"],)).fetchone()["status"] == "completed"
    assert client.get("/api/search", params={"q": "port:80"}).json()["total"] == 1


def test_missing_or_changed_batch_and_incomplete_finish_rejected(system, admin_headers):
    client, _, database = system
    job, wh = _running_job(system, admin_headers)
    assert _post(client, job, wh, 1, 2, []).status_code == 409
    assert _post(client, job, wh, 0, 1, []).status_code == 200
    assert _post(client, job, wh, 0, 1, [
        {"ip": "127.0.0.1", "port": 80},
    ]).status_code == 409
    assert _finish(client, job, wh, 1, 2).status_code == 409
    assert _post(client, job, wh, 1, 2, []).status_code == 200
    assert _finish(client, job, wh, 1, 1).status_code == 409
    with database.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM observations WHERE scan_job_id=?", (job["id"],)).fetchone()[0] == 0


def test_scope_and_worker_authentication_remain_enforced(system, admin_headers):
    client, _, _ = system
    job, wh = _running_job(system, admin_headers)
    assert _status(client, job, {}).status_code == 401
    assert _post(client, job, {}, 0, 1, []).status_code == 401
    assert _post(client, job, wh, 0, 1, [
        {"ip": "127.0.0.2", "port": 80},
    ]).status_code == 400
    assert _post(client, job, wh, 0, 1, [
        {"ip": "127.0.0.1", "port": 12345},
    ]).status_code == 400
    assert _post(client, job, wh, 0, 1, [
        {"ip": "127.0.0.1", "port": 80, "proto": "udp"},
    ]).status_code == 400
    assert _post(client, job, wh, 0, 2, []).status_code == 200
    assert _finish(client, job, wh, 1, 2).status_code == 200


def test_legacy_results_cannot_mix_with_batched_results(system, admin_headers):
    client, _, _ = system
    job, wh = _running_job(system, admin_headers)
    assert _post(client, job, wh, 0, 1, []).status_code == 200
    response = client.post(f"/api/worker/jobs/{job['id']}/results", headers=wh, json={
        "lease_token": job["lease_token"], "idempotency_key": "mixed-result-mode",
        "completed_checks": 2, "observations": [],
    })
    assert response.status_code == 409


def test_batched_v1_failure_requeues_and_checkpoint_survives(system, admin_headers):
    client, _, database = system
    job, wh = _running_job(system, admin_headers)
    assert _post(client, job, wh, 0, 1, []).status_code == 200
    failed = client.post(f"/api/worker/jobs/{job['id']}/fail", headers=wh,
                         json={"lease_token": job["lease_token"], "error": "connection lost"})
    assert failed.status_code == 200 and failed.json()["status"] == "queued"
    # Worker reclaims the same job, keeping its existing batch receipt.
    reassigned = client.post("/api/worker/jobs/claim", headers=wh, json={}).json()["jobs"][0]
    assert reassigned["id"] == job["id"] and reassigned["lease_token"] != job["lease_token"]
    assert client.post(f"/api/worker/jobs/{job['id']}/start", headers=wh,
                       json={"lease_token": reassigned["lease_token"]}).status_code == 200
    checkpoint = _status(client, reassigned, wh).json()
    assert checkpoint["batch_count"] == 1 and checkpoint["checks_done"] == 1
    assert _post(client, reassigned, wh, 1, 2, []).status_code == 200
    assert _finish(client, reassigned, wh, 2, 2).status_code == 200


def test_revocation_and_cancellation_reject_additional_batches(system, admin_headers):
    client, _, database = system
    job, wh = _running_job(system, admin_headers)
    assert _post(client, job, wh, 0, 1, []).status_code == 200
    auth = client.get("/api/admin/authorizations", headers=admin_headers).json()["authorizations"][0]
    assert client.post(f"/api/admin/authorizations/{auth['id']}/revoke",
                       headers=admin_headers).status_code == 200
    assert _post(client, job, wh, 1, 2, []).status_code == 409
    assert _finish(client, job, wh, 1, 2).status_code == 409
