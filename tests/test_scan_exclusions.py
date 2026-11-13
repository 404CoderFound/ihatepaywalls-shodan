from conftest import authorize, create_job, enroll


def add_exclusion(client, headers, cidr="198.51.100.64/26"):
    return client.post("/api/admin/scan-exclusions", headers=headers, json={
        "name": "Synthetic opt-out fixture", "cidr": cidr,
        "reason": "TEST-NET policy fixture",
    })


def test_scan_exclusion_overrides_authorization_for_direct_jobs(system, admin_headers):
    client, _, _ = system
    authorize(client, admin_headers, "198.51.100.0/24")
    excluded = add_exclusion(client, admin_headers)
    assert excluded.status_code == 200 and excluded.json()["enabled"] is True
    profiles = client.get("/api/admin/profiles", headers=admin_headers).json()["profiles"]
    blocked = client.post("/api/admin/jobs", headers=admin_headers, json={
        "target": "198.51.100.77/32", "profile_id": profiles[0]["id"], "ports": [80],
    })
    assert blocked.status_code == 403 and "scan exclusion" in blocked.json()["detail"]
    # A non-overlapping address inside the same explicit authorization remains valid.
    allowed = client.post("/api/admin/jobs", headers=admin_headers, json={
        "target": "198.51.100.10/32", "profile_id": profiles[0]["id"], "ports": [80],
    })
    assert allowed.status_code == 200


def test_new_exclusion_cancels_queued_or_assigned_jobs_and_blocks_old_lease(system, admin_headers):
    client, _, database = system
    authorize(client, admin_headers, "198.51.100.0/24")
    _, worker_headers = enroll(client, "exclusion-fixture-worker")
    created = create_job(client, admin_headers, target="198.51.100.77/32", ports=[80])
    assert created.status_code == 200
    claimed = client.post("/api/worker/jobs/claim", headers=worker_headers, json={})
    assert claimed.status_code == 200 and len(claimed.json()["jobs"]) == 1
    job = claimed.json()["jobs"][0]
    exclusion = add_exclusion(client, admin_headers)
    assert exclusion.status_code == 200 and exclusion.json()["cancelled_jobs"] == 1
    start = client.post(f"/api/worker/jobs/{job['id']}/start", headers=worker_headers,
                        json={"lease_token": job["lease_token"]})
    assert start.status_code == 409
    with database.connection() as db:
        state = db.execute("SELECT status,lease_token FROM scan_jobs WHERE id=?", (job["id"],)).fetchone()
    assert state["status"] == "cancelled" and state["lease_token"] is None


def test_exclusion_list_requires_admin_and_disable_is_audited(system, admin_headers):
    client, _, database = system
    assert client.get("/api/admin/scan-exclusions").status_code == 401
    assert client.post("/api/admin/scan-exclusions", json={
        "name": "unauthenticated", "cidr": "198.51.100.0/24",
    }).status_code == 401
    created = add_exclusion(client, admin_headers)
    assert created.status_code == 200
    assert add_exclusion(client, admin_headers).status_code == 409
    disabled = client.post(f"/api/admin/scan-exclusions/{created.json()['id']}/disable", headers=admin_headers)
    assert disabled.status_code == 200 and disabled.json()["enabled"] is False
    assert client.post("/api/admin/scan-exclusions/not-an-id/disable", headers=admin_headers).status_code == 422
    with database.connection() as db:
        audit = db.execute("SELECT COUNT(*) FROM audit_logs WHERE action='scan_exclusion.disabled'").fetchone()[0]
        assert audit == 1


def test_scan_exclusion_cidrs_validate_and_deep_recon_preview_marks_optouts(system, admin_headers):
    client, _, _ = system
    authorize(client, admin_headers, "198.51.100.0/24")
    profiles = client.get("/api/admin/profiles", headers=admin_headers).json()["profiles"]
    invalid = add_exclusion(client, admin_headers, "not-a-cidr")
    assert invalid.status_code == 400
    assert add_exclusion(client, admin_headers).status_code == 200
    preview = client.post("/api/admin/deep-recon/preview", headers=admin_headers, json={
        "query": "net:198.51.100.64/26", "profile_id": profiles[0]["id"], "ports": [80],
    })
    assert preview.status_code == 200
    candidate = preview.json()["candidates"][0]
    assert candidate["excluded"] is True and candidate["authorized"] is False
    assert preview.json()["target_count"] == 0


def test_admin_ui_exposes_audited_optout_management():
    from pathlib import Path

    root = Path(__file__).parents[1]
    html = (root / "app/static/index.html").read_text()
    script = (root / "app/static/app.js").read_text()
    assert 'id="exclusion-form"' in html and 'id="exclusion-list"' in html
    assert 'api("/api/admin/scan-exclusions"' in script
    assert "/api/admin/scan-exclusions/${button.dataset.id}/disable" in script


def test_postgresql_migration_persists_exclusions_and_generated_ids():
    from pathlib import Path
    from app.db_backend import _GENERATED_ID_TABLES

    migration = (Path(__file__).parents[1] / "migrations/postgresql/004_scan_exclusions.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS scan_exclusions" in migration
    assert "id BIGSERIAL PRIMARY KEY" in migration
    assert "cidr TEXT NOT NULL UNIQUE" in migration
    assert "scan_exclusions" in _GENERATED_ID_TABLES
