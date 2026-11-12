from pathlib import Path

def test_secret_file_loader_requires_private_permissions(tmp_path, monkeypatch):
    import app.main as main

    secret = tmp_path / "admin-token"
    secret.write_text("staging-only-token\n", encoding="utf-8")
    secret.chmod(0o400)
    monkeypatch.setenv("ADMIN_TOKEN_FILE", str(secret))
    monkeypatch.delenv("ADMIN_TOKEN", raising=False)
    assert main._configured_secret("ADMIN_TOKEN") == "staging-only-token"
    secret.chmod(0o644)
    try:
        main._configured_secret("ADMIN_TOKEN")
    except RuntimeError as exc:
        assert "staging-only-token" not in str(exc)
    else:
        raise AssertionError("group/world-readable secret file was accepted")


def test_staging_scan_kill_switch_rejects_worker_and_job_mutations(system, admin_headers, monkeypatch):
    client, main, _ = system
    monkeypatch.setattr(main, "ACTIVE_SCANNING_ENABLED", False)
    assert client.get("/api/health").json()["active_scanning"] is False
    assert client.post("/api/worker/register", json={}).status_code == 503
    assert client.post("/api/worker/heartbeat", json={}).status_code == 503
    assert client.post("/api/worker/jobs/claim", json={}).status_code == 503
    assert client.post("/api/admin/jobs", headers=admin_headers, json={}).status_code == 503
    assert client.post("/api/admin/refresh-requests", headers=admin_headers, json={}).status_code == 503


def test_debian_staging_compose_is_loopback_only_internal_and_persistent():
    compose = Path(__file__).parents[1] / "deploy" / "compose.debian-v2-staging.yaml"
    content = compose.read_text(encoding="utf-8")
    assert 'name: scanlattice-v2-staging' in content
    assert '127.0.0.1:8081:8080' in content
    assert 'internal: true' in content
    assert '/var/lib/postgresql/data' in content
    assert 'POSTGRES_PASSWORD_FILE: /run/secrets/db_password' in content
    assert 'DATABASE_PASSWORD_FILE: /run/secrets/db_password' in content
    assert 'ACTIVE_SCANNING_ENABLED: "false"' in content
    assert 'scanlattice_v2_postgresql_data' not in content
    assert 'web_scanlattice_data' not in content
    assert '5432:' not in content
    assert 'DATABASE_URL:' not in content
    assert 'ADMIN_TOKEN:' not in content
    assert 'ENROLLMENT_TOKEN:' not in content
