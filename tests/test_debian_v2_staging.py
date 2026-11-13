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
    assert 'com.docker.network.bridge.enable_ip_masquerade: "false"' in content
    assert 'com.docker.network.bridge.name: "slv2stage0"' in content
    assert 'networks: [staging_private, staging_loopback]' in content
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


def test_staging_image_lock_pins_reviewed_amd64_build():
    lock = Path(__file__).parents[1] / "deploy" / "debian-v2-staging-image.lock"
    content = lock.read_text(encoding="utf-8")
    assert "source_commit=4f5b1beb18a8380a7763af2a0c45d69f825aa8f1" in content
    assert "platform=linux/amd64" in content
    assert "platform_manifest=sha256:c747ee2b4f266fdf22040bc202c7711ce155ea7bff60ab7e5345a9dcd9f44d4b" in content
    assert "docker_image_id=sha256:d3351b3b7a5a14254cc0a06a4f9a5cdec00bf8772845306f9b3bdf7edc956678" in content


def test_postgresql_rehearsal_image_includes_fake_worker_protocol_client():
    dockerfile = Path(__file__).parents[1] / "Dockerfile.rehearsal"
    assert "COPY worker /srv/worker" in dockerfile.read_text(encoding="utf-8")
