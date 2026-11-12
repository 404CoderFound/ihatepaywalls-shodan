"""Offline preflight tests: pure JSON fixtures, no Docker required."""
from scripts.preflight_production_debian import (
    container_findings, compose_findings, BASE_COMPOSE, RELEASE_COMPOSE
)


def inventory():
    return {
        "State": {"Running": True},
        "Config": {"Labels": {
            "com.docker.compose.project": "web",
            "com.docker.compose.service": "web",
            "com.docker.compose.project.config_files": ",".join((str(BASE_COMPOSE), str(RELEASE_COMPOSE))),
        }, "Image": "scanlattice/release:v1"},
        "Image": "sha256:abc",
        "Mounts": [{"Type": "volume", "Name": "web_scanlattice_data", "Destination": "/data"}],
        "NetworkSettings": {"Networks": {"web_default": {}}},
        "HostConfig": {"PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}},
    }


def compose():
    return {"services": {"web": {
        "image": "scanlattice/release:v1",
        "ports": [{"target": 8080, "published": "8080", "host_ip": "127.0.0.1"}],
        "volumes": [{"type": "volume", "source": "scanlattice_data", "target": "/data"}],
        "environment": {"ADMIN_TOKEN": "SECRET_SHOULD_NEVER_BE_PRINTED"},
    }}}


def test_expected_v1_runtime_passes():
    errors, _ = container_findings(inventory())
    assert not errors
    assert not compose_findings(compose(), inventory())


def test_reject_wrong_volume():
    d = inventory()
    d["Mounts"][0]["Name"] = "other-volume"
    assert any("SQLite volume" in v for v in container_findings(d)[0])


def test_reject_public_port():
    d = inventory()
    d["HostConfig"]["PortBindings"]["8080/tcp"][0]["HostIp"] = "0.0.0.0"
    assert any("127.0.0.1" in v for v in container_findings(d)[0])


def test_reject_unexpected_compose_file():
    d = inventory()
    d["Config"]["Labels"]["com.docker.compose.project.config_files"] = str(BASE_COMPOSE)
    assert any("Compose-file" in v for v in container_findings(d)[0])


def test_reject_extra_public_port():
    d = inventory()
    d["HostConfig"]["PortBindings"]["5432/tcp"] = [{"HostIp": "0.0.0.0", "HostPort": "5432"}]
    assert any("extra web port" in v for v in container_findings(d)[0])


def test_reject_different_image():
    c = compose()
    c["services"]["web"]["image"] = "other"
    assert any("image" in v for v in compose_findings(c, inventory()))


def test_compose_secrets_not_in_output():
    # Neither check may leak source env values, including on failures.
    d = inventory()
    c = compose()
    errors = compose_findings(c, d)
    failures, notes = container_findings(d)
    text = str((errors, failures, notes))
    assert "SECRET_SHOULD_NEVER_BE_PRINTED" not in text
