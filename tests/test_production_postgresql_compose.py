"""Static safety checks for the standalone production PostgreSQL template."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
COMPOSE = ROOT / "deploy" / "compose.postgresql-production.yaml"
PROJECT = "scanlattice-postgresql-validation"


def test_postgresql_compose_is_private_and_never_publishes_5432():
    source = COMPOSE.read_text()
    service = source.split("services:\n", 1)[1].split("\nsecrets:", 1)[0]

    assert "image: postgres:17.11-alpine" in service
    assert not re.search(r"(?m)^    ports\s*:", service)
    assert "      - postgres_private" in service
    assert "name: scanlattice_postgresql_private" in source
    assert "driver: bridge" in source
    assert "internal: true" in source


def test_postgresql_compose_uses_dedicated_persistent_volume():
    source = COMPOSE.read_text()
    service = source.split("services:\n", 1)[1].split("\nsecrets:", 1)[0]
    assert "      - pgdata:/var/lib/postgresql/data" in service
    assert re.search(r"(?m)^  pgdata:\n    name: scanlattice_v2_postgresql_data$", source)
    assert "external: true" not in source


def test_postgresql_credentials_are_external_and_not_committed():
    source = COMPOSE.read_text()
    assert "POSTGRES_PASSWORD_FILE: /run/secrets/pg_password" in source
    assert "file: ${SCANLATTICE_PG_PASSWORD_FILE:?" in source
    assert not re.search(r"(?m)^\s+POSTGRES_PASSWORD\s*:", source)
    assert "scanlattice_v2_postgresql_data" not in (ROOT / ".env.example").read_text()


def test_v1_compose_pair_and_pinned_rollback_image_are_documented_unchanged():
    checklist = (ROOT / "V2_PRODUCTION_CUTOVER_CHECKLIST.md").read_text()
    preflight = (ROOT / "deploy" / "PRODUCTION_PREFLIGHT.md").read_text()
    assert "/opt/scanlattice/web/compose.web.yaml" in preflight
    assert "/home/ihatepaywalls/scanlattice-release-v1/compose.release.yaml" in preflight
    assert "scanlattice/release:v1.0.0-d0c969f" in checklist
    assert "Preserve" in checklist or "preserve" in checklist


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI is unavailable")
def test_docker_compose_config_resolves_private_network_and_persistent_volume(tmp_path):
    password_file = tmp_path / "postgres-password"
    password_file.write_text("local-validation-only-password\n")
    password_file.chmod(0o600)
    env = os.environ.copy()
    env["SCANLATTICE_PG_PASSWORD_FILE"] = str(password_file)

    result = subprocess.run(
        [
            "docker", "compose", "-p", PROJECT, "-f", str(COMPOSE),
            "config", "--format", "json",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    rendered = json.loads(result.stdout)
    service = rendered["services"]["postgres"]
    assert not service.get("ports")
    assert service["networks"] == {"postgres_private": None} or "postgres_private" in service["networks"]
    assert rendered["networks"]["postgres_private"]["internal"] is True
    assert rendered["volumes"]["pgdata"]["name"] == "scanlattice_v2_postgresql_data"
    assert service["volumes"][0]["target"] == "/var/lib/postgresql/data"
