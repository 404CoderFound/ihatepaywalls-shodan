#!/usr/bin/env python3
"""Disposable local smoke test for the Debian v2 staging Compose project.

Requires a local Unix-socket Docker context and a prebuilt immutable web image
ID. It creates fresh temporary credentials and uniquely named Compose resources,
then removes only that project. It never contacts a server or scans a target.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKER_CANDIDATES = (
    shutil.which("docker"),
    "/Applications/Docker.app/Contents/Resources/bin/docker",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="immutable sha256 image ID from the reviewed source commit")
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        parser.error("--image must be an immutable sha256 image ID")
    docker = next((path for path in DOCKER_CANDIDATES if path and pathlib.Path(path).is_file()), None)
    if not docker:
        raise SystemExit("Docker CLI is unavailable")

    env = os.environ.copy()
    docker_dir = str(pathlib.Path(docker).parent)
    env["PATH"] = docker_dir + os.pathsep + env.get("PATH", "")

    def run(command: list[str], *, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(command, cwd=ROOT, env=env, input=input_bytes,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check and result.returncode:
            raise RuntimeError(f"local smoke command failed ({result.returncode}): {' '.join(command[:5])}")
        return result

    context = run([docker, "context", "show"]).stdout.decode().strip()
    endpoint = run([docker, "context", "inspect", context, "--format", "{{.Endpoints.docker.Host}}"]).stdout.decode().strip()
    if not endpoint.startswith("unix://"):
        raise SystemExit("Refusing non-local Docker context; use a local Unix-socket Docker context")
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", 8081))
        except OSError as exc:
            raise SystemExit("Local loopback port 8081 is already in use; free it before this smoke test") from exc

    project = "scanlattice-v2-local-" + secrets.token_hex(5)
    work = pathlib.Path(tempfile.mkdtemp(prefix="scanlattice-v2-local-"))
    work.chmod(0o700)
    secrets_by_name: dict[str, str] = {}
    for name in ("db", "admin", "enrollment"):
        value = secrets.token_urlsafe(40)
        secrets_by_name[name] = value
        secret_file = work / name
        secret_file.write_text(value + "\n", encoding="utf-8")
        secret_file.chmod(0o400)

    env_file = work / "compose.env"
    env_file.write_text(
        f"SCANLATTICE_WEB_IMAGE={args.image}\n"
        f"SCANLATTICE_DB_PASSWORD_FILE={work}/db\n"
        f"SCANLATTICE_ADMIN_TOKEN_FILE={work}/admin\n"
        f"SCANLATTICE_ENROLLMENT_TOKEN_FILE={work}/enrollment\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    # On macOS the external secret bind mounts are owned by the host uid. This
    # isolated override lets the local smoke image read those files; the actual
    # Debian Compose file continues to run as its default UID/GID 10001.
    override = work / "local.override.yaml"
    override.write_text(f'services:\n  web:\n    user: "{os.getuid()}:{os.getgid()}"\n', encoding="utf-8")
    compose_file = ROOT / "deploy" / "compose.debian-v2-staging.yaml"

    def compose(*arguments: str, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        command = [docker, "compose", "--project-name", project, "--env-file", str(env_file),
                   "-f", str(compose_file), "-f", str(override), *arguments]
        return run(command, input_bytes=input_bytes, check=check)

    def wait_healthy(service: str) -> str:
        container = compose("ps", "-q", service).stdout.decode().strip()
        if not container:
            raise RuntimeError(f"missing disposable service: {service}")
        for _ in range(90):
            status = run([docker, "inspect", "--format",
                          "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                          container]).stdout.decode().strip()
            if status == "healthy":
                return container
            if status == "unhealthy":
                raise RuntimeError(f"disposable service became unhealthy: {service}")
            time.sleep(2)
        raise RuntimeError(f"timed out waiting for disposable service: {service}")

    def request(path: str, *, token: str | None = None, method: str = "GET",
                body: dict | None = None, expected: int = 200) -> dict:
        headers: dict[str, str] = {}
        payload = None
        if token:
            headers["X-Admin-Token"] = token
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode()
        req = urllib.request.Request("http://127.0.0.1:8081" + path, data=payload,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=8) as response:
                status, result = response.status, response.read()
        except urllib.error.HTTPError as exc:
            status, result = exc.code, exc.read()
        if status != expected:
            raise AssertionError(f"{method} {path}: expected {expected}, got {status}")
        return json.loads(result) if result else {}

    cleanup_error: str | None = None
    try:
        if compose("ps", "-a", "-q", check=False).stdout.decode().strip():
            raise RuntimeError("unique disposable Compose project already exists")
        config = json.loads(compose("config", "--format", "json").stdout)
        services = config["services"]
        assert set(services) == {"postgres", "web"}
        assert not services["postgres"].get("ports")
        web_port = services["web"]["ports"][0]
        assert (web_port["host_ip"], web_port["target"], web_port["published"]) == ("127.0.0.1", 8080, "8081")
        assert set(services["postgres"]["networks"]) == {"staging_private"}
        assert set(services["web"]["networks"]) == {"staging_private", "staging_loopback"}
        assert config["networks"]["staging_private"]["internal"] is True
        assert config["networks"]["staging_loopback"]["driver_opts"][
            "com.docker.network.bridge.enable_ip_masquerade"] == "false"
        assert config["networks"]["staging_loopback"]["driver_opts"][
            "com.docker.network.bridge.name"] == "slv2stage0"
        assert config["networks"]["staging_private"]["driver_opts"][
            "com.docker.network.bridge.name"] == "slv2priv0"
        assert services["web"]["environment"]["ACTIVE_SCANNING_ENABLED"] == "false"
        rendered = json.dumps(config)
        for value in secrets_by_name.values():
            assert value not in rendered, "generated secret appeared in Compose config"
        print("PASS: Compose network, loopback bind, unpublished DB port and secret handling")

        compose("up", "-d", "postgres", "web")
        db_container = wait_healthy("postgres")
        wait_healthy("web")
        assert request("/api/health")["active_scanning"] is False
        request("/api/worker/register", method="POST", body={}, expected=503)
        request("/api/admin/workers", expected=401)
        assert "workers" in request("/api/admin/workers", token=secrets_by_name["admin"])
        fixture = {"provenance": "isolated synthetic local staging fixture", "observations": [{
            "ip": "192.0.2.77", "port": 443, "country": "ZZ", "service": "https",
            "banner": "synthetic staging only",
        }]}
        assert request("/api/admin/import", token=secrets_by_name["admin"], method="POST", body=fixture)["imported"] == 1
        assert request("/api/search?q=ip%3A192.0.2.77")["total"] == 1
        print("PASS: health, admin auth, scan kill switch, synthetic import and search")

        db_ports = json.loads(run([docker, "inspect", "--format", "{{json .NetworkSettings.Ports}}",
                                   db_container]).stdout)
        assert db_ports.get("5432/tcp") in (None, [])
        assert run([docker, "network", "inspect", "--format", "{{.Internal}}",
                    f"{project}_staging_private"]).stdout.strip() == b"true"
        bridge_name = run([docker, "network", "inspect", "--format",
                           '{{index .Options "com.docker.network.bridge.name"}}',
                           f"{project}_staging_loopback"]).stdout.decode().strip()
        assert bridge_name == "slv2stage0", f"unexpected staging bridge interface: {bridge_name!r}"
        private_bridge_name = run([docker, "network", "inspect", "--format",
                                   '{{index .Options "com.docker.network.bridge.name"}}',
                                   f"{project}_staging_private"]).stdout.decode().strip()
        assert private_bridge_name == "slv2priv0", f"unexpected private staging bridge: {private_bridge_name!r}"
        compose("restart", "postgres")
        wait_healthy("postgres")
        compose("restart", "web")
        wait_healthy("web")
        assert request("/api/search?q=ip%3A192.0.2.77")["total"] == 1
        print("PASS: DB port isolation and indexed-record persistence across restart")

        compose("--profile", "backup-restore-test", "up", "-d", "postgres-restore-test")
        wait_healthy("postgres-restore-test")
        backup = compose("exec", "-T", "postgres", "pg_dump", "-U", "scanlattice_staging",
                         "-Fc", "scanlattice_staging").stdout
        assert backup.startswith(b"PGDMP")
        backup_file = work / "postgres.dump"
        backup_file.write_bytes(backup)
        backup_file.chmod(0o600)
        compose("exec", "-T", "postgres-restore-test", "pg_restore", "-U", "scanlattice_restore",
                "--exit-on-error", "--no-owner", "--role=scanlattice_restore", "-d", "restore_empty",
                input_bytes=backup)

        def restored_query(sql: str) -> int:
            output = compose("exec", "-T", "postgres-restore-test", "psql", "-U", "scanlattice_restore",
                             "-d", "restore_empty", "-tAc", sql).stdout.decode().strip()
            return int(output)

        assert restored_query("SELECT count(*) FROM schema_migrations;") > 0
        assert restored_query("SELECT count(*) FROM hosts;") == 1
        print("PASS: PostgreSQL backup restored to separate empty target; schema and data reconcile")

        logs = compose("logs", "--no-color").stdout.decode("utf-8", "replace")
        for value in secrets_by_name.values():
            assert value not in logs, "generated secret appeared in service logs"
        print("PASS: generated credentials absent from service logs")
    finally:
        down = compose("--profile", "backup-restore-test", "down", "--volumes", "--remove-orphans", check=False)
        remaining = compose("ps", "-a", "-q", check=False).stdout.decode().strip()
        volume_names = run([docker, "volume", "ls", "--filter",
                            f"label=com.docker.compose.project={project}", "--format", "{{.Name}}"], check=False).stdout.decode().splitlines()
        network_names = run([docker, "network", "ls", "--filter",
                             f"label=com.docker.compose.project={project}", "--format", "{{.Name}}"], check=False).stdout.decode().splitlines()
        if down.returncode or remaining or volume_names or network_names:
            cleanup_error = f"disposable project resources remain: {project}"
        shutil.rmtree(work, ignore_errors=True)
        if cleanup_error:
            raise RuntimeError(cleanup_error)
        print("PASS: disposable containers, volumes, network, backup and secret files removed")


if __name__ == "__main__":
    main()
