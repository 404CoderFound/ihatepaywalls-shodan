"""Disposable local Docker smoke test for the production PostgreSQL template.

This test requires a local Docker Unix socket. It generates unique Compose,
network, volume, and secret names, checks for collisions before starting, tests
health/port isolation/persistence, and removes only its own Compose resources.
It refuses TCP/SSH Docker contexts and never uses a production Compose project.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "deploy" / "compose.postgresql-production.yaml"


class SmokeTestError(RuntimeError):
    pass


def command(args: list[str], *, env: dict[str, str] | None = None,
            cwd: Path | None = None, timeout: int = 60,
            check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
        check=False,
    )
    if check and result.returncode:
        # Do not forward child output: Compose/database errors can include paths
        # or environment details that should stay local.
        raise SmokeTestError(f"{args[0]} operation failed (exit {result.returncode})")
    return result


def assert_local_context() -> tuple[str, dict[str, str]]:
    if os.environ.get("DOCKER_HOST"):
        raise SmokeTestError("Refusing DOCKER_HOST override; select a local Docker context")
    context = command(["docker", "context", "show"]).stdout.strip()
    endpoint_json = command([
        "docker", "context", "inspect", "--format",
        "{{json .Endpoints.docker}}", context,
    ]).stdout
    try:
        endpoint = json.loads(endpoint_json)["Host"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SmokeTestError("Unable to identify the active Docker endpoint") from exc
    if not endpoint.startswith("unix://"):
        raise SmokeTestError("Refusing non-local Docker endpoint; a Unix socket is required")
    command(["docker", "info", "--format", "{{.Name}}"], timeout=20)
    return context, {k: v for k, v in os.environ.items() if k != "DOCKER_HOST"}


def validate_rendered_config(config: dict[str, Any], network: str, volume: str) -> None:
    if set(config.get("services", {})) != {"postgres"}:
        raise SmokeTestError("Smoke Compose must contain only the PostgreSQL service")
    service = config["services"]["postgres"]
    if service.get("ports"):
        raise SmokeTestError("Refusing a Compose config that publishes a host port")
    if set(service.get("networks", {})) != {"postgres_private"}:
        raise SmokeTestError("PostgreSQL must use only its dedicated private network")
    network_config = config.get("networks", {}).get("postgres_private", {})
    if network_config.get("name") != network or not network_config.get("internal"):
        raise SmokeTestError("The PostgreSQL Docker network is not internal and isolated")
    volume_config = config.get("volumes", {}).get("pgdata", {})
    if volume_config.get("name") != volume:
        raise SmokeTestError("The smoke test volume name did not resolve uniquely")
    mounts = service.get("volumes", [])
    if not any(v.get("type") == "volume" and v.get("source") == "pgdata"
               and v.get("target") == "/var/lib/postgresql/data" for v in mounts):
        raise SmokeTestError("The PostgreSQL data directory is not on its named volume")


def inspect_missing(kind: str, name: str) -> None:
    check = command(["docker", kind, "inspect", name], check=False)
    if check.returncode == 0:
        raise SmokeTestError(f"Refusing to reuse pre-existing Docker {kind}: {name}")
    if "no such" not in check.stderr.lower() and "not found" not in check.stderr.lower():
        raise SmokeTestError(f"Unable to verify that Docker {kind} name is unused")


def assert_owned_resource(kind: str, name: str, project: str) -> bool:
    result = command(["docker", kind, "inspect", name], check=False)
    if result.returncode:
        message = result.stderr.lower()
        if "no such" not in message and "not found" not in message:
            raise SmokeTestError(f"Unable to confirm ownership of smoke-test {kind}")
        return False
    obj = json.loads(result.stdout)[0]
    labels = obj.get("Labels") or {}
    if labels.get("com.docker.compose.project") != project:
        raise SmokeTestError(f"Refusing to remove {kind} not owned by the unique smoke project")
    return True


def container_state(container_id: str) -> dict[str, Any]:
    raw = command(["docker", "inspect", container_id]).stdout
    return json.loads(raw)[0]


def assert_container_isolated(container_id: str, network: str) -> None:
    obj = container_state(container_id)
    if obj.get("State", {}).get("Health", {}).get("Status") != "healthy":
        raise SmokeTestError("PostgreSQL container did not become healthy")
    attached = obj.get("NetworkSettings", {}).get("Networks", {})
    if set(attached) != {network}:
        raise SmokeTestError("PostgreSQL container is attached to an unexpected network")
    bindings = obj.get("HostConfig", {}).get("PortBindings") or {}
    if any(value for value in bindings.values()):
        raise SmokeTestError("PostgreSQL container has a host port binding")
    published = obj.get("NetworkSettings", {}).get("Ports") or {}
    if any(value for value in published.values() if value):
        raise SmokeTestError("PostgreSQL port is published on the host")


def main() -> int:
    context, env = assert_local_context()
    suffix = uuid.uuid4().hex[:12]
    project = f"sl-pg-smoke-{suffix}"
    network = f"sl-pg-smoke-{suffix}-private"
    volume = f"sl_pg_smoke_{suffix}_data"
    marker = f"smoke-{suffix}"

    inspect_missing("volume", volume)
    inspect_missing("network", network)
    with tempfile.TemporaryDirectory(prefix="scanlattice-pg-smoke-") as temp_dir:
        temp = Path(temp_dir)
        secret_file = temp / "postgres-password"
        secret_file.write_text(secrets.token_hex(48) + "\n")
        secret_file.chmod(0o600)
        compose_file = temp / "compose.postgres.smoke.yaml"
        rendered_source = TEMPLATE.read_text()
        rendered_source = rendered_source.replace(
            "scanlattice_v2_postgresql_data", volume
        ).replace("scanlattice_postgresql_private", network)
        compose_file.write_text(rendered_source)
        env["SCANLATTICE_PG_PASSWORD_FILE"] = str(secret_file)

        def compose(*args: str, timeout: int = 60, check: bool = True):
            return command([
                "docker", "compose", "--env-file", "/dev/null", "-p", project,
                "-f", str(compose_file), *args,
            ], env=env, cwd=ROOT, timeout=timeout, check=check)

        if compose("ps", "--all", "--quiet").stdout.strip():
            raise SmokeTestError("Refusing to reuse a pre-existing Compose project")
        config_output = compose("config", "--format", "json").stdout
        validate_rendered_config(json.loads(config_output), network, volume)
        launched = False
        try:
            launched = True  # up can create resources before returning an error
            compose("up", "-d", "--wait", "--wait-timeout", "120", "postgres", timeout=150)
            first_id = compose("ps", "-q", "postgres").stdout.strip()
            if not first_id:
                raise SmokeTestError("Compose did not report a PostgreSQL container")
            assert_container_isolated(first_id, network)

            network_inspect = json.loads(command(["docker", "network", "inspect", network]).stdout)[0]
            if not network_inspect.get("Internal"):
                raise SmokeTestError("Docker network is not marked Internal")
            labels = network_inspect.get("Labels") or {}
            if labels.get("com.docker.compose.project") != project:
                raise SmokeTestError("Smoke network does not belong to the unique test project")

            volume_inspect = json.loads(command(["docker", "volume", "inspect", volume]).stdout)[0]
            if (volume_inspect.get("Labels") or {}).get("com.docker.compose.project") != project:
                raise SmokeTestError("Smoke volume does not belong to the unique test project")

            sql = (
                "CREATE TABLE IF NOT EXISTS smoke_probe (id text PRIMARY KEY, value text NOT NULL); "
                f"INSERT INTO smoke_probe VALUES ('{marker}', '{marker}');"
            )
            compose("exec", "-T", "postgres", "psql", "-U", "scanlattice", "-d",
                    "scanlattice", "-v", "ON_ERROR_STOP=1", "-c", sql)

            # Destroy and recreate only this uniquely named Compose project,
            # intentionally preserving its named data volume across recreation.
            compose("down", "--remove-orphans")
            if command(["docker", "volume", "inspect", volume], check=False).returncode:
                raise SmokeTestError("Named PostgreSQL volume did not survive Compose down")
            if command(["docker", "network", "inspect", network], check=False).returncode == 0:
                raise SmokeTestError("Smoke network remained after its containers stopped")
            compose("up", "-d", "--wait", "--wait-timeout", "120", "postgres", timeout=150)
            second_id = compose("ps", "-q", "postgres").stdout.strip()
            if not second_id or second_id == first_id:
                raise SmokeTestError("Compose did not recreate the PostgreSQL container")
            assert_container_isolated(second_id, network)
            result = compose(
                "exec", "-T", "postgres", "psql", "-U", "scanlattice", "-d",
                "scanlattice", "-At", "-v", "ON_ERROR_STOP=1", "-c",
                f"SELECT value FROM smoke_probe WHERE id='{marker}'",
            ).stdout.strip()
            if result != marker:
                raise SmokeTestError("PostgreSQL data did not persist after container recreation")
            print(f"PASS local PostgreSQL smoke: context={context}; healthy; internal network; no published ports; named-volume data survived recreation.")
        finally:
            if launched:
                # Safe because the project/network/volume names were generated
                # uniquely and checked absent before any resource was created.
                assert_owned_resource("volume", volume, project)
                assert_owned_resource("network", network, project)
                compose("down", "--volumes", "--remove-orphans")
                remaining_volume = assert_owned_resource("volume", volume, project)
                remaining_network = assert_owned_resource("network", network, project)
                if remaining_volume or remaining_network:
                    raise SmokeTestError("Could not remove all unique smoke-test resources")
                print("PASS cleanup: only the uniquely named smoke project, network, and volume were removed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SmokeTestError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL local PostgreSQL smoke: {exc}", file=sys.stderr)
        raise SystemExit(1)
