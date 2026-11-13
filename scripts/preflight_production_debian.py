#!/usr/bin/env python3
"""READ-ONLY ScanLattice Debian v1 inventory preflight for future v2 cutover.

Never starts/stops Docker containers, changes files, reads env-file contents
directly, or prints resolved environment values. Compose config and inspect
JSON are parsed in memory and only allowlisted structure is displayed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

WEB_DIR = Path("/opt/scanlattice/web")
BASE_COMPOSE = WEB_DIR / "compose.web.yaml"
RELEASE_COMPOSE = Path("/home/ihatepaywalls/scanlattice-release-v1/compose.release.yaml")
WEB_CONTAINER = "web-web-1"
WEB_PROJECT = "web"
WEB_NETWORK = "web_default"
WEB_VOLUME = "web_scanlattice_data"
EXPECTED_PORT = ("127.0.0.1", "8080", "8080")


class PreflightError(Exception):
    pass


def command_json(argv: list[str], *, cwd: Path | None = None):
    """Suppress raw command errors: they may contain secrets or env values."""
    try:
        p = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        raise PreflightError(f"Unable to run {argv[0]} ({type(exc).__name__})") from None
    if p.returncode:
        raise PreflightError(f"{argv[0]} returned error status {p.returncode}; raw stderr withheld")
    try:
        return json.loads(p.stdout)
    except (UnicodeDecodeError, ValueError):
        raise PreflightError(f"{argv[0]} returned invalid JSON") from None


def container_findings(obj: dict) -> tuple[list[str], list[str]]:
    failures = []
    observations = []
    labels = obj.get("Config", {}).get("Labels") or {}
    state = obj.get("State") or {}
    if not state.get("Running"):
        failures.append("Existing web container is not running")
    if labels.get("com.docker.compose.project") != WEB_PROJECT:
        failures.append("Existing web container belongs to an unexpected Compose project")
    if labels.get("com.docker.compose.service") != "web":
        failures.append("Existing web container has an unexpected Compose service label")
    configured = set(filter(None, (labels.get("com.docker.compose.project.config_files") or "").split(",")))
    expected = {str(BASE_COMPOSE), str(RELEASE_COMPOSE)}
    if configured != expected:
        failures.append("Running web container Compose-file list differs from expected two-file release")
    mounts = obj.get("Mounts") or []
    if not any(m.get("Type") == "volume" and m.get("Name") == WEB_VOLUME
               and m.get("Destination") == "/data" for m in mounts):
        failures.append("Expected persistent SQLite volume not mounted at /data")
    networks = (obj.get("NetworkSettings") or {}).get("Networks") or {}
    if WEB_NETWORK not in networks:
        failures.append("Existing web container not attached to expected web_default network")
    mappings = (obj.get("HostConfig") or {}).get("PortBindings") or {}
    binds = mappings.get("8080/tcp") or []
    if len(binds) != 1 or (binds[0].get("HostIp"), binds[0].get("HostPort")) != (
        EXPECTED_PORT[0], EXPECTED_PORT[1]
    ):
        failures.append("Web 8080 must have exactly one host binding at 127.0.0.1:8080")
    # A future system could add *other* published ports: refuse that too.
    if any(key != "8080/tcp" and val for key, val in mappings.items()):
        failures.append("Unexpected extra web port published")
    observations.append("Runtime image ref: " + str((obj.get("Config") or {}).get("Image", "<unknown>")))
    observations.append("Runtime image ID: " + str(obj.get("Image", "<unknown>")))
    return failures, observations


def compose_findings(conf: dict, obj: dict) -> list[str]:
    failures = []
    services = conf.get("services") or {}
    svc = services.get("web")
    if not isinstance(svc, dict):
        return ["Combined Compose config has no web service"]
    if svc.get("image") and svc["image"] != (obj.get("Config") or {}).get("Image"):
        failures.append("Compose image does not match running image reference")
    ports = svc.get("ports") or []
    expected = any(
        p.get("target") == 8080 and str(p.get("published")) == "8080"
        and p.get("host_ip") == "127.0.0.1"
        for p in ports if isinstance(p, dict)
    )
    if len(ports) != 1 or not expected:
        failures.append("Rendered Compose web port differs from 127.0.0.1:8080")
    volumes = svc.get("volumes") or []
    if not any(v.get("type") == "volume" and v.get("target") == "/data"
               for v in volumes if isinstance(v, dict)):
        failures.append("Rendered Compose does not preserve a named /data volume")
    return failures


def run() -> int:
    print("ScanLattice Debian v2 readiness — READ ONLY. No services changed.")
    for name in ("docker",):
        if not shutil.which(name):
            raise PreflightError(f"Missing command: {name}")
    for file in (BASE_COMPOSE, RELEASE_COMPOSE):
        if not file.is_file():
            raise PreflightError(f"Expected Compose file not present: {file}")
    info = command_json(["docker", "inspect", WEB_CONTAINER])
    if len(info) != 1:
        raise PreflightError("docker inspect did not identify exactly one web container")
    obj = info[0]
    failures, notes = container_findings(obj)
    conf = command_json([
        "docker", "compose", "-p", WEB_PROJECT,
        "-f", str(BASE_COMPOSE), "-f", str(RELEASE_COMPOSE),
        "config", "--format", "json"
    ], cwd=WEB_DIR)
    failures.extend(compose_findings(conf, obj))

    for args, name in (
        (["docker", "network", "inspect", WEB_NETWORK], WEB_NETWORK),
        (["docker", "volume", "inspect", WEB_VOLUME], WEB_VOLUME),
    ):
        response = command_json(args)
        if len(response) != 1 or response[0].get("Name") != name:
            failures.append(f"Docker resource identity mismatch: {name}")
    # The planned PostgreSQL volume must not already be occupied unexpectedly.
    try:
        proc = subprocess.run(["docker", "volume", "inspect",
            "scanlattice_v2_postgresql_data"], capture_output=True, check=False)
        if proc.returncode == 0:
            failures.append("Planned PostgreSQL volume already exists; review before deploying")
    except OSError:
        failures.append("Unable to check planned PostgreSQL volume")

    print("Host architecture:", os.uname().machine)
    print("Docker volume:", WEB_VOLUME, "mounted at /data (expected)")
    print("Docker network:", WEB_NETWORK, "(expected)")
    print("Expected Compose files:", BASE_COMPOSE, "&", RELEASE_COMPOSE)
    for note in notes:
        print(note)
    print("The active AWS worker and any in-flight jobs have NOT been inspected by this script.")
    if failures:
        for failure in failures:
            print("BLOCKER:", failure)
        print(f"NO-GO: {len(failures)} preflight issue(s); no production changes performed")
        return 1
    print("PASS: Debian web Compose/runtime structure matches known v1; no production changes performed")
    print("Note: this is NOT approval to migrate or cut over. A fresh DB backup,")
    print("worker drain, production PostgreSQL restore, and explicit approval remain mandatory.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except PreflightError as exc:
        print("NO-GO:", exc, file=sys.stderr)
        raise SystemExit(1)
