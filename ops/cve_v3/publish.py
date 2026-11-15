#!/usr/bin/env python3
"""Publish CVE V3 on production's intentionally read-only Docker rootfs.

Deploys a single read-only bind mount of a COMPLETE copy of current static/
assets using a separate Compose override. Never docker-cp *into* a container.
Changing the dynamic JSON report updates host files, without container restarts.
The original Compose and production image are left unchanged; rollback simply
recreates the web service without the override.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

CONTAINER = "scanlattice-v2-prodweb-web-1"
PROJECT = "scanlattice-v2-prodweb"
COMPOSE_DIR = Path("/etc/scanlattice/v2-prodweb")
COMPOSE = COMPOSE_DIR / "compose.yaml"
OVERRIDE = COMPOSE_DIR / "cve-v3.readonly.override.yaml"
LOCAL_REPORT = Path("/var/lib/scanlattice-cve/cve-v3-public.json")
BACKUPS = Path("/var/lib/scanlattice-cve/site-v3-backups")
PUBLISHED = Path("/var/lib/scanlattice-cve/site-v3-static")
SCRIPT = Path("/usr/local/lib/scanlattice/cve_v3/cve-v3.js")
SCRIPT_TAG = '<script src="/static/cve-v3.js" defer></script>'
IMAGE = "scanlattice-prodweb:cve-bulk-v1"
BASE_HEALTH = "https://scanlattice.plezi.eu/api/health"
JS_URL = "https://scanlattice.plezi.eu/static/cve-v3.js"
REPORT_URL = "https://scanlattice.plezi.eu/static/cve-v3-public.json"


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, **kwargs)


def compose(*args, override=False):
    command = ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE)]
    if override:
        command += ["-f", str(OVERRIDE)]
    command.extend(args)
    return subprocess.run(command, cwd=COMPOSE_DIR, check=True,
                          capture_output=True, text=True)


def container_static():
    result = docker(
        "exec", CONTAINER, "python", "-c",
        "from pathlib import Path; import app; print(Path(app.__file__).parent/'static')",
        capture_output=True, text=True)
    path = result.stdout.strip()
    if not re.fullmatch(r"/[A-Za-z0-9_/.-]+/static", path):
        raise RuntimeError("Unexpected production static path: " + repr(path))
    return path


def ui_features(html):
    def has_id(name):
        expression = r"""\bid\s*=\s*(['"])""" + re.escape(name) + r"""\1"""
        return bool(re.search(expression, html, re.IGNORECASE))
    lower = html.lower()
    return {
        "host-content": has_id("host-content"),
        "insight-content": has_id("insight-content"),
        "app.js": "/app.js" in lower,
        "insights.js": "/insights.js" in lower,
        "body-close": lower.count("</body>") == 1,
    }


def validate_ui(html):
    missing = [name for name, yes in ui_features(html).items() if not yes]
    if missing:
        raise RuntimeError(
            "Production UI missing required V3 targets: " + ", ".join(missing)
            + "; no files modified")
    return True


def patched_index(html):
    validate_ui(html)
    if SCRIPT_TAG not in html:
        if html.lower().count("</body>") != 1:
            raise RuntimeError("Cannot insert V3 script into this HTML")
        html = re.sub(r"</body>", SCRIPT_TAG + "</body>", html, count=1,
                      flags=re.IGNORECASE)
    return html


def atomic_bytes(destination, raw):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as f:
        temp = Path(f.name)
        f.write(raw)
        f.flush()
        os.fchmod(f.fileno(), 0o644)
        os.fsync(f.fileno())
    os.replace(temp, destination)


def atomic_copy(source, destination):
    raw = Path(source).read_bytes()
    if destination.exists() and destination.read_bytes() == raw:
        return
    atomic_bytes(destination, raw)


def checked_report():
    if not SCRIPT.is_file() or not LOCAL_REPORT.is_file():
        raise RuntimeError("Missing V3 script/report. Run V3 assess/merge first.")
    data = json.loads(LOCAL_REPORT.read_text())
    if data.get("schema_version") != 1 or not isinstance(data.get("findings"), list):
        raise RuntimeError("V3 report invalid. No files changed.")


def image_check():
    actual = docker("inspect", "-f", "{{.Config.Image}}", CONTAINER,
                    capture_output=True, text=True).stdout.strip()
    if actual not in (IMAGE,):
        raise RuntimeError("Production image is " + actual
                           + "; expected " + IMAGE + ". Refusing redeployment.")
    # The two different Compose stacks must refer to the same production image.
    imgs = compose("config", "--images").stdout.splitlines()
    if actual not in imgs:
        raise RuntimeError("Original compose image differs from running web image: "
                           + repr(imgs))


def overlay_yaml(target):
    # Docker Compose merges the new mount with other existing service mounts.
    # Source is an explicit absolute path and target is validated.
    return ("services:\n"
            "  web:\n"
            "    volumes:\n"
            "      - type: bind\n"
            f"        source: {str(PUBLISHED)}\n"
            f"        target: {target}\n"
            "        read_only: true\n")


def health_check():
    error = None
    # Docker Compose may report "running" before the FastAPI process is ready.
    # Retry the real public endpoints before considering rollback.
    for attempt in range(10):
        try:
            for url in (BASE_HEALTH, JS_URL, REPORT_URL):
                request = urllib.request.Request(
                    url, headers={"Cache-Control": "no-cache",
                                  "User-Agent": "ScanLattice-V3-Publisher/2.0"})
                with urllib.request.urlopen(request, timeout=8) as response:
                    body = response.read(15_000_000 + 1)
                    if response.status != 200:
                        raise RuntimeError("Public endpoint unhealthy: " + url)
                if url == JS_URL and b"ScanLattice V3" not in body:
                    raise RuntimeError("Public CVE V3 JS mismatch")
                if url == REPORT_URL:
                    result = json.loads(body)
                    if result.get("schema_version") != 1:
                        raise RuntimeError("Public V3 JSON invalid")
            return
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            error = exc
            if attempt != 9:
                time.sleep(2)
    raise RuntimeError("V3 public health check did not pass: " + str(error))


def inspect_ui():
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory) / "index.html"
        target = container_static()
        docker("cp", f"{CONTAINER}:{target}/index.html", str(temp))
        html = temp.read_text()
        print(json.dumps(ui_features(html), indent=2))
        validate_ui(html)
        print("Production DOM compatible with CVE V3.")


def prepare_static():
    checked_report()
    if not COMPOSE.is_file():
        raise RuntimeError("Production Compose missing: " + str(COMPOSE))
    image_check()
    target = container_static()
    BACKUPS.mkdir(parents=True, exist_ok=True)

    # Avoid shadowing other volumes already mounted under static/.
    details = json.loads(docker("inspect", CONTAINER, capture_output=True,
                                text=True).stdout)[0]
    for mount in details.get("Mounts", []):
        dst = mount.get("Destination", "")
        if (dst == target or dst.startswith(target + "/")) and not (
            OVERRIDE.is_file() and PUBLISHED.is_dir() and dst == target
        ):
            raise RuntimeError("Existing static mount at " + dst
                               + "; refusing to replace it.")

    if not PUBLISHED.exists():
        # Copy the whole static folder, not just index.html, so original
        # stylesheets, app.js and world-map files remain accessible.
        tmp = PUBLISHED.with_name(PUBLISHED.name + ".stage")
        if tmp.exists():
            shutil.rmtree(tmp)
        tmp.mkdir(parents=True, exist_ok=False)
        try:
            docker("cp", f"{CONTAINER}:{target}/.", str(tmp))
            html = (tmp / "index.html").read_text()
            validate_ui(html)
            atomic_bytes(tmp / "index.html", patched_index(html).encode())
            if not (BACKUPS / "index.html").exists():
                shutil.copyfile(tmp / "index.html", BACKUPS / "index-v3-template.html")
                docker("cp", f"{CONTAINER}:{target}/index.html",
                       str(BACKUPS / "index.html"))
            atomic_copy(SCRIPT, tmp / "cve-v3.js")
            atomic_copy(LOCAL_REPORT, tmp / "cve-v3-public.json")
            os.rename(tmp, PUBLISHED)
        except Exception:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
    else:
        # If an interrupted run created the directory, insist that the
        # expected static entrypoint and application assets exist.
        for asset in ("index.html", "app.js", "insights.js"):
            if not (PUBLISHED / asset).is_file():
                raise RuntimeError("Incomplete V3 static directory: " + asset)
        atomic_bytes(PUBLISHED / "index.html",
                     patched_index((PUBLISHED / "index.html").read_text()).encode())
        atomic_copy(SCRIPT, PUBLISHED / "cve-v3.js")
        atomic_copy(LOCAL_REPORT, PUBLISHED / "cve-v3-public.json")

    yaml = overlay_yaml(target)
    if OVERRIDE.exists() and OVERRIDE.read_text() != yaml:
        raise RuntimeError("Existing CVE V3 override differs from expected; no changes made")
    if not OVERRIDE.exists():
        atomic_bytes(OVERRIDE, yaml.encode())
    compose("config", "--quiet", override=True)
    return target


def already_mounted(target):
    details = json.loads(docker("inspect", CONTAINER, capture_output=True,
                                text=True).stdout)[0]
    return any(m.get("Destination") == target and
               Path(m.get("Source", "")).resolve() == PUBLISHED.resolve()
               for m in details.get("Mounts", []))


def deploy(retire=False):
    target = container_static()
    if retire:
        if not already_mounted(target):
            raise RuntimeError("V3 overlay not active; will not retire Explorer")
        health_check()
        explorer = PUBLISHED / "cve-explorer.html"
        if explorer.is_file():
            explorer.unlink()
        print("Temporary Explorer retired in V3 static mount; original image unchanged.")
        return

    target = prepare_static()
    if already_mounted(target):
        print("Read-only V3 static mount active; refreshed report without restarting web.")
        return
    print("Applying Compose override with read-only V3 static mount...")
    try:
        compose("up", "-d", "--no-deps", "--no-build", "web", override=True)
        if not already_mounted(target):
            raise RuntimeError("New web container did not mount V3 assets")
        health_check()
    except Exception:
        print("V3 activation failed; attempting automatic rollback to original Compose.")
        try:
            compose("up", "-d", "--no-deps", "--no-build", "web")
        except Exception as rollback_error:
            print("ROLLBACK FAILED: " + str(rollback_error))
        raise
    print("V3 overlay active and public health/assets verified.")


def rollback():
    print("Recreating web from ORIGINAL Compose file; CVE data is preserved.")
    compose("up", "-d", "--no-deps", "--no-build", "web")
    print("V3 static override removed from running container. Original image restored.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command",
                        choices=["inspect", "install", "retire-explorer", "rollback"])
    args = parser.parse_args()
    if args.command == "inspect":
        inspect_ui()
    elif args.command == "rollback":
        rollback()
    else:
        deploy(retire=args.command == "retire-explorer")


if __name__ == "__main__":
    main()
