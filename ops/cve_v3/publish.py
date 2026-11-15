#!/usr/bin/env python3
"""Safely overlay the running ScanLattice main UI with the CVE V3 panel.

No Docker image/build changes, no PostgreSQL writes. Backups are made before
patching the current container. Re-run after container recreation.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request

CONTAINER="scanlattice-v2-prodweb-web-1"
LOCAL_REPORT=Path("/var/lib/scanlattice-cve/cve-v3-public.json")
BACKUPS=Path("/var/lib/scanlattice-cve/site-v3-backups")
SCRIPT=Path("/usr/local/lib/scanlattice/cve_v3/cve-v3.js")
SCRIPT_TAG='<script src="/static/cve-v3.js" defer></script>'

def docker(*args,**kwargs):
    return subprocess.run(["docker",*args],check=True,**kwargs)

def static_dir():
    result=docker("exec",CONTAINER,"python","-c",
                  "from pathlib import Path; import app; print(Path(app.__file__).parent/'static')",
                  text=True,capture_output=True)
    path=result.stdout.strip()
    if not path.startswith("/") or not path.endswith("/static"):
        raise RuntimeError("Unexpected production static directory: "+repr(path))
    return path

def cp_from(path, dest):
    docker("cp",f"{CONTAINER}:{path}",str(dest))
def cp_to(src,path):
    docker("cp",str(src),f"{CONTAINER}:{path}")

def backup_once(source, backup):
    backup.parent.mkdir(parents=True,exist_ok=True)
    if not backup.exists():
        cp_from(source,backup)

def verify_public():
    with urllib.request.urlopen("https://scanlattice.plezi.eu/static/cve-v3.js",timeout=15) as response:
        script=response.read(5_000_000).decode()
    if "ScanLattice V3" not in script:
        raise RuntimeError("CVE V3 script not available at the public site")
    with urllib.request.urlopen("https://scanlattice.plezi.eu/static/cve-v3-public.json",timeout=15) as response:
        result=json.loads(response.read(10_000_000))
    if result.get("schema_version")!=1 or not isinstance(result.get("findings"),list):
        raise RuntimeError("Public V3 report is invalid")

def ui_features(html):
    """Check actual DOM targets used by app.js and cve-v3.js.

    Do not require nav text or a page-host marker: production templates may
    omit/rename those while keeping the same host and insight containers.
    """
    def has_id(name):
        pattern = r"""\\bid\\s*=\\s*([\\"'])""" + re.escape(name) + r"""\\1"""
        return bool(re.search(pattern, html, re.IGNORECASE))
    return {
        "host-content": has_id("host-content"),
        "insight-content": has_id("insight-content"),
        "app.js": bool(re.search(r"<script\\b[^>]+\\bapp\\.js(?:\\?[^\\"']*)?[\\"']", html, re.I)),
        "insights.js": bool(re.search(r"<script\\b[^>]+\\binsights\\.js(?:\\?[^\\"']*)?[\\"']", html, re.I)),
        "body-close": html.lower().count("</body>") == 1,
    }


def validate_ui(html):
    features = ui_features(html)
    missing = [name for name, value in features.items() if not value]
    if missing:
        raise RuntimeError(
            "Production UI missing required V3 targets: " + ", ".join(missing)
            + ". No site files modified."
        )
    return features


def inspect_ui():
    with tempfile.TemporaryDirectory() as temporary:
        local = Path(temporary) / "index.html"
        cp_from(f"{static_dir()}/index.html", local)
        html = local.read_text()
        print(json.dumps(ui_features(html), indent=2))
        validate_ui(html)
        print("Production DOM compatible with CVE V3 overlay.")


def deploy(retire=False):
    if not SCRIPT.is_file() or not LOCAL_REPORT.is_file():
        raise RuntimeError("Missing V3 script/report. Run reconcile first.")
    report=json.loads(LOCAL_REPORT.read_text())
    if report.get("schema_version")!=1:
        raise RuntimeError("Invalid public CVE V3 report")
    target=static_dir()
    original=BACKUPS/"index.html"
    backup_once(f"{target}/index.html",original)
    with tempfile.TemporaryDirectory() as temporary:
        tmp=Path(temporary)
        live=tmp/"index.html"
        cp_from(f"{target}/index.html",live)
        html=live.read_text()
        validate_ui(html)
        if SCRIPT_TAG not in html:
            if html.count("</body>")!=1:
                raise RuntimeError("Unexpected index.html body; no modifications made")
            html=html.replace("</body>",SCRIPT_TAG+"</body>")
            live.write_text(html)
        # Install script and report before enabling UI script tag.
        cp_to(SCRIPT,f"{target}/cve-v3.js")
        cp_to(LOCAL_REPORT,f"{target}/cve-v3-public.json")
        cp_to(live,f"{target}/index.html")
    print("V3 main UI overlay installed on",CONTAINER)
    if retire:
        verify_public()
        legacy=BACKUPS/"cve-explorer.html"
        try:
            backup_once(f"{target}/cve-explorer.html",legacy)
        except subprocess.CalledProcessError:
            # Already absent is okay.
            pass
        docker("exec","-u","0",CONTAINER,"rm","-f",
               f"{target}/cve-explorer.html")
        print("Retired temporary CVE Explorer (verified main V3 assets first)")

def rollback():
    target=static_dir()
    original=BACKUPS/"index.html"
    if not original.exists():raise RuntimeError("No original main site backup")
    cp_to(original,f"{target}/index.html")
    legacy=BACKUPS/"cve-explorer.html"
    if legacy.exists():cp_to(legacy,f"{target}/cve-explorer.html")
    docker("exec","-u","0",CONTAINER,"rm","-f",
           f"{target}/cve-v3.js",f"{target}/cve-v3-public.json")
    print("Original site index and temporary Explorer restored where available")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("command",choices=["inspect","install","retire-explorer","rollback"])
    a=p.parse_args()
    if a.command=="inspect":inspect_ui()
    elif a.command=="rollback":rollback()
    else:deploy(retire=a.command=="retire-explorer")

if __name__=="__main__":main()
