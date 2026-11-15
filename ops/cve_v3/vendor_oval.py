#!/usr/bin/env python3
"""Export authenticated Ubuntu OVAL package evidence for ScanLattice.

Execute ON the Ubuntu machine being assessed (not on Debian control plane).
No remote scanning or SSH credentials; uses the local package database via
OpenSCAP and Canonical's official USN OVAL definitions.
"""
from __future__ import annotations

import argparse
import bz2
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

def lname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]

def refs_by_definition(path):
    """Read potentially large Canonical definitions with bounded XML memory."""
    mapping = {}
    for _, item in ET.iterparse(path, events=("end",)):
        if lname(item.tag) != "definition":
            continue
        identifier = item.get("id")
        if identifier:
            cves = {
                ref.get("ref_id", "").upper()
                for ref in item.iter()
                if lname(ref.tag) == "reference" and
                   re.fullmatch(r"CVE-\d{4}-\d{4,}", ref.get("ref_id", ""), re.I)
            }
            if cves:
                mapping[identifier] = sorted(cves)
        item.clear()
    return mapping

def oval_results(path):
    """Map OVAL definition ID to result from a local oscap evaluation."""
    output = {}
    for _, item in ET.iterparse(path, events=("end",)):
        if lname(item.tag) == "definition" and item.get("definition_id"):
            status = (item.get("result") or "").lower()
            if status in {"true", "false", "unknown", "error", "not evaluated", "not applicable"}:
                output[item["definition_id"] if False else item.get("definition_id")] = status
            item.clear()
    return output

def aggregate(definitions, results):
    """True = package check affected. False = vendor test did not report affected.

    Do NOT equate false with 'patched': the affected package may be absent.
    """
    merged = {}
    for definition_id, cves in definitions.items():
        status = results.get(definition_id)
        if not status:
            continue
        for cve in cves:
            prev = merged.get(cve)
            if status == "true":
                merged[cve] = "vendor_affected"
            elif status == "false" and prev is None:
                merged[cve] = "vendor_not_affected"
            elif status != "false" and prev is None:
                merged[cve] = "vendor_unknown"
    return merged

def os_release(path="/etc/os-release"):
    fields = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            fields[k] = v.strip().strip('"')
    if fields.get("ID") != "ubuntu":
        raise RuntimeError("Only local Ubuntu installations are supported by this exporter")
    codename = fields.get("VERSION_CODENAME", "")
    if not re.fullmatch(r"[a-z]{4,12}", codename):
        raise RuntimeError("Ubuntu VERSION_CODENAME missing or invalid")
    return codename

def download_definitions(codename, directory):
    directory.mkdir(parents=True, exist_ok=True)
    name = f"com.ubuntu.{codename}.usn.oval.xml"
    path = directory / name
    url = f"https://security-metadata.canonical.com/oval/{name}.bz2"
    req = urllib.request.Request(url, headers={"User-Agent": "ScanLattice-OVAL/1.0"})
    with urllib.request.urlopen(req, timeout=180) as response:
        compressed = response.read(120_000_000 + 1)
    if len(compressed) > 120_000_000:
        raise RuntimeError("Canonical definition file exceeds safety limit")
    contents = bz2.decompress(compressed)
    if len(contents) > 1_500_000_000:
        raise RuntimeError("Canonical definitions exceed decompressed size limit")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(contents)
    os.replace(tmp, path)
    return path

def export(host_ip, output, definitions=None, results=None, definitions_dir=None):
    address = str(ipaddress.ip_address(host_ip))
    codename = os_release()
    directory = Path(definitions_dir or "/var/lib/scanlattice-oval")
    if definitions:
        definitions_path = Path(definitions)
    else:
        definitions_path = download_definitions(codename, directory)
    if results:
        results_path = Path(results)
    else:
        results_path = directory / "oscap-result.xml"
        result = subprocess.run(
            ["oscap", "oval", "eval", "--results", str(results_path),
             str(definitions_path)], check=False
        )
        # OpenSCAP returns non-zero for failed/error checks on some releases:
        # Require the generated result and parse its per-definition statuses.
        if not results_path.exists() or results_path.stat().st_size == 0:
            raise RuntimeError(f"OpenSCAP generated no results (exit {result.returncode})")
    references = refs_by_definition(definitions_path)
    statuses = oval_results(results_path)
    by_cve = aggregate(references, statuses)
    payload = {
        "schema_version": 1,
        "ip": address,
        "os_family": "ubuntu",
        "os_codename": codename,
        "source": "canonical_ubuntu_usn_oval_local_openscap",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "definitions": len(references),
        "evaluated_definitions": len(statuses),
        "cve_status": by_cve,
        "meaning": {
            "vendor_affected": "OpenSCAP local package evaluation returned true",
            "vendor_not_affected": "OpenSCAP returned false (may be patched or not installed)",
            "vendor_unknown": "OpenSCAP could not establish applicability"
        },
    }
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_suffix(destination.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    os.chmod(tmp, 0o600)
    os.replace(tmp, destination)
    print(f"OVAL local export: {len(by_cve)} CVE statuses -> {destination}", flush=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ip", required=True, help="IP of THIS Ubuntu host as indexed by ScanLattice")
    p.add_argument("--output", required=True)
    p.add_argument("--definitions", help="Use previously downloaded Canonical OVAL definitions XML")
    p.add_argument("--results", help="Use existing OpenSCAP results XML")
    p.add_argument("--definitions-dir")
    a = p.parse_args()
    export(a.ip, a.output, a.definitions, a.results, a.definitions_dir)

if __name__ == "__main__":
    main()
