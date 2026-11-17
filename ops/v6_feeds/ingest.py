#!/usr/bin/env python3
"""ScanLattice V6: restart-safe continuous passive dataset ingestion.

A read-only data-feed watcher; no target connections, port scans, credentials
sent to feeds, or changes to the production Docker image. Imports via the
existing authenticated dataset API, one acknowledged batch at a time.
"""
from __future__ import annotations

import argparse
import csv
import fcntl
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_CONFIG = "/etc/scanlattice/v6-feeds/config.json"
MAX_JSONL_LINE = 2 * 1024 * 1024


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def config_read(path):
    c = json.loads(Path(path).read_text())
    base = urllib.parse.urlsplit(c.get("api_base", ""))
    if (base.scheme != "http" or base.hostname not in ("127.0.0.1", "localhost")
            or base.port != 8080 or base.username or base.password or
            base.path not in ("", "/") or base.query or base.fragment):
        raise ValueError("API endpoint must be http://127.0.0.1:8080")
    c["_api_base"] = "http://127.0.0.1:8080"
    state = Path(c.get("state_dir", "/var/lib/scanlattice-feeds")).resolve()
    if not state.is_absolute():
        raise ValueError("state_dir must be absolute")
    c["_state"] = state
    for key, low, high in (
        ("batch_records", 1, 1000),
        ("batch_bytes", 16384, 2 * 1024 * 1024),
        ("max_source_bytes", 1024, 20 * 1024 * 1024 * 1024),
        ("max_batches_per_run", 1, 50000),
    ):
        value = c.get(key)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"invalid configuration setting {key}")
    token_file = Path(c.get("admin_token_file", "")).resolve()
    if not token_file.is_relative_to(Path("/etc/scanlattice")):
        raise ValueError("admin_token_file must be under /etc/scanlattice")
    c["_token_file"] = token_file
    allowed = c.get("allowed_https_hosts", [])
    if not isinstance(allowed, list) or not all(
            isinstance(host, str) and re.fullmatch(r"[a-zA-Z0-9.-]+", host)
            for host in allowed):
        raise ValueError("allowed_https_hosts must contain DNS names")
    if not isinstance(c.get("sources"), list):
        raise ValueError("sources must be an array")
    ids = set()
    inbox = (state / "inbox").resolve()
    for source in c["sources"]:
        if not isinstance(source, dict):
            raise ValueError("source must be an object")
        ident = source.get("id")
        if (not isinstance(ident, str) or
                not re.fullmatch(r"[a-z0-9_-]{1,32}", ident) or ident in ids):
            raise ValueError("source ids must be unique lowercase names")
        ids.add(ident)
        if source.get("rights_confirmed") is not True:
            raise ValueError(f"{ident}: confirm data usage/redistribution rights first")
        if source.get("format") not in ("jsonl", "csv"):
            raise ValueError(f"{ident}: format must be jsonl or csv")
        if source.get("compression", "identity") not in ("identity", "gzip"):
            raise ValueError(f"{ident}: compression must be identity or gzip")
        url, path = source.get("url"), source.get("path")
        if bool(url) == bool(path):
            raise ValueError(f"{ident}: exactly one of url or path is required")
        if url:
            parts = urllib.parse.urlsplit(url)
            if (parts.scheme != "https" or parts.hostname not in allowed or
                    parts.username or parts.password or not parts.path or
                    parts.fragment or parts.query or parts.port not in (None, 443)):
                raise ValueError(f"{ident}: use a pre-approved HTTPS feed host")
        else:
            local = Path(path).resolve()
            if not local.is_relative_to(inbox) or local == inbox:
                raise ValueError(f"{ident}: local file must reside in {inbox}")
    return c


def database(state):
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    (state / "inbox").mkdir(mode=0o700, exist_ok=True)
    (state / "snapshots").mkdir(mode=0o700, exist_ok=True)
    db = sqlite3.connect(state / "feed-progress.sqlite3", timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS progress(
        source_id TEXT PRIMARY KEY, digest TEXT NOT NULL DEFAULT '',
        cursor INTEGER NOT NULL DEFAULT 0, complete INTEGER NOT NULL DEFAULT 0,
        etag TEXT NOT NULL DEFAULT '', modified TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '')""")
    db.commit()
    return db


def get_progress(db, sid):
    row = db.execute("SELECT * FROM progress WHERE source_id=?", (sid,)).fetchone()
    return dict(row) if row else None


def save_progress(db, sid, **fields):
    names = {"digest", "cursor", "complete", "etag", "modified", "error"}
    if not set(fields).issubset(names):
        raise ValueError("unrecognized progress field")
    db.execute("INSERT OR IGNORE INTO progress(source_id) VALUES (?)", (sid,))
    if fields:
        columns = ", ".join(k + "=?" for k in fields)
        db.execute(f"UPDATE progress SET {columns},updated_at=? WHERE source_id=?",
                   (*fields.values(), utcnow(), sid))
    db.commit()


def file_hash(path):
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        while buf := stream.read(131072):
            sha.update(buf)
    return sha.hexdigest()


def bounded_copy(reader, writer, limit):
    size = 0
    while data := reader.read(131072):
        size += len(data)
        if size > limit:
            raise ValueError("feed file exceeded configured byte limit")
        writer.write(data)


def check_public_dns(host):
    records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not records:
        raise ValueError("feed host did not resolve")
    if not all(ipaddress.ip_address(record[4][0]).is_global for record in records):
        raise ValueError("feed resolves to a local or private address")


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("feed redirects are not permitted")


def acquire(c, source, previous):
    """Capture a full new version atomically; never process partial downloads."""
    sid = source["id"]
    target = c["_state"] / "snapshots" / (sid + ".data")
    etag = modified = ""
    if source.get("url"):
        url = source["url"]
        check_public_dns(urllib.parse.urlsplit(url).hostname)
        headers = {"User-Agent": "ScanLattice-v6-feed-reader/1.0"}
        if previous and previous["complete"] and target.is_file():
            if previous["etag"]:
                headers["If-None-Match"] = previous["etag"]
            if previous["modified"]:
                headers["If-Modified-Since"] = previous["modified"]
        req = urllib.request.Request(url, headers=headers)
        try:
            response = urllib.request.build_opener(RejectRedirect).open(req, timeout=60)
        except urllib.error.HTTPError as exc:
            if exc.code == 304 and previous and previous["complete"] and target.is_file():
                if file_hash(target) == previous["digest"]:
                    return target, previous["digest"], previous["etag"], previous["modified"]
            raise
        with response:
            if urllib.parse.urlsplit(response.url).hostname != urllib.parse.urlsplit(url).hostname:
                raise ValueError("feed address changed unexpectedly")
            etag = response.headers.get("ETag", "")[:512]
            modified = response.headers.get("Last-Modified", "")[:512]
            with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as out:
                temp = Path(out.name)
                try:
                    bounded_copy(response, out, c["max_source_bytes"])
                    out.flush()
                    os.fsync(out.fileno())
                except BaseException:
                    temp.unlink(missing_ok=True)
                    raise
    else:
        local = Path(source["path"]).resolve()
        if not local.is_file():
            raise FileNotFoundError(local)
        if local.stat().st_size > c["max_source_bytes"]:
            raise ValueError("local feed exceeds configured size")
        with local.open("rb") as stream, tempfile.NamedTemporaryFile(
                dir=target.parent, delete=False) as out:
            temp = Path(out.name)
            try:
                bounded_copy(stream, out, c["max_source_bytes"])
                out.flush()
                os.fsync(out.fileno())
            except BaseException:
                temp.unlink(missing_ok=True)
                raise
    try:
        digest = file_hash(temp)
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)
    return target, digest, etag, modified


def sanitize(obj):
    """Remove NUL characters invalid in PostgreSQL text and JSON values."""
    if isinstance(obj, str):
        return obj.replace("\x00", "\ufffd")
    if isinstance(obj, list):
        return [sanitize(value) for value in obj]
    if isinstance(obj, dict):
        return {str(key).replace("\x00", "\ufffd"): sanitize(value)
                for key, value in obj.items()}
    return obj


def iter_records(path, source):
    opening = gzip.open if source.get("compression", "identity") == "gzip" else open
    with opening(path, "rt", encoding="utf-8-sig", newline="") as stream:
        if source["format"] == "jsonl":
            for index, line in enumerate(stream, 1):
                if len(line) > MAX_JSONL_LINE:
                    raise ValueError(f"JSONL line {index} too long")
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("JSONL records must be objects")
                yield sanitize(value)
        else:
            csv.field_size_limit(1024 * 1024)
            rows = csv.DictReader(stream)
            if not rows.fieldnames:
                raise ValueError("CSV requires headers")
            for row in rows:
                if None in row:
                    raise ValueError("CSV row has extra columns")
                yield sanitize(row)


def batches(path, source, max_records, max_bytes):
    rows = []
    size = 0
    for item in iter_records(path, source):
        raw_ip = next((item[key] for key in ("ip", "ip_str", "ip_address", "address")
                       if item.get(key)), None)
        if raw_ip is None:
            raise ValueError("dataset record has no IP")
        ipaddress.ip_address(str(raw_ip).strip())
        blob = json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        if len(blob) > max_bytes:
            raise ValueError("one JSONL observation exceeds batch_bytes")
        if rows and (len(rows) >= max_records or size + len(blob) > max_bytes):
            yield b"".join(rows)
            rows, size = [], 0
        rows.append(blob)
        size += len(blob)
    if rows:
        yield b"".join(rows)


class ApiClient:
    def __init__(self, base, token):
        self.base = base
        self.token = token

    def call(self, method, path, data=None, extra=None):
        headers = {"X-Admin-Token": self.token, **(extra or {})}
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=300) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, {"detail": exc.read(1000).decode("utf-8", "replace")}

    def find(self, ident):
        status, data = self.call("GET", "/api/admin/datasets/imports")
        if status != 200:
            raise RuntimeError(f"import status API returned HTTP {status}")
        return next((row for row in data.get("imports", []) if row["id"] == ident), None)

    def upload(self, ident, source, data):
        previous = self.find(ident)
        if previous and previous["status"] == "completed":
            return
        if previous and previous["status"] in ("partial", "uploaded"):
            status, outcome = self.call("POST", "/api/admin/datasets/imports/" + ident + "/resume")
            if status == 200 and outcome.get("status") == "completed":
                return
            raise RuntimeError(f"import {ident} cannot resume: HTTP {status}")
        offset = int(previous["uploaded_bytes"]) if previous else 0
        if offset < 0 or offset >= len(data):
            raise RuntimeError("import offset invalid, cannot safely overwrite prior upload")
        headers = {
            "X-Import-Id": ident,
            "X-Import-Source": source,
            "X-Import-Format": "jsonl",
            "X-Import-Encoding": "identity",
            "Content-Range": f"bytes {offset}-{len(data)-1}/{len(data)}",
            "Content-Type": "application/octet-stream",
        }
        status, outcome = self.call("POST", "/api/admin/datasets/imports",
                                    data=data[offset:], extra=headers)
        if status != 200 or outcome.get("status") != "completed":
            raise RuntimeError(f"import {ident} incomplete: HTTP {status} {str(outcome)[:200]}")


def process_source(c, db, source, client):
    sid = source["id"]
    prev = get_progress(db, sid)
    target = c["_state"] / "snapshots" / (sid + ".data")
    if prev and not prev["complete"] and target.is_file() and file_hash(target) == prev["digest"]:
        digest, etag, modified = prev["digest"], prev["etag"], prev["modified"]
    else:
        target, digest, etag, modified = acquire(c, source, prev)
    if prev and prev["complete"] and prev["digest"] == digest:
        return {"source": sid, "status": "unchanged", "batch_cursor": prev["cursor"]}
    if not prev or prev["digest"] != digest:
        save_progress(db, sid, digest=digest, cursor=0, complete=0,
                      etag=etag, modified=modified, error="")
    prev = get_progress(db, sid)
    sent = 0
    for index, data in enumerate(batches(target, source,
                                         c["batch_records"], c["batch_bytes"])):
        if index < prev["cursor"]:
            continue
        if sent >= c["max_batches_per_run"]:
            return {"source": sid, "status": "partial", "uploaded_batches": sent,
                    "batch_cursor": index}
        # Deterministic ID means repeating an acknowledged batch after a crash
        # does not produce a duplicate import.
        ident = "v6-" + sid[:16] + "-" + digest[:16] + f"-{index:08d}"
        client.upload(ident, "v6:" + sid, data)
        save_progress(db, sid, cursor=index+1, error="")
        sent += 1
    save_progress(db, sid, complete=1, error="")
    return {"source": sid, "status": "completed", "uploaded_batches": sent,
            "batch_cursor": get_progress(db, sid)["cursor"]}


def run(config_path, once=True, status=False):
    c = config_read(config_path)
    db = database(c["_state"])
    if status:
        rows = [dict(x) for x in db.execute("SELECT source_id,digest,cursor,complete,updated_at,error FROM progress ORDER BY source_id")]
        print(json.dumps(rows, indent=2))
        return 0
    token = c["_token_file"].read_text().strip()
    if not token or len(token) < 20:
        raise ValueError("admin token file missing or empty")
    lock = c["_state"] / "ingest.lock"
    with lock.open("w") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Another feed import is still running")
            return 0
        client = ApiClient(c["_api_base"], token)
        results = []
        failures = 0
        for source in c["sources"]:
            try:
                result = process_source(c, db, source, client)
                results.append(result)
            except Exception as exc:
                failures += 1
                save_progress(db, source["id"], error=str(exc)[:500])
                results.append({"source": source["id"], "status": "failed", "error": str(exc)[:250]})
        print(json.dumps({"checked_at": utcnow(), "sources": results}, indent=2))
        return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description="Continuous passive data importer; never launches scans")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    raise SystemExit(run(args.config, status=args.status))


if __name__ == "__main__":
    main()
