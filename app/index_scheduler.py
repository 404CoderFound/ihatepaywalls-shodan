"""Bounded, administrator-requested scan generations over the v1 worker queue.

One v2 task is backed by one existing v1 scan_job (a single indexed IP and a
bounded port set). This keeps the current worker claim/start/result protocol
unchanged while adding durable generation/task state and request idempotency.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import time
import uuid
from typing import Any

from fastapi import HTTPException

from .database import utc_now
from .search import QueryError, parse_query


def _network_for_authorized_ip(db, ip: str):
    address = ipaddress.ip_address(ip)
    target = ipaddress.ip_network(f"{ip}/{address.max_prefixlen}", strict=False)
    for row in db.execute("SELECT * FROM authorizations WHERE enabled=1 ORDER BY id"):
        scope = ipaddress.ip_network(row["cidr"], strict=False)
        if address.version == scope.version and target.subnet_of(scope):
            return row
    return None


def _candidate_ips(db, kind: str, value: str, limit: int) -> list[str]:
    if kind == "ip":
        return [str(ipaddress.ip_address(value))]
    if kind == "asn":
        rows = db.execute(
            "SELECT ip FROM hosts WHERE UPPER(asn)=? ORDER BY ip_version,ip_hex LIMIT ?",
            (value.upper(), limit + 1),
        ).fetchall()
        return [row[0] for row in rows]
    network = ipaddress.ip_network(value, strict=False)
    start = f"{int(network.network_address):032x}"
    end = f"{int(network.broadcast_address):032x}"
    rows = db.execute(
        "SELECT ip FROM hosts WHERE ip_version=? AND ip_hex BETWEEN ? AND ? ORDER BY ip_hex LIMIT ?",
        (network.version, start, end, limit + 1),
    ).fetchall()
    return [row[0] for row in rows]


def _parse_plan(db, query: str, profile_id: int, requested_ports: list[int] | None,
                max_targets: int, max_ports: int) -> tuple[str, str, list[str], list[int], Any]:
    try:
        parsed = parse_query(query)
    except QueryError as exc:
        raise HTTPException(400, str(exc)) from exc
    allowed_fields = {"ip", "net", "asn", "port"}
    if parsed.free or parsed.excluded or parsed.alternatives or set(parsed.filters) - allowed_fields:
        raise HTTPException(400, "Refresh planning supports one IP, CIDR, or ASN filter and an optional port filter")
    targets = [(key, values) for key, values in parsed.filters.items() if key in {"ip", "net", "asn"}]
    if len(targets) != 1 or len(targets[0][1]) != 1:
        raise HTTPException(400, "Specify exactly one ip:, net:, or asn: target")
    kind, target_values = targets[0]
    value = target_values[0]
    kind = "cidr" if kind == "net" else kind
    if kind == "ip":
        value = str(ipaddress.ip_address(value))
    elif kind == "cidr":
        value = str(ipaddress.ip_network(value, strict=False))
    else:
        value = "AS" + str(int(value.upper().removeprefix("AS")))

    profile = db.execute("SELECT * FROM scan_profiles WHERE id=?", (profile_id,)).fetchone()
    if profile is None:
        raise HTTPException(404, "Scan profile not found")
    query_ports = parsed.filters.get("port", [])
    if len(query_ports) > 1:
        raise HTTPException(400, "Refresh planning accepts one port filter")
    ports = [int(query_ports[0])] if query_ports else sorted(set(
        requested_ports if requested_ports is not None else
        [int(item) for item in profile["ports"].split(",")]
    ))
    if requested_ports is not None and query_ports and sorted(set(requested_ports)) != ports:
        raise HTTPException(400, "Requested ports must match the port: query filter")
    if not ports or len(ports) > max_ports or any(port < 1 or port > 65535 for port in ports):
        raise HTTPException(400, "Invalid or excessive port selection")

    candidates = _candidate_ips(db, kind, value, max_targets)
    if len(candidates) > max_targets:
        raise HTTPException(413, f"Query matches more than the {max_targets} host refresh limit; narrow the query")
    if not candidates:
        raise HTTPException(404, "No indexed host matches this bounded refresh query")
    profile_data = dict(profile)
    return kind, value, candidates, ports, profile_data


def sync_generation_states(db) -> None:
    """Mirror the authoritative v1 job lease/status onto durable v2 task rows."""
    now = utc_now()
    db.execute("""UPDATE scan_tasks SET
      status=(SELECT j.status FROM scan_jobs j WHERE j.id=scan_tasks.scan_job_id),
      attempt_count=COALESCE((SELECT j.attempts FROM scan_jobs j WHERE j.id=scan_tasks.scan_job_id),attempt_count),
      lease_owner=COALESCE((SELECT j.assigned_worker_id FROM scan_jobs j WHERE j.id=scan_tasks.scan_job_id),''),
      lease_token=COALESCE((SELECT j.lease_token FROM scan_jobs j WHERE j.id=scan_tasks.scan_job_id),''),
      lease_expires_at=(SELECT j.lease_expires_at FROM scan_jobs j WHERE j.id=scan_tasks.scan_job_id),
      error=COALESCE((SELECT j.error FROM scan_jobs j WHERE j.id=scan_tasks.scan_job_id),''),
      updated_at=? WHERE scan_job_id IS NOT NULL""", (now,))
    for generation in db.execute("SELECT id FROM scan_generations").fetchall():
        rows = db.execute("SELECT status,COUNT(*) count FROM scan_tasks WHERE generation_id=? GROUP BY status", (generation[0],)).fetchall()
        counts = {row["status"]: row["count"] for row in rows}
        total = sum(counts.values())
        completed = counts.get("completed", 0)
        failed = counts.get("failed", 0)
        cancelled = counts.get("cancelled", 0)
        terminal = completed + failed + cancelled
        if terminal == total and completed == total:
            status = "completed"
        elif terminal == total and completed:
            status = "partial"
        elif terminal == total and cancelled == total:
            status = "cancelled"
        elif terminal == total:
            status = "failed"
        elif counts.get("running", 0) or counts.get("assigned", 0) or completed or failed:
            status = "running"
        else:
            status = "queued"
        completed_at = now if terminal == total else None
        db.execute("UPDATE scan_generations SET status=?,completed_tasks=?,failed_tasks=?,updated_at=?,completed_at=? WHERE id=?",
                   (status, completed, failed, now, completed_at, generation[0]))
        db.execute("UPDATE scan_refresh_requests SET status=?,updated_at=? WHERE generation_id=?",
                   (status, now, generation[0]))


def create_refresh_request(db, *, query: str, profile_id: int, requested_ports: list[int] | None,
                           idempotency_key: str | None, requested_by: str,
                           max_targets: int | None = None, max_ports: int = 100,
                           max_checks: int = 25600) -> dict[str, Any]:
    target_limit = max_targets or int(os.getenv("MAX_REFRESH_TARGETS", "256"))
    if target_limit < 1 or target_limit > 4096:
        target_limit = 256
    if requested_ports is not None and (not requested_ports or len(set(requested_ports)) > max_ports):
        raise HTTPException(400, "Invalid or excessive port selection")
    kind, value, candidates, ports, profile = _parse_plan(
        db, query, profile_id, requested_ports, target_limit, max_ports
    )
    if len(candidates) * len(ports) > max_checks:
        raise HTTPException(413, f"Refresh exceeds the {max_checks} indexed host/port check limit; narrow the query")
    normalized = json.dumps({"kind":kind,"value":value,"profile_id":profile_id,"ports":ports}, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(normalized.encode()).hexdigest()
    if idempotency_key:
        if len(idempotency_key) > 200:
            raise HTTPException(400, "Idempotency-Key must not exceed 200 characters")
        request_key = "key:" + hashlib.sha256(idempotency_key.encode()).hexdigest()
    else:
        # Network retries inside a five-minute window collapse to one request;
        # a deliberate later refresh receives a new generation.
        request_key = f"auto:{fingerprint}:{int(time.time()) // 300}"
    existing = db.execute("SELECT * FROM scan_refresh_requests WHERE idempotency_key=?", (request_key,)).fetchone()
    if existing:
        if existing["request_fingerprint"] != fingerprint:
            raise HTTPException(409, "Idempotency-Key was already used for a different refresh request")
        return _request_detail(db, existing["id"])

    authorized = []
    rejected = []
    auth_by_ip = {}
    for ip in candidates:
        authorization = _network_for_authorized_ip(db, ip)
        (authorized if authorization else rejected).append(ip)
        if authorization:
            auth_by_ip[ip] = authorization
    if not authorized:
        raise HTTPException(403, "No indexed target is covered by an enabled authorization")

    request_id = str(uuid.uuid4())
    generation_id = str(uuid.uuid4())
    now = utc_now()
    db.execute("INSERT INTO scan_generations(id,refresh_request_id,query,normalized_query,query_kind,status,requested_by,target_count,task_count,completed_tasks,failed_tasks,created_at,updated_at) VALUES(?,?,?,?,?,'queued',?,?,?,0,0,?,?)",
               (generation_id, request_id, query, normalized, kind, requested_by, len(authorized), len(authorized), now, now))
    db.execute("INSERT INTO scan_refresh_requests(id,idempotency_key,request_fingerprint,query,normalized_query,profile_id,ports_json,status,requested_by,generation_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'queued',?,?,?,?)",
               (request_id, request_key, fingerprint, query, normalized, profile_id, json.dumps(ports), requested_by, generation_id, now, now))
    for ip in authorized:
        address = ipaddress.ip_address(ip)
        target = f"{ip}/{address.max_prefixlen}"
        ports_json = json.dumps(ports, separators=(",", ":"))
        task_key = hashlib.sha256(f"{generation_id}|{ip}|{ports_json}".encode()).hexdigest()
        job_id = str(uuid.uuid4())
        db.execute("INSERT INTO scan_jobs(id,target,authorization_id,profile_id,ports,requested_worker_id,status,progress_total,created_at,updated_at) VALUES(?,?,?,?,?,?,'queued',?,?,?)",
                   (job_id, target, auth_by_ip[ip]["id"], profile_id, ports_json, "__scanlattice_v2_scheduler__", len(ports), now, now))
        db.execute("INSERT INTO scan_tasks(id,generation_id,idempotency_key,target_ip,ports_json,profile_id,scan_job_id,status,attempt_count,max_attempts,lease_owner,lease_token,lease_expires_at,available_at,error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'queued',0,3,'','',NULL,0,'',?,?)",
                   (str(uuid.uuid4()), generation_id, task_key, ip, ports_json, profile_id, job_id, now, now))
    db.execute("UPDATE scan_refresh_requests SET rejected_targets_json=? WHERE id=?", (json.dumps(rejected), request_id))
    return _request_detail(db, request_id)


def _request_detail(db, request_id: str) -> dict[str, Any]:
    row = db.execute("""SELECT r.*,g.query_kind,g.target_count,g.task_count,g.completed_tasks,g.failed_tasks,g.status generation_status
      FROM scan_refresh_requests r JOIN scan_generations g ON g.id=r.generation_id WHERE r.id=?""", (request_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Refresh request not found")
    result = dict(row)
    result["ports"] = json.loads(result.pop("ports_json"))
    result["rejected_targets"] = json.loads(result.pop("rejected_targets_json"))
    result["generation"] = {key:result.pop(key) for key in ("generation_id","generation_status","query_kind","target_count","task_count","completed_tasks","failed_tasks")}
    return result


def list_refresh_requests(db, limit: int = 100) -> list[dict[str, Any]]:
    sync_generation_states(db)
    ids = [row[0] for row in db.execute("SELECT id FROM scan_refresh_requests ORDER BY created_at DESC LIMIT ?", (limit,))]
    return [_request_detail(db, request_id) for request_id in ids]


def get_refresh_request(db, request_id: str) -> dict[str, Any]:
    sync_generation_states(db)
    return _request_detail(db, request_id)


def list_generations(db, limit: int = 100) -> list[dict[str, Any]]:
    sync_generation_states(db)
    return [dict(row) for row in db.execute("SELECT * FROM scan_generations ORDER BY created_at DESC LIMIT ?", (limit,))]


def list_tasks(db, limit: int = 250) -> list[dict[str, Any]]:
    sync_generation_states(db)
    rows = [dict(row) for row in db.execute("""SELECT t.*,w.name worker_name FROM scan_tasks t
      LEFT JOIN scan_jobs j ON j.id=t.scan_job_id LEFT JOIN workers w ON w.id=j.assigned_worker_id
      ORDER BY t.created_at DESC LIMIT ?""", (limit,))]
    for row in rows:
        row["ports"] = json.loads(row.pop("ports_json"))
        row.pop("lease_token", None)
    return rows
