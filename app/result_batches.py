"""Durable idempotent ingestion of worker result batches.

All operations run inside the caller's existing transaction. The v1 results
endpoint remains available to older scanner agents.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from typing import Callable

from fastapi import HTTPException
from pydantic import BaseModel, Field

from .database import utc_now

MAX_BATCH_CHECKS = 128
MAX_BATCH_OBSERVATIONS = 128


class BatchUpload(BaseModel):
    lease_token: str = Field(min_length=10, max_length=200)
    batch_index: int = Field(ge=0, le=1000000)
    checks_done: int = Field(ge=1)
    observations: list = Field(default_factory=list, max_length=MAX_BATCH_OBSERVATIONS)


class BatchFinish(BaseModel):
    lease_token: str = Field(min_length=10, max_length=200)
    batch_count: int = Field(ge=1, le=1000000)
    completed_checks: int = Field(ge=1)


def batch_digest(checks_done: int, observations: list) -> str:
    canonical = json.dumps(
        {"checks_done": checks_done, "observations": [
            item.model_dump(mode="json") if hasattr(item, "model_dump") else item
            for item in observations
        ]}, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def accept_batch(db, job, worker_id: str, batch_index: int, checks_done: int,
                 observations: list, store: Callable) -> dict:
    """Accept exactly-once batch delivery in one database transaction.

    A repeated delivery is acknowledged only if its canonical content matches.
    A gap, changed payload, out-of-scope result or invalid progress fails closed.
    """
    if job["status"] != "running":
        raise HTTPException(409, "Job must be running before batch results can be uploaded")
    if db.execute("SELECT 1 FROM result_uploads WHERE job_id=?", (job["id"],)).fetchone():
        raise HTTPException(409, "Legacy result mode already used for this job")
    raw = batch_digest(checks_done, observations)
    previous = db.execute(
        "SELECT payload_hash,checks_done,observation_count FROM scan_result_batches "
        "WHERE job_id=? AND batch_index=?", (job["id"], batch_index),
    ).fetchone()
    if previous:
        if previous["payload_hash"] != raw or previous["checks_done"] != checks_done:
            raise HTTPException(409, "Batch index was already committed with different contents")
        return {"status": "already_processed", "batch_index": batch_index,
                "indexed": previous["observation_count"], "checks_done": checks_done}

    tail = db.execute(
        "SELECT batch_index,checks_done FROM scan_result_batches "
        "WHERE job_id=? ORDER BY batch_index DESC LIMIT 1", (job["id"],),
    ).fetchone()
    expected = tail["batch_index"] + 1 if tail else 0
    last_checks = tail["checks_done"] if tail else 0
    delta = checks_done - last_checks
    if batch_index != expected:
        raise HTTPException(409, f"Missing batch; expected batch_index {expected}")
    if delta < 1 or delta > MAX_BATCH_CHECKS or checks_done > job["progress_total"]:
        raise HTTPException(400, "Invalid cumulative check progress")
    if len(observations) > delta:
        raise HTTPException(400, "More observations than completed endpoint checks")

    authorization = db.execute(
        "SELECT cidr FROM authorizations WHERE id=? AND enabled=1",
        (job["authorization_id"],),
    ).fetchone()
    if not authorization:
        raise HTTPException(409, "Target authorization was revoked")
    target = ipaddress.ip_network(job["target"], strict=False)
    allowed = ipaddress.ip_network(authorization["cidr"], strict=False)
    ports = set(json.loads(job["ports"]))
    for observation in observations:
        try:
            address = ipaddress.ip_address(observation.ip)
        except ValueError as exc:
            raise HTTPException(400, "Invalid observation IP") from exc
        if address not in target or address not in allowed or observation.port not in ports or observation.proto != "tcp":
            raise HTTPException(400, "Result outside authorized TCP job scope")

    indexed = store(db, observations, "active-scan", job["id"], worker_id)
    db.execute(
        "INSERT INTO scan_result_batches"
        "(job_id,batch_index,payload_hash,checks_done,observation_count,created_at)"
        " VALUES(?,?,?,?,?,?)",
        (job["id"], batch_index, raw, checks_done, indexed, utc_now()),
    )
    db.execute(
        "UPDATE scan_jobs SET progress_done=?,updated_at=?,lease_expires_at=? WHERE id=?",
        (checks_done, utc_now(), int(time.time()) + 90, job["id"]),
    )
    return {"status": "accepted", "batch_index": batch_index,
            "indexed": indexed, "checks_done": checks_done}


def finish_batches(db, job, worker_id: str, batch_count: int, completed_checks: int,
                   notify_missing: Callable) -> dict:
    existing = db.execute(
        "SELECT * FROM scan_result_finishes WHERE job_id=?", (job["id"],),
    ).fetchone()
    if existing:
        if (existing["worker_id"] != worker_id or existing["batch_count"] != batch_count
                or existing["completed_checks"] != completed_checks):
            raise HTTPException(409, "Conflicting batch finalization")
        return {"status": "already_completed", "indexed": existing["observation_count"]}
    if job["status"] != "running":
        raise HTTPException(409, "Job must be running to finish batches")
    total = db.execute(
        "SELECT COUNT(*) as count,COALESCE(SUM(observation_count),0) as indexed,"
        " COALESCE(MAX(checks_done),0) as checked "
        "FROM scan_result_batches WHERE job_id=?", (job["id"],),
    ).fetchone()
    if (total["count"] != batch_count or total["checked"] != completed_checks
            or completed_checks != job["progress_total"]):
        raise HTTPException(409, "Batches are incomplete or completed_checks does not match job")
    rows = db.execute(
        "SELECT batch_index FROM scan_result_batches WHERE job_id=? ORDER BY batch_index",
        (job["id"],),
    ).fetchall()
    if [row[0] for row in rows] != list(range(batch_count)):
        raise HTTPException(409, "Missing batches")
    notify_missing(db, job)
    db.execute(
        "INSERT INTO scan_result_finishes"
        "(job_id,worker_id,batch_count,completed_checks,observation_count,finished_at)"
        " VALUES(?,?,?,?,?,?)",
        (job["id"], worker_id, batch_count, completed_checks, total["indexed"], utc_now()),
    )
    timestamp = utc_now()
    db.execute(
        "UPDATE scan_jobs SET status='completed',progress_done=progress_total,"
        "completed_at=?,updated_at=?,lease_token=NULL,lease_expires_at=NULL WHERE id=?",
        (timestamp, timestamp, job["id"]),
    )
    db.execute("UPDATE workers SET completed_jobs=completed_jobs+1 WHERE id=?", (worker_id,))
    return {"status": "completed", "indexed": total["indexed"]}
