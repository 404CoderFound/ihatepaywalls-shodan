"""Crash-safe bounded local spool for a worker's result batches.

Only one small chunk is held in RAM. Persist chunks before HTTP upload so a
lost response or worker restart can safely replay the same batch index.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import itertools
import json
import os
import shutil
import tempfile
import threading
import time
import uuid
from pathlib import Path

MAX_SPOOL_BYTES = 128 * 1024 * 1024
MAX_BATCH_CHECKS = 128


def _canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _atomic_json(path: Path, data) -> None:
    raw = _canonical(data)
    handle, tmp = tempfile.mkstemp(prefix=".batch-", dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class DurableSpool:
    def __init__(self, base: Path, job: dict):
        job_id = str(uuid.UUID(job["id"]))
        self.path = base / job_id
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path.chmod(0o700)
        identity = {"id": job_id, "target": str(ipaddress.ip_network(job["target"], strict=False)),
                    "ports": sorted(set(int(p) for p in job["ports"]))}
        manifest = self.path / "manifest.json"
        if manifest.exists():
            if json.loads(manifest.read_text()) != identity:
                raise ValueError("Saved spool does not match the assigned scan job")
        else:
            _atomic_json(manifest, identity)
        self.total_checks = ipaddress.ip_network(identity["target"]).num_addresses * len(identity["ports"])
        self.next_checks = 0
        self.next_index = 0
        self.saved_bytes = manifest.stat().st_size
        while True:
            path = self._chunk_path(self.next_index)
            if not path.exists():
                break
            data = json.loads(path.read_text())
            if (data["batch_index"] != self.next_index
                    or data["checks_done"] <= self.next_checks
                    or data["checks_done"] - self.next_checks > MAX_BATCH_CHECKS
                    or len(data["observations"]) > data["checks_done"] - self.next_checks):
                raise ValueError("Saved batch spool is inconsistent")
            self.next_checks = data["checks_done"]
            self.next_index += 1
            self.saved_bytes += path.stat().st_size
        if self.next_checks > self.total_checks:
            raise ValueError("Saved spool exceeds scan job size")
        # A missing middle chunk must not silently cause a partial replay.
        for path in self.path.glob("chunk-*.json"):
            if int(path.stem.split("-")[1]) >= self.next_index:
                raise ValueError("Saved spool has a missing batch")

    def _chunk_path(self, index: int) -> Path:
        return self.path / f"chunk-{index:08d}.json"

    def saved(self):
        for index in range(self.next_index):
            yield json.loads(self._chunk_path(index).read_text())

    def append(self, checks_done: int, observations: list) -> dict:
        if not (self.next_checks < checks_done <= self.total_checks):
            raise ValueError("Invalid next batch checkpoint")
        if checks_done - self.next_checks > MAX_BATCH_CHECKS:
            raise ValueError("Batch too large")
        data = {"batch_index": self.next_index, "checks_done": checks_done,
                "observations": observations}
        raw_size = len(_canonical(data))
        if self.saved_bytes + raw_size > MAX_SPOOL_BYTES:
            raise RuntimeError("Worker batch spool limit exceeded")
        _atomic_json(self._chunk_path(self.next_index), data)
        self.saved_bytes += raw_size
        self.next_checks = checks_done
        self.next_index += 1
        return data

    def cleanup(self):
        shutil.rmtree(self.path)


def _targets(job):
    network = ipaddress.ip_network(job["target"], strict=False)
    ports = sorted(set(int(port) for port in job["ports"]))
    for address in network:
        for port in ports:
            yield str(address), port


def run_batched_job(job, headers, call, scan, state_dir: Path):
    """Use the existing v1 claim/start flow, then durable result batch endpoints."""
    target = ipaddress.ip_network(job["target"], strict=False)
    allowed = ipaddress.ip_network(job["authorization_cidr"], strict=False)
    if not target.subnet_of(allowed) or target.num_addresses > 4096 or len(job["ports"]) > 100:
        raise RuntimeError("Job exceeds worker authorization or size limits")
    spool = DurableSpool(state_dir, job)
    lease = job["lease_token"]
    job_id = job["id"]
    call(f"/api/worker/jobs/{job_id}/start", {"lease_token": lease}, headers)

    def upload(data):
        result = call(f"/api/worker/jobs/{job_id}/results/batches",
                      {"lease_token": lease, **data}, headers)
        if result.get("status") not in ("accepted", "already_processed"):
            raise RuntimeError("Unexpected result batch acknowledgment")
        if result.get("batch_index") != data["batch_index"] or result.get("checks_done") != data["checks_done"]:
            raise RuntimeError("Result batch acknowledgment mismatch")

    # Replaying acknowledged chunks is safe: the server compares payload hashes.
    for saved in spool.saved():
        upload(saved)

    concurrency = min(max(int(job["max_concurrency"]), 1), 50)
    rate = max(0.1, float(job.get("rate_per_second", 20)))
    connect_timeout = float(job["connect_timeout"])
    banner_timeout = float(job["banner_timeout"])
    # Keep a chunk under about 20s even on a single slow worker, to renew leases.
    batch_size = min(MAX_BATCH_CHECKS, max(1, int(20 * concurrency / max(0.1, connect_timeout + banner_timeout))))
    rate_lock = threading.Lock()
    next_start = [time.monotonic()]

    def probe(endpoint):
        with rate_lock:
            delay = next_start[0] - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            next_start[0] = max(next_start[0], time.monotonic()) + 1 / rate
        return scan(endpoint[0], endpoint[1], connect_timeout, banner_timeout)

    targets = itertools.islice(_targets(job), spool.next_checks, None)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        while True:
            chunk = list(itertools.islice(targets, batch_size))
            if not chunk:
                break
            observations = [item for item in executor.map(probe, chunk) if item is not None]
            data = spool.append(spool.next_checks + len(chunk), observations)
            upload(data)

    if spool.next_checks != spool.total_checks:
        raise RuntimeError("Scan spool did not complete all endpoint checks")
    result = call(f"/api/worker/jobs/{job_id}/results/complete",
                  {"lease_token": lease, "batch_count": spool.next_index,
                   "completed_checks": spool.next_checks}, headers)
    if result.get("status") not in ("completed", "already_completed"):
        raise RuntimeError("Result finalization was not acknowledged")
    spool.cleanup()
    return result
