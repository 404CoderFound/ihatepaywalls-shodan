"""Durable worker spool tests never connect to external networks."""
import json
import uuid

import pytest

from worker.agent.batches import DurableSpool, run_batched_job


def _job(ports=(80, 443, 8080, 8443)):
    return {"id": str(uuid.uuid4()), "target": "127.0.0.1/32",
            "authorization_cidr": "127.0.0.0/24", "ports": list(ports),
            "lease_token": "test-lease-token-12345",
            "max_concurrency": 2, "connect_timeout": 1,
            "banner_timeout": 1, "rate_per_second": 1000}


def test_spool_survives_restart_and_removes_confirmed_chunks(tmp_path):
    job = _job()
    spool = DurableSpool(tmp_path, job)
    first = spool.append(2, [{"ip": "127.0.0.1", "port": 80}])
    assert (spool.path / "chunk-00000000.json").exists()
    spool2 = DurableSpool(tmp_path, job)
    assert list(spool2.saved()) == [first]
    spool2.acknowledge(0, 2)
    spool3 = DurableSpool(tmp_path, job)
    assert spool3.next_index == 1 and spool3.next_checks == 2
    assert list(spool3.saved()) == []
    assert not (spool3.path / "chunk-00000000.json").exists()
    second = spool3.append(4, [])
    assert second["batch_index"] == 1
    assert len(list(DurableSpool(tmp_path, job).saved())) == 1


def test_lost_upload_ack_does_not_force_rescan(tmp_path):
    job = _job()
    state = {"batches": 0, "checks": 0, "drop_ack": True, "probe_count": 0}

    def scan(ip, port, *args):
        state["probe_count"] += 1
        return {"ip": ip, "port": port}

    def call(path, payload=None, headers=None):
        if path.endswith("/start"):
            return {"status": "running"}
        if path.endswith("/status"):
            return {"status": "running", "batch_count": state["batches"], "checks_done": state["checks"]}
        if path.endswith("/batches"):
            state["batches"] = payload["batch_index"] + 1
            state["checks"] = payload["checks_done"]
            if state["drop_ack"]:
                state["drop_ack"] = False
                raise ConnectionError("acknowledgment lost")
            return {"status": "already_processed", "batch_index": payload["batch_index"],
                    "checks_done": payload["checks_done"]}
        if path.endswith("/complete"):
            return {"status": "completed"}
        raise AssertionError(path)

    with pytest.raises(ConnectionError, match="acknowledgment lost"):
        run_batched_job(job, {}, call, scan, tmp_path)
    assert state["probe_count"] == 4
    assert run_batched_job(job, {}, call, scan, tmp_path)["status"] == "completed"
    assert state["probe_count"] == 4
    assert not list(tmp_path.glob("*/manifest.json"))


def test_worker_can_continue_from_remote_checkpoint_without_prior_local_spool(tmp_path):
    job = _job()
    calls = []
    state = {"batches": 1, "checks": 2}

    def scan(ip, port, *args):
        calls.append(port)
        return {"ip": ip, "port": port}

    def call(path, payload=None, headers=None):
        if path.endswith("/start"):
            return {"status": "running"}
        if path.endswith("/status"):
            return {"status": "running", "batch_count": state["batches"], "checks_done": state["checks"]}
        if path.endswith("/batches"):
            assert payload["batch_index"] == 1 and payload["checks_done"] == 4
            state["batches"] = 2
            state["checks"] = 4
            return {"status": "accepted", "batch_index": 1, "checks_done": 4}
        if path.endswith("/complete"):
            return {"status": "completed"}
        raise AssertionError(path)

    result = run_batched_job(job, {}, call, scan, tmp_path)
    assert result["status"] == "completed"
    assert sorted(calls) == [8080, 8443]


def test_spool_rejects_mismatched_job_identity(tmp_path):
    job = _job()
    DurableSpool(tmp_path, job)
    changed = {**job, "ports": [1234]}
    with pytest.raises(ValueError, match="does not match"):
        DurableSpool(tmp_path, changed)
