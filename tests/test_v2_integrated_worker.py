"""End-to-end contract of combined PostgreSQL-compatible service scanner and v2 batch API.

All requests stay inside FastAPI TestClient and fake workers; no public targets.
"""
from conftest import authorize, create_job, enroll
from worker.agent.batches import run_batched_job
from worker.scanners.fingerprints import fingerprint_banner
from worker.agent.main import CAPABILITIES, VERSION


def test_combined_agent_declares_fingerprints_and_durable_batching():
    assert VERSION == "0.7.0"
    assert "service-fingerprints" in CAPABILITIES
    assert "durable-batched-results" in CAPABILITIES
    assert "postgresql-sslrequest" in CAPABILITIES


def test_fingerprinted_results_are_indexed_with_durable_worker_batches(system, admin_headers, tmp_path):
    client, _, database = system
    authorize(client, admin_headers)
    _, worker_headers = enroll(client, "integration-fixture")
    result = create_job(client, admin_headers, ports=[22, 80])
    assert result.status_code == 200
    job = client.post("/api/worker/jobs/claim", headers=worker_headers, json={}).json()["jobs"][0]

    def call(path, payload=None, headers=None):
        response = (client.post(path, headers=headers, json=payload) if payload is not None
                    else client.get(path, headers=headers))
        assert response.status_code == 200, (path, response.status_code, response.text)
        return response.json()

    def fake_scan(ip, port, connect_timeout, banner_timeout):
        banner = (b"SSH-2.0-OpenSSH_9.6\\r\\n" if port == 22
                  else b"HTTP/1.1 200 OK\\r\\nServer: LocalFixture\\r\\n\\r\\n")
        fingerprint = fingerprint_banner(port, banner)
        return {"ip": ip, "port": port, "proto": "tcp",
                "service": fingerprint.service, "product": fingerprint.product,
                "banner": banner.decode("utf-8", "replace")}

    output = run_batched_job(job, worker_headers, call, fake_scan, tmp_path)
    assert output["status"] == "completed"
    assert client.get("/api/search", params={"q": "port:22 service:ssh"}).json()["total"] == 1
    assert client.get("/api/search", params={"q": "port:80 service:http"}).json()["total"] == 1
    with database.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM scan_result_batches").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM observations WHERE scan_job_id=?", (job["id"],)).fetchone()[0] == 2
