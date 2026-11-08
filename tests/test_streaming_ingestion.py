import gzip
import json
import pytest


def _upload(client, headers, import_id, source, fmt, encoding, data, start=0, end=None, total=None):
    end = len(data) - 1 if end is None else end
    total = len(data) if total is None else total
    request_headers = {**headers, "X-Import-Id": import_id, "X-Import-Source": source,
                       "X-Import-Format": fmt, "X-Import-Encoding": encoding,
                       "Content-Range": f"bytes {start}-{end}/{total}",
                       "Content-Type": "application/octet-stream"}
    return client.post("/api/admin/datasets/imports", headers=request_headers, content=data)


def test_resumable_streaming_json_import_indexes_real_hosts_and_services(system, admin_headers):
    client, _, _ = system
    payload = json.dumps([
        {"ip_str":"198.51.100.71","asn":"AS65071","org":"Example Backbone","country_code":"NL","os":"Linux","hostnames":["edge.example.test"],"data":[
            {"port":443,"transport":"tcp","service":"https","product":"ExampleTLS","cpe":"cpe:2.3:a:example:exampletls:1.2:*:*:*:*:*:*:*","banner":"TLS fixture banner","timestamp":"2025-01-02T03:04:05Z","http":{"title":"Example UI"},"ssl":{"cert":{"subject":{"CN":"edge.example.test"}}}},
            {"port":22,"transport":"tcp","service":"ssh","product":"OpenSSH","banner":"SSH-2.0-fixture"}
        ]},
        {"ip":"198.51.100.72","asn":"65071","org":"Example Backbone","country":"NL","hostname":"bare.example.test"}
    ], separators=(",", ":")).encode()
    pivot = len(payload) // 2
    first = _upload(client, admin_headers, "json-resume", "fixture-json", "json", "identity", payload[:pivot], 0, pivot-1, len(payload))
    assert first.status_code == 202 and first.json()["resume_offset"] == pivot
    wrong = _upload(client, admin_headers, "json-resume", "fixture-json", "json", "identity", payload[pivot:], 0, len(payload)-pivot-1, len(payload))
    assert wrong.status_code == 409
    result = _upload(client, admin_headers, "json-resume", "fixture-json", "json", "identity", payload[pivot:], pivot, len(payload)-1, len(payload))
    assert result.status_code == 200 and result.json()["records_processed"] == 2
    search = client.get("/api/search", params={"q":"asn:AS65071 port:443"}).json()
    assert search["total"] == 1
    host = search["hosts"][0]
    https = next(service for service in host["services"] if service["port"] == 443)
    assert host["ip"] == "198.51.100.71" and https["banner"] == "TLS fixture banner"
    assert https["cpe"].startswith("cpe:2.3:") and host["os_name"] == "Linux"
    assert https["last_seen"] == "2025-01-02T03:04:05+00:00"
    assert client.get("/api/search", params={"q":"hostname:bare.example.test"}).json()["total"] == 1
    assert client.get("/api/admin/datasets/imports", headers=admin_headers).json()["imports"][0]["status"] == "completed"


def test_gzip_csv_and_jsonl_ingestion_keep_provenance(system, admin_headers):
    client, _, _ = system
    csv_bytes = gzip.compress(b"ip,port,proto,hostname,asn,org,country,service,product,banner,observed_at\n203.0.113.81,8443,tcp,web.example.test,AS65081,Fixture Org,US,https,FixtureHTTP,fixture-csv,2024-08-01T00:00:00Z\n")
    imported = _upload(client, admin_headers, "csv-gzip", "fixture-csv-feed", "csv", "gzip", csv_bytes)
    assert imported.status_code == 200
    data = client.get("/api/hosts/203.0.113.81").json()
    assert data["services"][0]["source"] == "fixture-csv-feed"
    assert data["services"][0]["banner"] == "fixture-csv"
    jsonl = b'{"ip":"203.0.113.82","port":53,"proto":"udp","asn":"AS65082","service":"dns","banner":"dns fixture"}\n'
    result = _upload(client, admin_headers, "jsonl", "fixture-jsonl-feed", "jsonl", "identity", jsonl)
    assert result.status_code == 200
    assert client.get("/api/search", params={"q":"asn:AS65082 port:53"}).json()["total"] == 1


def test_stream_import_auth_and_chunk_limits(system, monkeypatch):
    client, main, _ = system
    data = b'[]'
    result = _upload(client, {}, "no-auth", "source", "json", "identity", data)
    assert result.status_code == 401
    import app.intelligence as intelligence
    monkeypatch.setattr(intelligence, "MAX_IMPORT_CHUNK", 1)
    result = _upload(client, {"X-Admin-Token":"admin-test-token"}, "size-check", "source", "json", "identity", b'[]')
    assert result.status_code == 413


@pytest.mark.parametrize(("body", "message"), [
    ('[{"ip":"192.0.2.1"}', "missing its closing bracket"),
    ('[{"ip":"192.0.2.1"}] trailing', "Unexpected data after JSON array"),
])
def test_json_array_import_rejects_truncation_and_trailing_garbage(system, admin_headers, body, message):
    client, _, _ = system
    data = body.encode()
    result = _upload(client, admin_headers, "bad-json-" + str(len(data)), "fixture", "json", "identity", data)
    assert result.status_code == 422
    assert message in result.json()["error"]
