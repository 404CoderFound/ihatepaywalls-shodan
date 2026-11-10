from app.database import utc_now


def test_public_history_domains_and_empty_intelligence(system, admin_headers):
    client, _, _ = system
    assert client.get("/api/hosts/203.0.113.8/observations").status_code == 200
    assert client.get("/api/hosts/not-an-ip/observations").status_code == 400
    empty = client.get("/api/vulnerabilities").json()
    assert empty["total"] == 0 and empty["results"] == []
    summary = client.get("/api/analytics/summary").json()
    assert summary["totals"] == {"hosts": 0, "observations": 0, "services": 0}
    body={"source":"fixture-dns-dataset","method":"dataset","records":[{"type":"A","value":"192.0.2.99","observed_at":utc_now()}]}
    assert client.post("/api/admin/domains/example.org/dns-import",json=body).status_code==401
    assert client.post("/api/admin/domains/example.org/dns-import",headers=admin_headers,json=body).status_code==200
    result = client.get("/api/domains/example.org").json()
    assert result["dns_history"][0]["value"] == "192.0.2.99"
    assert result["dns_history"][0]["method"] == "dataset"
    assert client.get("/api/domains/invalid").status_code == 400


def test_api_key_lifecycle_and_read_only_scopes(system, admin_headers):
    client, _, _ = system
    assert client.get("/api/admin/api-keys").status_code == 401
    created = client.post("/api/admin/api-keys", headers=admin_headers,
                          json={"name": "report-reader", "scopes": ["analytics:read"]})
    assert created.status_code == 200
    token = created.json()["token"]
    assert client.get("/api/analytics/summary", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert client.get("/api/hosts/192.0.2.4", headers={"Authorization": f"Bearer {token}"}).status_code == 403
    assert client.get("/api/analytics/summary", headers={"Authorization": "Bearer made-up"}).status_code == 401
    assert client.post("/api/admin/api-keys", headers=admin_headers,
                       json={"name": "too-powerful", "scopes": ["scan:write"]}).status_code == 422
    key_id = created.json()["id"]
    assert client.post(f"/api/admin/api-keys/{key_id}/revoke", headers=admin_headers).status_code == 200
    assert client.get("/api/analytics/summary", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_saved_search_update_is_admin_only_and_updates_timestamp(system, admin_headers):
    client, _, _ = system
    payload = {"name": "TLS services", "query": "port:443"}
    assert client.post("/api/admin/saved-searches", json=payload).status_code == 401
    created = client.post("/api/admin/saved-searches", headers=admin_headers, json=payload)
    assert created.status_code == 200
    search_id = created.json()["id"]

    updated = client.put(
        f"/api/admin/saved-searches/{search_id}",
        headers=admin_headers,
        json={"name": "Dutch TLS services", "query": 'country:NL port:443'},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Dutch TLS services"
    assert updated.json()["query"] == "country:NL port:443"
    assert updated.json()["updated_at"] >= created.json()["created_at"]
    assert client.put(
        "/api/admin/saved-searches/9999", headers=admin_headers, json=payload
    ).status_code == 404
    assert client.put(
        f"/api/admin/saved-searches/{search_id}", headers=admin_headers,
        json={"name": "x", "query": ""},
    ).status_code == 422


def test_vulnerability_import_and_monitor_scope(system, admin_headers):
    client, _, _ = system
    body = {"source": "fixture-feed", "records": [{"cve": "CVE-2024-12345", "description": "Example CVE", "cvss": 8.2, "severity": "HIGH", "known_exploited": True}]}
    assert client.post("/api/admin/vulnerabilities/import", json=body).status_code == 401
    imported = client.post("/api/admin/vulnerabilities/import", headers=admin_headers, json=body)
    assert imported.status_code == 200 and imported.json()["imported"] == 1
    results = client.get("/api/vulnerabilities?q=CVE-2024-12345").json()
    assert results["total"] == 1 and results["results"][0]["known_exploited"] == 1

    authorization = client.post("/api/admin/authorizations", headers=admin_headers,
                                json={"name": "owned lab", "cidr": "192.0.2.0/24"}).json()
    allowed = client.post("/api/admin/monitor/targets", headers=admin_headers,
                          json={"name": "lab host", "target": "192.0.2.32/28", "authorization_id": authorization["id"]})
    denied = client.post("/api/admin/monitor/targets", headers=admin_headers,
                         json={"name": "outside", "target": "198.51.100.0/24", "authorization_id": authorization["id"]})
    assert allowed.status_code == 200
    assert denied.status_code == 403
    assert client.get("/api/admin/monitor/events", headers=admin_headers).status_code == 200


def test_csv_export_has_provenance_columns(system):
    client, _, _ = system
    response = client.get("/api/reports/export.csv")
    assert response.status_code == 200
    assert "source,observed_at" in response.text.splitlines()[0]
    assert "attachment; filename=scanlattice-observations.csv" in response.headers["content-disposition"]


def test_public_api_rate_limit_and_monitor_ingested_observation(system, admin_headers):
    client, main, database = system
    main.PUBLIC_RATE_LIMIT = 2
    main.RATE_LIMITER.clear()
    assert client.get("/api/analytics/summary").status_code == 200
    assert client.get("/api/analytics/summary").status_code == 200
    assert client.get("/api/analytics/summary").status_code == 429
    main.PUBLIC_RATE_LIMIT = 60
    auth = client.post("/api/admin/authorizations", headers=admin_headers,
                       json={"name": "monitor lab", "cidr": "192.0.2.0/24"}).json()
    client.post("/api/admin/monitor/targets", headers=admin_headers,
                json={"name": "monitor", "target": "192.0.2.1/32", "authorization_id": auth["id"]})
    with database.connection() as db:
        main.store(db, [main.Observation(ip="192.0.2.1", port=443, service="https", product="TestServer", source="fixture")], "fixture")
    events = client.get("/api/admin/monitor/events", headers=admin_headers).json()["results"]
    assert len(events) == 1 and events[0]["event_type"] == "service_observed"
