def test_api_reference_matches_public_and_privileged_feature_surface(system):
    client, _, _ = system
    response = client.get("/api/docs")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "1.0.0"
    assert data["search"]["pagination"]
    assert "vuln:CVE-2024-0001" in data["search"]["syntax"]
    assert "POST /api/admin/datasets/imports (Content-Range chunk upload)" in data["endpoints"]["admin_control"]
    assert "GET /api/search" in data["endpoints"]["public_read"]
    assert "GET/POST /api/admin/jobs" in data["endpoints"]["admin_control"]
    assert data["dataset_import"]["maximum_chunk_bytes"] > 0
    routes={row["path"]:row for row in data["route_inventory"]}
    assert routes["/api/admin/jobs"]["authorization"]=="administrator"
    assert routes["/api/search"]["authorization"]=="public read or scoped read-only API key"
    assert routes["/api/worker/jobs/claim"]["authorization"]=="worker token"
