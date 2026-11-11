def test_map_boundaries_are_served_locally_and_analytics_use_indexed_hosts(system, admin_headers):
    client, _, _ = system
    client.post("/api/admin/import", headers=admin_headers, json={"provenance":"map-fixture","observations":[{"ip":"198.51.100.200","country":"NL","asn":"AS65020","port":443,"service":"https","banner":"fixture"}]})
    response = client.get("/api/analytics/summary")
    assert response.status_code == 200, response.text
    analytics = response.json()
    assert any(row["country"] == "NL" and row["hosts"] >= 1 for row in analytics["countries"])
    # Regression: the daily analytics endpoint must return a stable "day"
    # column and observation/host counts on both SQLite and PostgreSQL.
    assert analytics["daily"]
    assert all(set(("day", "observations", "hosts")).issubset(row) for row in analytics["daily"])
    assert all(row["observations"] >= row["hosts"] >= 1 for row in analytics["daily"])
    response = client.get("/static/data/world-countries.geojson")
    assert response.status_code == 200
    world = response.json()
    assert world["type"] == "FeatureCollection" and len(world["features"]) > 150
