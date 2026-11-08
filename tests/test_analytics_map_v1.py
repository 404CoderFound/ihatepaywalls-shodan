def test_map_boundaries_are_served_locally_and_analytics_use_indexed_hosts(system, admin_headers):
    client, _, _ = system
    client.post("/api/admin/import", headers=admin_headers, json={"provenance":"map-fixture","observations":[{"ip":"198.51.100.200","country":"NL","asn":"AS65020","port":443,"service":"https","banner":"fixture"}]})
    analytics = client.get("/api/analytics/summary").json()
    assert any(row["country"] == "NL" and row["hosts"] >= 1 for row in analytics["countries"])
    response = client.get("/static/data/world-countries.geojson")
    assert response.status_code == 200
    world = response.json()
    assert world["type"] == "FeatureCollection" and len(world["features"]) > 150
