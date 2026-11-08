from app.search import QueryError, parse_query


def test_search_boolean_exclusion_and_field_validation():
    parsed=parse_query('port:80 OR (port:443) -country:US')
    assert parsed.filters=={"port":["80"]}
    assert parsed.alternatives==[({"port":["443"]},[])]
    assert parsed.excluded==[("country","US")]
    assert parse_query('http.title:"Admin Portal"').filters["http.title"]==["Admin Portal"]
    assert parse_query('after:2024-02-29').filters["after"]==["2024-02-29"]
    for invalid in ("OR port:443","port:80 OR","has_screenshot:maybe","after:2023-02-29"):
        try:parse_query(invalid)
        except QueryError:pass
        else:raise AssertionError(f"accepted invalid query: {invalid}")


def test_filter_queries_unique_host_counts_and_full_query_facets(system):
    client,main,database=system
    rows=[
        main.Observation(ip="192.0.2.40",port=80,service="http",product="nginx",country="NL",http={"title":"Public Dashboard"},tls={"cert":{"subject":{"CN":"alpha.example"}}},cpe="cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*",os_name="Linux"),
        main.Observation(ip="192.0.2.40",port=443,service="https",product="nginx",country="NL",http={"title":"Secure Dashboard"},tls={"cert":{"subject":{"CN":"alpha.example"}}},cpe="cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*",os_name="Linux"),
        main.Observation(ip="192.0.2.41",port=443,service="https",product="Apache",country="DE",http={"title":"Status"},os_name="FreeBSD"),
    ]
    with database.connection() as db:main.store(db,rows,"query-fixture")
    assert client.get("/api/search",params={"q":"port:80 OR port:443"}).json()["total"]==2
    assert client.get("/api/search",params={"q":"port:443 -country:DE"}).json()["total"]==1
    assert client.get("/api/search",params={"q":"http.title:Dashboard"}).json()["total"]==1
    assert client.get("/api/search",params={"q":"ssl.cert.subject.cn:alpha.example"}).json()["total"]==1
    assert client.get("/api/search",params={"q":"cpe:nginx os:linux"}).json()["total"]==1
    response=client.get("/api/search",params={"q":"","limit":1,"sort":"ip"}).json()
    assert response["total"]==2 and response["per_page"]==1 and response["has_next"]
    assert response["facets"]["ports"]["443"]==2
