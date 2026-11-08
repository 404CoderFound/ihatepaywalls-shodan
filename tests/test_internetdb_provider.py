import json

from app.enrichment import ShodanInternetDBProvider, _store_records


def test_shodan_internetdb_is_explicitly_gated_and_never_invents_banners(system,admin_headers,monkeypatch):
    client,_,database=system
    with database.connection() as db:provider=db.execute("SELECT * FROM passive_providers WHERE provider_type='shodan_internetdb'").fetchone()
    assert provider and provider["enabled"]==0
    blocked=client.put(f"/api/admin/passive/providers/{provider['id']}",headers=admin_headers,json={"enabled":True,"requests_per_minute":5})
    assert blocked.status_code==403
    monkeypatch.setenv("SHODAN_INTERNETDB_NONCOMMERCIAL_CONSENT","true")
    enabled=client.put(f"/api/admin/passive/providers/{provider['id']}",headers=admin_headers,json={"enabled":True,"requests_per_minute":5})
    assert enabled.status_code==200

    calls=[]
    def fake_fetch(url,timeout=8):
        calls.append(url)
        return {"ip":"1.1.1.1","ports":[443,8443],"cpes":["cpe:2.3:a:example:edge:1.0:*:*:*:*:*:*:*"],"hostnames":["one.example.test"],"tags":["fixture"],"vulns":["CVE-2020-12345"]}
    monkeypatch.setattr("app.enrichment._fetch_json",fake_fetch)
    result=ShodanInternetDBProvider().lookup("ip","1.1.1.1","Shodan InternetDB")
    assert result.ttl_seconds==7*86400 and len(result.records)==1
    record=result.records[0]
    assert record["record_type"]=="internetdb-host" and record["value"]["banners_available"] is False
    assert "banner" not in record["value"] and calls==["https://internetdb.shodan.io/1.1.1.1"]
    with database.connection() as db:_store_records(db,provider["id"],[record],result.ttl_seconds)
    by_ip=client.get("/api/search",params={"q":"ip:1.1.1.1"}).json()
    by_port=client.get("/api/search",params={"q":"port:443"}).json()
    assert by_ip["total"]==1 and by_ip["hosts"][0]["services"]==[] and by_ip["passive_total"]==1
    assert by_port["total"]==1 and by_port["hosts"][0]["services"]==[]
    assert by_port["passive_intelligence"][0]["value"]["ports"]==[443,8443]


def test_internetdb_private_addresses_are_not_queried(system,monkeypatch):
    called=[]
    monkeypatch.setattr("app.enrichment._fetch_json",lambda *args,**kwargs:called.append(args))
    result=ShodanInternetDBProvider().lookup("ip","192.0.2.1","fixture")
    assert result.records==[] and "global IP" in result.error and called==[]
