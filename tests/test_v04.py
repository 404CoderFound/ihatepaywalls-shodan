import sqlite3
import time
from pathlib import Path


def observations(count,base=0,asn="AS64590"):
    rows=[]
    for index in range(count):
        number=base+index
        rows.append({"ip":f"10.{number//65536}.{(number//256)%256}.{number%256}","port":80+(number%3),"asn":asn,"org":"Pagination Network","service":"http","product":"fixture","banner":f"host-{number}"})
    return rows


def test_exactly_ten_hosts_per_page_and_279_results(system,admin_headers):
    client,_,_=system
    assert client.post("/api/admin/import",headers=admin_headers,json={"provenance":"279-host-fixture","observations":observations(279)}).status_code==200
    first=client.get("/api/search",params={"q":"asn:AS64590","page":1}).json()
    last=client.get("/api/search",params={"q":"asn:AS64590","page":28}).json()
    assert (first["page"],first["per_page"],first["total"],first["total_pages"],first["has_next"])==(1,10,279,28,True)
    assert len(first["hosts"])==10 and first["range_start"]==1 and first["range_end"]==10
    assert len(last["hosts"])==9 and last["range_start"]==271 and last["range_end"]==279 and last["has_next"] is False
    page_two=client.get("/api/search",params={"q":"asn:AS64590","page":2}).json()
    assert not ({host["ip"] for host in first["hosts"]}&{host["ip"] for host in page_two["hosts"]})


def test_zero_results_have_complete_pagination_metadata(system):
    client,_,_=system;result=client.get("/api/search",params={"q":"ip:203.0.113.99"}).json()
    assert result["total"]==0 and result["hosts"]==[] and result["total_pages"]==0 and result["range_start"]==0 and result["range_end"]==0


def test_host_service_dedup_preserves_observation_history(system,admin_headers):
    client,_,database=system;payload={"provenance":"repeatable-dataset","observations":[{"ip":"192.0.2.8","port":443,"service":"https","product":"nginx","banner":"same banner"}]}
    client.post("/api/admin/import",headers=admin_headers,json=payload);client.post("/api/admin/import",headers=admin_headers,json=payload)
    with database.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM hosts WHERE ip='192.0.2.8'").fetchone()[0]==1
        assert db.execute("SELECT COUNT(*) FROM services WHERE host_ip='192.0.2.8' AND port=443").fetchone()[0]==1
        assert db.execute("SELECT COUNT(*) FROM observations WHERE ip='192.0.2.8' AND port=443").fetchone()[0]==2


def test_prefix_mapping_associates_real_hosts_without_expanding_network(system,admin_headers):
    client,_,database=system
    client.post("/api/admin/passive/import",headers=admin_headers,json={"records":[{"subject":"AS64591","subject_type":"asn","asn":"AS64591","org":"Mapped Network","network":"198.51.100.0/24","record_type":"announced-prefix","value":{"prefix":"198.51.100.0/24"},"source":"routing-fixture"}]})
    client.post("/api/admin/import",headers=admin_headers,json={"provenance":"observed-host-only","observations":[{"ip":"198.51.100.23","port":22,"service":"ssh","banner":"SSH fixture"}]})
    result=client.get("/api/search",params={"q":"asn:64591"}).json()
    assert result["total"]==1 and result["hosts"][0]["ip"]=="198.51.100.23" and result["hosts"][0]["network_prefix"]=="198.51.100.0/24"
    with database.connection() as db:assert db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]==1


def test_indexed_service_and_hostname_search(system,admin_headers):
    client,_,_=system
    client.post("/api/admin/import",headers=admin_headers,json={"provenance":"service-fixture","observations":[{"ip":"192.0.2.80","port":8443,"hostname":"portal.example.test","service":"https","product":"Jetty","banner":"HTTP fixture"}]})
    assert client.get("/api/search",params={"q":"port:8443 service:https"}).json()["total"]==1
    assert client.get("/api/search",params={"q":"hostname:portal.example.test"}).json()["total"]==1


def test_resumable_paginated_dataset_ingestion(system,admin_headers):
    client,_,database=system
    page1={"dataset_id":"licensed-feed","source":"licensed-feed","cursor":"","next_cursor":"page-2","complete":False,"observations":observations(2,500)}
    first=client.post("/api/admin/datasets/ingest",headers=admin_headers,json=page1);assert first.status_code==200 and first.json()["status"]=="partial"
    duplicate=client.post("/api/admin/datasets/ingest",headers=admin_headers,json=page1);assert duplicate.json()["deduplicated"] is True
    page2={"dataset_id":"licensed-feed","source":"licensed-feed","cursor":"page-2","next_cursor":"done","complete":True,"observations":observations(1,502)}
    assert client.post("/api/admin/datasets/ingest",headers=admin_headers,json=page2).json()["status"]=="completed"
    with database.connection() as db:assert db.execute("SELECT records_processed FROM dataset_ingestions WHERE dataset_id='licensed-feed'").fetchone()[0]==3


def test_additive_migration_preserves_v03_hosts(tmp_path,monkeypatch):
    import app.database as database
    path=tmp_path/"legacy.db";db=sqlite3.connect(path)
    db.executescript("""CREATE TABLE observations(id INTEGER PRIMARY KEY,ip TEXT NOT NULL,port INTEGER NOT NULL,proto TEXT NOT NULL DEFAULT 'tcp',asn TEXT NOT NULL DEFAULT '',org TEXT NOT NULL DEFAULT '',country TEXT NOT NULL DEFAULT '',product TEXT NOT NULL DEFAULT '',banner TEXT NOT NULL DEFAULT '',source TEXT NOT NULL DEFAULT 'manual',seen_at TEXT NOT NULL,is_demo INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE hosts(ip TEXT PRIMARY KEY,hostname TEXT NOT NULL DEFAULT '',asn TEXT NOT NULL DEFAULT '',org TEXT NOT NULL DEFAULT '',country TEXT NOT NULL DEFAULT '',first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,last_scan_at TEXT NOT NULL DEFAULT '',is_demo INTEGER NOT NULL DEFAULT 0);
    INSERT INTO observations(ip,port,asn,org,source,seen_at) VALUES('192.0.2.4',443,'AS64500','Legacy Org','legacy','2026-01-01T00:00:00Z');
    INSERT INTO hosts(ip,asn,org,first_seen,last_seen) VALUES('192.0.2.4','AS64500','Legacy Org','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');""");db.commit();db.close()
    monkeypatch.setattr(database,"DB_PATH",path);database.init_db(False)
    with database.connection() as migrated:
        host=migrated.execute("SELECT * FROM hosts WHERE ip='192.0.2.4'").fetchone();assert host["asn"]=="AS64500" and host["ip_version"]==4 and host["ip_hex"]
        assert migrated.execute("SELECT COUNT(*) FROM services WHERE host_ip='192.0.2.4'").fetchone()[0]==1


def test_recurring_index_schedule_is_admin_only_and_resumable(system,admin_headers):
    client,_,database=system
    body={"name":"Refresh ASN","query":"asn:64592","interval_seconds":300,"enabled":True}
    assert client.post("/api/admin/indexing/schedules",json=body).status_code==401
    created=client.post("/api/admin/indexing/schedules",headers=admin_headers,json=body);assert created.status_code==200
    schedules=client.get("/api/admin/indexing/schedules",headers=admin_headers).json()["schedules"]
    assert schedules[0]["query"]=="asn:64592" and schedules[0]["last_status"]=="scheduled"


def test_frontend_keeps_query_and_numbered_page_state():
    script=(Path(__file__).parents[1]/"app/static/app.js").read_text()
    assert "prefix_page=${prefixPage}" in script and "metadata_page=${metadataPage}" in script
    assert "numberedPagination" in script and "&page=1" in script
