import concurrent.futures
import time

from app.enrichment import ProviderResult


def wait_for_job(client, job_id):
    for _ in range(100):
        job=client.get(f"/api/enrichment/{job_id}").json()
        if job["status"] in {"completed","partial","failed"}:return job
        time.sleep(.01)
    raise AssertionError("enrichment did not complete")


def configure_fake(system,monkeypatch,provider_type,lookup):
    client,main,database=system;main.ENRICHMENT_ENABLED=True
    with database.connection() as db:
        db.execute("UPDATE passive_providers SET enabled=CASE WHEN provider_type=? THEN 1 ELSE 0 END",(provider_type,))
    class FakeProvider:
        def lookup(self,kind,value,source):return lookup(kind,value,source)
    import app.enrichment as enrichment
    monkeypatch.setitem(enrichment.PROVIDER_CLASSES,provider_type,FakeProvider)
    return client,main,database


def test_unseen_asn_enriches_and_normalizes_both_forms(system,monkeypatch):
    calls=[]
    def lookup(kind,value,source):
        calls.append((kind,value));assert kind=="asn" and value=="AS30925"
        return ProviderResult(records=[
          {"subject":value,"subject_type":"asn","ip":"","domain":"","asn":value,"org":"Example Transit","network":"","record_type":"asn-overview","value":{"announced":True},"source":source,"observed_at":"2026-11-08T10:00:00Z"},
          {"subject":value,"subject_type":"asn","ip":"","domain":"","asn":value,"org":"Example Transit","network":"203.0.113.0/24","record_type":"announced-prefix","value":{"prefix":"203.0.113.0/24"},"source":source,"observed_at":"2026-11-08T10:00:00Z"}] )
    client,_,_=configure_fake(system,monkeypatch,"ripestat",lookup)
    first=client.get("/api/search",params={"q":"asn:30925"}).json();assert first["enrichment"]["status"]=="enriching"
    wait_for_job(client,first["enrichment"]["id"])
    second=client.get("/api/search",params={"q":"asn:AS30925"}).json()
    assert second["passive_total"]==2 and any(row["prefix"]=="203.0.113.0/24" for row in second["asn_intelligence"]["announced_networks"]["results"])
    assert calls==[("asn","AS30925")]


def test_unseen_ip_and_domain_receive_passive_metadata(system,monkeypatch):
    def lookup(kind,value,source):
        fields={"subject":value,"subject_type":kind,"ip":value if kind=="ip" else "","domain":value if kind=="domain" else "","asn":"AS64500" if kind=="ip" else "","org":"Registry Owner","network":"192.0.2.0/24" if kind=="ip" else "","record_type":"routing" if kind=="ip" else "domain-rdap","value":{"real":True},"source":source,"observed_at":"2026-11-08T10:00:00Z"}
        return ProviderResult(records=[fields])
    client,_,database=configure_fake(system,monkeypatch,"rdap",lookup)
    for query in ("ip:192.0.2.44","domain:example.test"):
        first=client.get("/api/search",params={"q":query}).json();wait_for_job(client,first["enrichment"]["id"])
        result=client.get("/api/search",params={"q":query}).json();assert result["passive_total"]==1 and result["passive_intelligence"][0]["value"]["real"] is True


def test_concurrent_searches_deduplicate_provider_request(system,monkeypatch):
    calls=[]
    def lookup(kind,value,source):
        calls.append(value);time.sleep(.05)
        return ProviderResult(records=[{"subject":value,"subject_type":"asn","ip":"","domain":"","asn":value,"org":"Concurrent ASN","network":"198.51.100.0/24","record_type":"announced-prefix","value":{"prefix":"198.51.100.0/24"},"source":source,"observed_at":"2026-11-08T10:00:00Z"}])
    client,_,database=configure_fake(system,monkeypatch,"ripestat",lookup)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        responses=list(pool.map(lambda _:client.get("/api/search",params={"q":"asn:64544"}),range(8)))
    assert all(response.status_code==200 for response in responses)
    with database.connection() as db:
        jobs=db.execute("SELECT * FROM enrichment_jobs WHERE query_key='asn:AS64544'").fetchall()
    wait_for_job(client,jobs[0]["id"])
    assert len(jobs)==1 and calls==["AS64544"]


def test_deep_recon_is_admin_only_and_splits_authorized_campaign(system,admin_headers):
    client,main,database=system;main.MAX_BATCH_TARGETS=256
    passive={"records":[{"subject":"AS64555","subject_type":"asn","asn":"AS64555","network":"198.51.100.0/23","record_type":"announced-prefix","value":{"prefix":"198.51.100.0/23"},"source":"test-routing"}]}
    assert client.post("/api/admin/passive/import",headers=admin_headers,json=passive).status_code==200
    assert client.post("/api/admin/authorizations",headers=admin_headers,json={"name":"owned test range","cidr":"198.51.100.0/23"}).status_code==200
    profiles=client.get("/api/admin/profiles",headers=admin_headers).json()["profiles"]
    profile=next(item for item in profiles if item["name"]=="Quick Recon")
    body={"query":"asn:64555","profile_id":profile["id"]}
    assert client.post("/api/admin/deep-recon/preview",json=body).status_code==401
    preview=client.post("/api/admin/deep-recon/preview",headers=admin_headers,json=body).json()
    assert preview["candidates"][0]["authorized"] is True and preview["candidates"][0]["batches"]==2
    launch={**body,"targets":["198.51.100.0/23"]}
    assert client.post("/api/admin/deep-recon/launch",json=launch).status_code==401
    campaign=client.post("/api/admin/deep-recon/launch",headers=admin_headers,json=launch)
    assert campaign.status_code==200 and campaign.json()["job_count"]==2
    with database.connection() as db:
        rows=db.execute("SELECT target,status FROM scan_jobs ORDER BY target").fetchall()
    assert [row["target"] for row in rows]==["198.51.100.0/24","198.51.101.0/24"] and all(row["status"]=="queued" for row in rows)


def test_deep_recon_rejects_out_of_scope_search_target(system,admin_headers):
    client,_,_=system
    profile=next(item for item in client.get("/api/admin/profiles",headers=admin_headers).json()["profiles"] if item["name"]=="Quick Recon")
    launch={"query":"ip:203.0.113.9","profile_id":profile["id"],"targets":["203.0.113.9/32"]}
    assert client.post("/api/admin/deep-recon/launch",headers=admin_headers,json=launch).status_code==403
