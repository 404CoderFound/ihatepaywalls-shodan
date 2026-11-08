import ast
import socket
import urllib.request
from pathlib import Path

from conftest import authorize, create_job, enroll


def job_count(database):
    with database.connection() as db:
        return db.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0]


def test_public_search_is_unauthenticated_and_never_creates_jobs(system):
    client, _, database = system
    before = job_count(database)
    response = client.get("/api/search", params={"q": "port:443"})
    assert response.status_code == 200
    assert job_count(database) == before


def test_public_cannot_create_or_cancel_jobs(system, admin_headers):
    client, _, _ = system
    assert client.post("/api/admin/jobs", json={"target":"127.0.0.1/32","profile_id":1}).status_code == 401
    authorize(client, admin_headers)
    job = create_job(client, admin_headers).json()
    assert client.post(f"/api/admin/jobs/{job['id']}/cancel").status_code == 401


def test_public_search_performs_no_outbound_probe(system, monkeypatch):
    client, _, _ = system
    def forbidden(*args, **kwargs):
        raise AssertionError("Public search attempted outbound network access")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    assert client.get("/api/search", params={"q":"ip:192.0.2.1"}).status_code == 200


def test_passive_only_host_is_publicly_searchable(system, admin_headers):
    client, _, _ = system
    record={"subject":"198.51.100.77","subject_type":"ip","ip":"198.51.100.77","asn":"AS64577","org":"Passive Example","network":"198.51.100.0/24","record_type":"rdap","value":{"name":"EXAMPLE-NET"},"source":"licensed-rdap-cache","observed_at":"2026-11-08T10:00:00+00:00"}
    assert client.post("/api/admin/passive/import",headers=admin_headers,json={"records":[record]}).status_code==200
    result=client.get("/api/search",params={"q":"ip:198.51.100.77"}).json()
    assert result["total"]==0 and result["passive_total"]==1
    assert result["passive_intelligence"][0]["source"]=="licensed-rdap-cache"
    host=client.get("/api/hosts/198.51.100.77").json()
    assert host["services"]==[] and len(host["passive_intelligence"])==1


def test_no_passive_provider_result_is_fabricated(system):
    client, _, _ = system
    result=client.get("/api/search",params={"q":"domain:not-present.invalid"}).json()
    assert result["has_information"] is False
    assert result["passive_intelligence"]==[] and result["indexed_observations"]==[]
    assert result["message"]=="No indexed or passive information available."
    assert result["enrichment"]["live_lookup_attempted"] is False


def test_approved_rdap_provider_is_cached_without_contacting_target(system,admin_headers,monkeypatch):
    client,_,_=system
    created=client.post("/api/admin/passive/providers",headers=admin_headers,json={"name":"approved-rdap","provider_type":"rdap","enabled":True,"config":{"base_url":"https://rdap.org/ip/"},"requests_per_minute":2})
    assert created.status_code==200
    calls=[]
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def read(self,limit):return b'{"handle":"NET-TEST","name":"Test Registry Network","startAddress":"203.0.113.0","endAddress":"203.0.113.255","country":"ZZ"}'
    def provider_call(request,timeout):
        calls.append(request.full_url);assert request.full_url=="https://rdap.org/ip/203.0.113.9";return Response()
    monkeypatch.setattr(urllib.request,"urlopen",provider_call)
    first=client.get("/api/search",params={"q":"ip:203.0.113.9"}).json()
    second=client.get("/api/search",params={"q":"ip:203.0.113.9"}).json()
    assert first["passive_total"]==1 and first["enrichment"]["live_lookup_attempted"] is True
    assert second["passive_total"]==1 and calls==["https://rdap.org/ip/203.0.113.9"]


def test_admin_session_can_create_authorized_job_with_csrf(system):
    client, _, _ = system
    login=client.post("/api/admin/session",json={"admin_token":"admin-test-token"})
    assert login.status_code==200 and login.cookies.get("scanlattice_session")
    csrf=login.json()["csrf_token"]
    headers={"X-CSRF-Token":csrf}
    assert client.post("/api/admin/authorizations",headers=headers,json={"name":"session local","cidr":"127.0.0.1/32"}).status_code==200
    job=client.post("/api/admin/jobs",headers=headers,json={"target":"127.0.0.1/32","profile_id":1,"ports":[80]})
    assert job.status_code==200
    assert client.post("/api/admin/jobs",json={"target":"127.0.0.1/32","profile_id":1,"ports":[80]}).status_code==403


def test_public_api_rate_limit(system):
    client, main, _ = system
    main.PUBLIC_RATE_LIMIT=2;main.RATE_LIMITER.clear()
    assert client.get("/api/search").status_code==200
    assert client.get("/api/search").status_code==200
    response=client.get("/api/search")
    assert response.status_code==429 and response.headers["retry-after"]=="60"


def test_control_plane_has_no_scanner_imports():
    app_dir=Path(__file__).parents[1]/"app"
    imports=[]
    for path in app_dir.glob("*.py"):
        tree=ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imports.extend(alias.name for alias in node.names)
            elif isinstance(node,ast.ImportFrom) and node.module:imports.append(node.module)
    assert not any(name=="worker" or name.startswith("worker.") for name in imports)
