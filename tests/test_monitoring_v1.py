import json
from datetime import datetime, timedelta, timezone

from conftest import authorize, create_job, enroll


def _monitor(client,admin_headers,target="127.0.0.1/32"):
    auth=client.post("/api/admin/authorizations",headers=admin_headers,json={"name":"monitor authorization","cidr":"127.0.0.0/24"}).json()
    result=client.post("/api/admin/monitor/targets",headers=admin_headers,json={"name":"lab monitor","target":target,"authorization_id":auth["id"],"cooldown_seconds":60})
    assert result.status_code==200
    return result.json()


def test_active_scan_absence_creates_disappearance_alert(system,admin_headers):
    client,main,database=system
    monitor=_monitor(client,admin_headers)
    with database.connection() as db:
        main.store(db,[main.Observation(ip="127.0.0.1",port=443,service="https",product="Example",source="imported")],"imported")
    _,worker_headers=enroll(client)
    job=create_job(client,admin_headers,target="127.0.0.1/32",ports=[443]).json()
    claimed=client.post("/api/worker/jobs/claim",headers=worker_headers,json={}).json()["jobs"][0]
    response=client.post(f"/api/worker/jobs/{job['id']}/results",headers=worker_headers,json={"lease_token":claimed["lease_token"],"idempotency_key":"monitor-no-port-result","completed_checks":1,"observations":[]})
    assert response.status_code==200
    events=client.get("/api/admin/monitor/events",headers=admin_headers).json()["results"]
    disappeared=next(event for event in events if event["event_type"]=="service_disappeared")
    assert disappeared["ip"]=="127.0.0.1" and disappeared["target_id"]==monitor["id"]
    assert disappeared["details"]["scan_job_id"]==job["id"]


def test_certificate_expiry_and_notification_outbox(system,admin_headers,monkeypatch):
    client,main,database=system
    _monitor(client,admin_headers)
    destination=client.post("/api/admin/monitor/destinations",headers=admin_headers,json={"name":"local test inbox","kind":"email","endpoint":"alerts@example.test"})
    assert destination.status_code==200
    expiry=(datetime.now(timezone.utc)+timedelta(days=10)).isoformat()
    with database.connection() as db:
        main.store(db,[main.Observation(ip="127.0.0.1",port=443,service="https",product="FixtureTLS",tls={"cert":{"not_after":expiry,"fingerprint_sha256":"fixture-fingerprint"}},source="fixture")],"fixture")
    deliveries=[]
    monkeypatch.setattr("app.monitoring._send_email",lambda address,payload:deliveries.append((address,payload["event_type"])))
    from app.monitoring import run_monitoring_checks_once
    assert run_monitoring_checks_once()==1
    assert set(deliveries)=={("alerts@example.test","service_observed"),("alerts@example.test","certificate_expiring")}
    notifications=client.get("/api/admin/monitor/notifications",headers=admin_headers).json()
    assert len(notifications["results"])==2 and all(row["status"]=="delivered" for row in notifications["results"])
    events=client.get("/api/admin/monitor/events",headers=admin_headers).json()["results"]
    event=next(row for row in events if row["event_type"]=="certificate_expiring")
    acknowledged=client.post(f"/api/admin/monitor/events/{event['id']}/acknowledge",headers=admin_headers)
    assert acknowledged.status_code==200 and acknowledged.json()["acknowledged"]


def test_webhook_destination_rejects_private_addresses_and_admin_is_required(system,admin_headers):
    client,_,_=system
    body={"name":"unsafe hook","kind":"webhook","endpoint":"https://127.0.0.1/hook"}
    assert client.post("/api/admin/monitor/destinations",json=body).status_code==401
    response=client.post("/api/admin/monitor/destinations",headers=admin_headers,json=body)
    assert response.status_code==422
    assert client.get("/api/admin/monitor/destinations").status_code==401


def test_admin_run_once_checks_cert_expiry_and_delivers_outbox(system,admin_headers,monkeypatch):
    client,main,database=system
    future=(datetime.now(timezone.utc)+timedelta(days=7)).isoformat()
    with database.connection() as db:
        main.store(db,[main.Observation(ip="127.0.0.8",port=443,service="https",tls={"cert":{"not_after":future}},source="run-once-fixture")],"run-once-fixture")
    _monitor(client,admin_headers,target="127.0.0.8/32")
    assert client.post("/api/admin/monitor/destinations",headers=admin_headers,json={"name":"run-once inbox","kind":"email","endpoint":"alerts@example.test"}).status_code==200
    delivered=[]
    monkeypatch.setattr("app.monitoring._send_email",lambda address,payload:delivered.append(payload["event_type"]))
    assert client.post("/api/admin/monitor/run-once").status_code==401
    run=client.post("/api/admin/monitor/run-once",headers=admin_headers)
    assert run.status_code==200 and run.json()["created_events"]==1
    assert delivered==["certificate_expiring"]
    assert client.get("/api/admin/monitor/notifications",headers=admin_headers).json()["results"][0]["status"]=="delivered"
