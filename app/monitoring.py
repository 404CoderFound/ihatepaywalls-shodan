"""Durable monitoring event creation, certificate checks, and notification delivery."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import smtplib
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import urlsplit

from .database import connection, utc_now

_started=False


def _matches(target: str, ip: str) -> bool:
    try:
        scope=ipaddress.ip_network(target,strict=False);address=ipaddress.ip_address(ip)
        return scope.version==address.version and address in scope
    except ValueError:return False


def create_event(db, monitor, ip: str, event_type: str, details: dict, source: str, observed_at: str|None=None) -> int|None:
    allowed=json.loads(monitor["alert_types_json"] or "[]") if "alert_types_json" in monitor.keys() else []
    if event_type not in allowed:return None
    now=observed_at or utc_now();cooldown=int(monitor["cooldown_seconds"] if "cooldown_seconds" in monitor.keys() else 900)
    boundary=datetime.now(timezone.utc).timestamp()-cooldown
    recent=db.execute("SELECT id FROM monitor_events WHERE target_id=? AND ip=? AND event_type=? AND created_at>=? ORDER BY id DESC LIMIT 1",(monitor["id"],ip,event_type,datetime.fromtimestamp(boundary,timezone.utc).isoformat(timespec="seconds"))).fetchone()
    if recent:return None
    cur=db.execute("INSERT INTO monitor_events(target_id,ip,event_type,details,source,created_at) VALUES(?,?,?,?,?,?)",(monitor["id"],ip,event_type,json.dumps(details,sort_keys=True),source,now))
    event_id=cur.lastrowid
    db.execute("INSERT OR IGNORE INTO monitor_notifications(event_id,destination_id,status,next_attempt_at) SELECT ?,id,'queued',0 FROM monitor_destinations WHERE enabled=1",(event_id,))
    return event_id


def _validate_public_https(url: str) -> None:
    parsed=urlsplit(url)
    if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Webhook endpoint must be an HTTPS URL without credentials or fragment")
    try:addresses={ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(parsed.hostname,parsed.port or 443,type=socket.SOCK_STREAM)}
    except OSError as exc:raise ValueError("Webhook hostname did not resolve") from exc
    if not addresses or any(not address.is_global for address in addresses):raise ValueError("Webhook hostname must resolve only to public IP addresses")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None


def _send_webhook(endpoint: str, payload: dict) -> None:
    _validate_public_https(endpoint)
    body=json.dumps(payload,separators=(",",":"),ensure_ascii=False).encode()
    secret=os.getenv("MONITOR_WEBHOOK_SECRET","")
    headers={"Content-Type":"application/json","User-Agent":"ScanLattice/1.0"}
    if secret:headers["X-ScanLattice-Signature"]="sha256="+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
    opener=urllib.request.build_opener(_NoRedirect)
    request=urllib.request.Request(endpoint,data=body,headers=headers,method="POST")
    with opener.open(request,timeout=10) as response:
        if response.status<200 or response.status>=300:raise RuntimeError(f"Webhook returned HTTP {response.status}")


def _send_email(address: str, payload: dict) -> None:
    host=os.getenv("SMTP_HOST","");sender=os.getenv("SMTP_FROM","")
    if not host or not sender:raise RuntimeError("SMTP_HOST and SMTP_FROM must be configured")
    message=EmailMessage();message["Subject"]=f"ScanLattice alert: {payload['event_type']}";message["From"]=sender;message["To"]=address
    message.set_content(json.dumps(payload,indent=2,ensure_ascii=False))
    port=int(os.getenv("SMTP_PORT","465"));username=os.getenv("SMTP_USERNAME","");password=os.getenv("SMTP_PASSWORD","")
    if port==465:
        with smtplib.SMTP_SSL(host,port,timeout=10,context=ssl.create_default_context()) as client:
            if username:client.login(username,password)
            client.send_message(message)
    else:
        with smtplib.SMTP(host,port,timeout=10) as client:
            client.starttls(context=ssl.create_default_context())
            if username:client.login(username,password)
            client.send_message(message)


def deliver_notifications_once(limit: int=100) -> int:
    with connection() as db:
        rows=[dict(r) for r in db.execute("""SELECT n.*,d.kind,d.endpoint,e.ip,e.event_type,e.details,e.source,e.created_at event_created
          FROM monitor_notifications n JOIN monitor_destinations d ON d.id=n.destination_id
          JOIN monitor_events e ON e.id=n.event_id WHERE n.status='queued' AND n.next_attempt_at<=? AND d.enabled=1 ORDER BY n.id LIMIT ?""",(int(time.time()),limit))]
    delivered=0
    for row in rows:
        payload={"id":row["event_id"],"ip":row["ip"],"event_type":row["event_type"],"details":json.loads(row["details"]),"source":row["source"],"observed_at":row["event_created"]}
        try:
            if row["kind"]=="webhook":_send_webhook(row["endpoint"],payload)
            else:_send_email(row["endpoint"],payload)
            with connection() as db:db.execute("UPDATE monitor_notifications SET status='delivered',attempts=attempts+1,delivered_at=?,error='' WHERE id=?",(utc_now(),row["id"]))
            delivered+=1
        except Exception as exc:
            attempts=row["attempts"]+1;status="failed" if attempts>=8 else "queued";next_at=int(time.time()+min(3600,15*(2**min(attempts,8))))
            with connection() as db:db.execute("UPDATE monitor_notifications SET status=?,attempts=?,next_attempt_at=?,error=? WHERE id=?",(status,attempts,next_at,str(exc)[:500],row["id"]))
    return delivered


def run_monitoring_checks_once() -> int:
    now=datetime.now(timezone.utc);cutoff=(now.timestamp()+30*86400)
    with connection() as db:
        services=[dict(r) for r in db.execute("SELECT s.host_ip,s.port,s.proto,s.tls_json,s.source,s.last_seen FROM services s WHERE s.tls_json!='{}'")]
        monitors=[dict(r) for r in db.execute("SELECT * FROM monitor_targets WHERE enabled=1")]
        created=0
        for service in services:
            try:tls=json.loads(service["tls_json"]);cert=tls.get("cert",tls) if isinstance(tls,dict) else {};expiry=cert.get("not_after") or cert.get("notAfter") or tls.get("not_after")
            except (ValueError,AttributeError):continue
            if not expiry:continue
            try:
                if isinstance(expiry,(int,float)):expires=datetime.fromtimestamp(expiry,timezone.utc)
                else:
                    expires=datetime.fromisoformat(str(expiry).replace("Z","+00:00"))
                    if expires.tzinfo is None:expires=expires.replace(tzinfo=timezone.utc)
                if not now.timestamp()<expires.timestamp()<=cutoff:continue
            except (ValueError,OverflowError,OSError):continue
            details={"port":service["port"],"protocol":service["proto"],"expires_at":expires.astimezone(timezone.utc).isoformat(timespec="seconds"),"days_remaining":max(0,(expires.timestamp()-now.timestamp())//86400)}
            for monitor in monitors:
                if _matches(monitor["target"],service["host_ip"]):created+=bool(create_event(db,monitor,service["host_ip"],"certificate_expiring",details,service["source"],now.isoformat(timespec="seconds")))
    deliver_notifications_once()
    return created


def start_scheduler() -> None:
    global _started
    if os.getenv("MONITORING_AUTO_CHECKS","false").lower() not in {"1","true","yes"} or _started:return
    _started=True
    def loop():
        while True:
            try:run_monitoring_checks_once()
            except Exception as exc:print(f"Monitoring scheduler error: {str(exc)[:300]}",flush=True)
            time.sleep(300)
    threading.Thread(target=loop,name="scanlattice-monitoring",daemon=True).start()
