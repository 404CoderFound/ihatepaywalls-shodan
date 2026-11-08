from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import threading
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any

from .database import connection, utc_now
from .search import ParsedQuery

USER_AGENT = "ScanLattice/0.4 (+https://scanlattice.plezi.eu; passive intelligence cache)"
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="passive-enrichment")
_LOCK = threading.Lock()
_RUNNING: set[str] = set()
_SCHEDULER_STARTED = False


@dataclass
class ProviderResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""


def enrichment_target(parsed: ParsedQuery) -> tuple[str, str] | None:
    supported = [(key, values[0]) for key, values in parsed.filters.items() if key in {"asn", "ip", "net", "domain", "hostname"} and len(values) == 1]
    if len(supported) == 1:
        kind, value = supported[0]
        return ("domain" if kind == "hostname" else kind, value.lower() if kind in {"domain", "hostname"} else value)
    if parsed.filters or len(parsed.free) != 1:
        return None
    value = parsed.free[0].strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
        return ("ip" if network.num_addresses == 1 else "net", str(network.network_address) if network.num_addresses == 1 else str(network))
    except ValueError:
        pass
    if re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", value):
        return "domain", value.lower().rstrip(".")
    return None


def _fetch_json(url: str, timeout: float = 8) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json, application/rdap+json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(2 * 1024 * 1024))


class RIPEstatProvider:
    provider_type = "ripestat"
    base = "https://stat.ripe.net/data/"

    def _call(self, endpoint: str, resource: str) -> dict[str, Any]:
        url = f"{self.base}{endpoint}/data.json?{urllib.parse.urlencode({'resource': resource})}"
        payload = _fetch_json(url)
        if payload.get("status") != "ok":
            raise ValueError(payload.get("messages") or "RIPEstat request failed")
        return payload.get("data", {})

    def lookup(self, kind: str, value: str, source: str) -> ProviderResult:
        now = utc_now(); records: list[dict[str, Any]] = []
        try:
            if kind == "asn":
                asn = value.upper()
                overview = self._call("as-overview", asn)
                records.append(_record(asn,"asn",source,"asn-overview",overview,now,asn=asn,org=str(overview.get("holder") or "")))
                prefixes = self._call("announced-prefixes", asn).get("prefixes", [])
                for item in prefixes:
                    prefix = item.get("prefix")
                    if prefix:records.append(_record(asn,"asn",source,"announced-prefix",item,now,asn=asn,network=prefix))
                v4=sum(1 for item in prefixes if ":" not in item.get("prefix", ""));v6=len(prefixes)-v4
                records.append(_record(asn,"asn",source,"prefix-statistics",{"ipv4_prefixes":v4,"ipv6_prefixes":v6,"total_prefixes":len(prefixes)},now,asn=asn,org=str(overview.get("holder") or "")))
            elif kind == "ip":
                data=self._call("network-info",value);prefix=data.get("prefix","");asns=data.get("asns",[])
                records.append(_record(value,"ip",source,"routing",data,now,ip=value,asn=f"AS{asns[0]}" if asns else "",network=prefix))
            elif kind == "net":
                data=self._call("prefix-overview",value);asns=data.get("asns",[])
                asn_value=f"AS{asns[0].get('asn')}" if asns and isinstance(asns[0],dict) else ""
                org=str(asns[0].get("holder") or "") if asns and isinstance(asns[0],dict) else ""
                records.append(_record(value,"network",source,"prefix-overview",data,now,asn=asn_value,org=org,network=value))
            else:return ProviderResult(error="unsupported query type")
            return ProviderResult(records=records)
        except Exception as exc:return ProviderResult(records=records,error=str(exc)[:500])


class RDAPProvider:
    provider_type = "rdap"
    base = "https://rdap.org/"

    def lookup(self, kind: str, value: str, source: str) -> ProviderResult:
        if kind not in {"ip","net","domain"}:return ProviderResult(error="unsupported query type")
        resource = str(ipaddress.ip_network(value,strict=False).network_address) if kind == "net" else value
        path = "domain" if kind == "domain" else "ip"
        try:
            data=_fetch_json(f"{self.base}{path}/{urllib.parse.quote(resource,safe='')}")
            network=""
            if data.get("startAddress") and data.get("endAddress"):
                network=str(next(ipaddress.summarize_address_range(ipaddress.ip_address(data["startAddress"]),ipaddress.ip_address(data["endAddress"]))))
            record=_record(value,kind,source,"domain-rdap" if kind=="domain" else "rdap",_compact_rdap(data),utc_now(),ip=value if kind=="ip" else "",domain=value if kind=="domain" else "",org=str(data.get("name") or ""),network=network)
            return ProviderResult(records=[record])
        except Exception as exc:return ProviderResult(error=str(exc)[:500])


class CertificateTransparencyProvider:
    """Optional crt.sh JSON integration; disabled until an administrator enables it."""
    provider_type = "certificate_transparency"
    base = "https://crt.sh/"

    def lookup(self, kind: str, value: str, source: str) -> ProviderResult:
        if kind != "domain":return ProviderResult(error="unsupported query type")
        try:
            query=urllib.parse.urlencode({"q":f"%.{value}","output":"json"})
            payload=_fetch_json(f"{self.base}?{query}",timeout=10)
            if not isinstance(payload,list):raise ValueError("Unexpected Certificate Transparency response")
            records=[];seen=set();now=utc_now()
            for item in payload[:500]:
                names=[name.strip().lower().removeprefix("*.") for name in str(item.get("name_value","")).splitlines()]
                names=[name for name in names if name==value or name.endswith("."+value)]
                key=(item.get("id"),tuple(names))
                if not names or key in seen:continue
                seen.add(key)
                compact={field:item.get(field) for field in ("id","issuer_name","common_name","name_value","not_before","not_after","serial_number") if item.get(field) is not None}
                records.append(_record(value,"domain",source,"certificate-transparency",compact,now,domain=value))
                for name in names:
                    records.append(_record(value,"domain",source,"ct-subdomain",{"name":name,"certificate_id":item.get("id")},now,domain=name))
            return ProviderResult(records=records)
        except Exception as exc:return ProviderResult(error=str(exc)[:500])


PROVIDER_CLASSES = {"ripestat": RIPEstatProvider, "rdap": RDAPProvider, "certificate_transparency": CertificateTransparencyProvider}


def _compact_rdap(data: dict[str, Any]) -> dict[str, Any]:
    keys=("handle","name","type","country","startAddress","endAddress","port43","status","events","nameservers","secureDNS","ldhName","unicodeName")
    return {key:data[key] for key in keys if key in data}


def _record(subject: str, subject_type: str, source: str, record_type: str, value: dict[str, Any], observed_at: str, **fields: str) -> dict[str, Any]:
    return {"subject":subject,"subject_type":subject_type,"ip":fields.get("ip",""),"domain":fields.get("domain",""),"asn":fields.get("asn",""),"org":fields.get("org",""),"network":fields.get("network",""),"record_type":record_type,"value":value,"source":source,"observed_at":observed_at}


def _consume_quota(db, provider) -> bool:
    window=int(time.time())//60;row=db.execute("SELECT request_count FROM passive_provider_usage WHERE provider_id=? AND window_start=?",(provider["id"],window)).fetchone()
    if row and row[0]>=provider["requests_per_minute"]:return False
    db.execute("INSERT INTO passive_provider_usage(provider_id,window_start,request_count) VALUES(?,?,1) ON CONFLICT(provider_id,window_start) DO UPDATE SET request_count=request_count+1",(provider["id"],window));return True


def _store_records(db, provider_id: int, records: list[dict[str, Any]], ttl: int = 86400) -> int:
    count=0;expires=int(time.time())+ttl
    for row in records:
        cursor=db.execute("""INSERT INTO passive_records(subject,subject_type,ip,domain,asn,org,network,record_type,value_json,source,observed_at,expires_at,provider_id)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(subject,record_type,source,value_json) DO UPDATE SET observed_at=excluded.observed_at,expires_at=excluded.expires_at""",
          (row["subject"],row["subject_type"],row.get("ip",""),row.get("domain",""),row.get("asn",""),row.get("org",""),row.get("network",""),row["record_type"],json.dumps(row["value"],sort_keys=True),row["source"],row["observed_at"],expires,provider_id))
        count+=1 if cursor.rowcount else 0
        if row.get("network") and row.get("asn"):
            try:
                network=ipaddress.ip_network(row["network"],strict=False)
                db.execute("""INSERT INTO routing_prefixes(prefix,asn,organization,source,first_seen,last_seen,expires_at)
                  VALUES(?,?,?,?,?,?,?) ON CONFLICT(prefix,asn,source) DO UPDATE SET organization=excluded.organization,last_seen=excluded.last_seen,expires_at=excluded.expires_at""",
                  (str(network),row["asn"].upper(),row.get("org",""),row["source"],row["observed_at"],row["observed_at"],expires))
                for host in db.execute("SELECT ip,network_prefix FROM hosts").fetchall():
                    address=ipaddress.ip_address(host["ip"])
                    if address.version!=network.version or address not in network:continue
                    current=ipaddress.ip_network(host["network_prefix"],strict=False) if host["network_prefix"] else None
                    if current is None or network.prefixlen>=current.prefixlen:
                        db.execute("UPDATE hosts SET asn=?,org=CASE WHEN ?!='' THEN ? ELSE org END,network_prefix=? WHERE ip=?",(row["asn"].upper(),row.get("org",""),row.get("org",""),str(network),host["ip"]))
            except ValueError:
                pass
    return count


def ensure_enrichment(db, parsed: ParsedQuery, enabled: bool = True, queue_limit: int = 100) -> tuple[dict[str, Any] | None, bool]:
    target=enrichment_target(parsed)
    if not enabled or not target:return None,False
    kind,value=target;key=f"{kind}:{value}";now=int(time.time())
    existing=db.execute("SELECT 1 FROM enrichment_jobs WHERE query_key=?",(key,)).fetchone()
    if existing is None and db.execute("SELECT COUNT(*) FROM enrichment_jobs WHERE status='enriching'").fetchone()[0]>=queue_limit:
        return {"status":"failed","error":"Passive enrichment queue is full"},False
    timestamp=utc_now();job_id=str(uuid.uuid4())
    created=db.execute("INSERT OR IGNORE INTO enrichment_jobs(id,query_key,query_type,query_value,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",(job_id,key,kind,value,"enriching",timestamp,timestamp))
    job=db.execute("SELECT * FROM enrichment_jobs WHERE query_key=?",(key,)).fetchone()
    if created.rowcount:
        return dict(job),True
    if job and job["status"] in {"completed","partial"} and (job["cache_expires_at"] or 0)>now:
        result=dict(job);result["status"]="cached";return result,False
    if job and job["status"]=="failed" and (job["cache_expires_at"] or 0)>now:
        return dict(job),False
    if job and job["attempts"]>=job["max_attempts"]:
        return dict(job),False
    if job and job["status"]=="enriching":return dict(job),False
    updated=db.execute("UPDATE enrichment_jobs SET status='enriching',error='',updated_at=?,completed_at=NULL WHERE id=? AND status!='enriching'",(timestamp,job["id"]))
    return dict(db.execute("SELECT * FROM enrichment_jobs WHERE id=?",(job["id"],)).fetchone()),bool(updated.rowcount)


def queue_job(job_id: str) -> None:
    with _LOCK:
        if job_id in _RUNNING:return
        _RUNNING.add(job_id)
    future=_EXECUTOR.submit(run_job,job_id)
    future.add_done_callback(lambda _: _finished(job_id))


def _finished(job_id: str) -> None:
    with _LOCK:_RUNNING.discard(job_id)


def run_job(job_id: str) -> None:
    with connection() as db:
        job=db.execute("SELECT * FROM enrichment_jobs WHERE id=?",(job_id,)).fetchone()
        if not job:return
        providers=db.execute("SELECT * FROM passive_providers WHERE enabled=1 ORDER BY id").fetchall()
        relevant=[p for p in providers if p["provider_type"] in PROVIDER_CLASSES]
        db.execute("UPDATE enrichment_jobs SET attempts=attempts+1,started_at=COALESCE(started_at,?),providers_total=?,updated_at=? WHERE id=?",(utc_now(),len(relevant),utc_now(),job_id))
    successes=0;completed=0;added=0;errors=[]
    for provider in relevant:
        with connection() as db:
            if not _consume_quota(db,provider):errors.append(f"{provider['name']}: quota reached");continue
        result=PROVIDER_CLASSES[provider["provider_type"]]().lookup(job["query_type"],job["query_value"],provider["name"])
        completed+=1
        if result.records:
            with connection() as db:added+=_store_records(db,provider["id"],result.records)
            successes+=1
        if result.error and result.error!="unsupported query type":errors.append(f"{provider['name']}: {result.error}")
    status="completed" if successes and not errors else "partial" if successes else "failed"
    with connection() as db:db.execute("UPDATE enrichment_jobs SET status=?,providers_completed=?,records_added=?,error=?,updated_at=?,completed_at=?,cache_expires_at=? WHERE id=?",(status,completed,added,"; ".join(errors)[:2000],utc_now(),utc_now(),int(time.time())+86400 if successes else int(time.time())+300,job_id))


def recover_pending() -> None:
    with connection() as db:
        rows=db.execute("SELECT id FROM enrichment_jobs WHERE status='enriching' AND attempts<max_attempts").fetchall()
    for row in rows:queue_job(row["id"])


def run_due_schedules_once() -> int:
    from .search import parse_query
    now=int(time.time());queued=0
    with connection() as db:schedules=db.execute("SELECT * FROM indexing_schedules WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at LIMIT 20",(now,)).fetchall()
    for schedule in schedules:
        try:
            parsed=parse_query(schedule["query"]);target=enrichment_target(parsed)
            if target is None:raise ValueError("Schedule query must identify one ASN, IP, CIDR, domain or hostname")
            key=f"{target[0]}:{target[1]}"
            with connection() as db:
                db.execute("UPDATE enrichment_jobs SET cache_expires_at=0 WHERE query_key=? AND status!='enriching'",(key,))
                job,should_queue=ensure_enrichment(db,parsed,True)
                db.execute("UPDATE indexing_schedules SET last_run_at=?,next_run_at=?,last_job_id=?,last_status='enriching',last_error='' WHERE id=?",(now,now+schedule["interval_seconds"],job.get("id") if job else None,schedule["id"]))
            if should_queue and job:queue_job(job["id"]);queued+=1
        except Exception as exc:
            with connection() as db:db.execute("UPDATE indexing_schedules SET last_run_at=?,next_run_at=?,last_status='failed',last_error=? WHERE id=?",(now,now+schedule["interval_seconds"],str(exc)[:500],schedule["id"]))
    return queued


def start_schedule_runner() -> None:
    global _SCHEDULER_STARTED
    with _LOCK:
        if _SCHEDULER_STARTED:return
        _SCHEDULER_STARTED=True
    def loop():
        while True:
            try:run_due_schedules_once()
            except Exception:pass
            time.sleep(30)
    threading.Thread(target=loop,name="passive-index-scheduler",daemon=True).start()
