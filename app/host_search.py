from __future__ import annotations

import ipaddress
import json
import math
import os
import sqlite3
from typing import Any

from .search import ParsedQuery

PER_PAGE = 10


def _port_array_join() -> str:
    if os.getenv("DATABASE_BACKEND", "sqlite").lower() in {"postgres", "postgresql"}:
        return "CROSS JOIN LATERAL jsonb_array_elements_text(pr.value_json::jsonb->'ports') AS p(value)"
    return "CROSS JOIN json_each(pr.value_json,'$.ports') AS p"


def _where_group(filters,free) -> tuple[list[str],list[Any]]:
    clauses: list[str] = [];params: list[Any] = []
    for key, values in filters.items():
        for value in values:
            if key == "ip": clauses.append("h.ip=?");params.append(value)
            elif key == "asn": clauses.append("UPPER(h.asn)=?");params.append(value.upper())
            elif key == "country": clauses.append("UPPER(h.country)=?");params.append(value.upper())
            elif key == "org": clauses.append("LOWER(h.org) LIKE ?");params.append(f"%{value.lower()}%")
            elif key in {"hostname","domain"}:
                clauses.append("(LOWER(h.hostname) LIKE ? OR EXISTS(SELECT 1 FROM hostnames hn WHERE hn.ip=h.ip AND LOWER(hn.hostname) LIKE ?))");params.extend([f"%{value.lower()}%"]*2)
            elif key == "port": clauses.append("(EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND s.port=?) OR EXISTS(SELECT 1 FROM passive_records pr "+_port_array_join()+" WHERE pr.ip=h.ip AND pr.record_type='internetdb-host' AND CAST(p.value AS INTEGER)=?))");params.extend([int(value),int(value)])
            elif key == "service": clauses.append("EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND LOWER(s.service)=LOWER(?))");params.append(value)
            elif key == "product": clauses.append("EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND LOWER(s.product) LIKE ?)");params.append(f"%{value.lower()}%")
            elif key == "source": clauses.append("(LOWER(h.source)=LOWER(?) OR EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND LOWER(s.source)=LOWER(?)))");params.extend([value,value])
            elif key == "os": clauses.append("LOWER(h.os_name) LIKE ?");params.append(f"%{value.lower()}%")
            elif key == "http.title": clauses.append("EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND LOWER(COALESCE(json_extract(s.http_json,'$.title'),'')) LIKE ?)");params.append(f"%{value.lower()}%")
            elif key == "http.headers": clauses.append("EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND LOWER(s.http_json) LIKE ?)");params.append(f"%{value.lower()}%")
            elif key == "ssl.cert.subject.cn": clauses.append("EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND (LOWER(COALESCE(json_extract(s.tls_json,'$.cert.subject.CN'),json_extract(s.tls_json,'$.cert.subject.cn'),'')) LIKE ? OR LOWER(s.tls_json) LIKE ?))");params.extend([f"%{value.lower()}%",f"%{value.lower()}%"])
            elif key == "ssl.cert.issuer.cn": clauses.append("EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND (LOWER(COALESCE(json_extract(s.tls_json,'$.cert.issuer.CN'),json_extract(s.tls_json,'$.cert.issuer.cn'),'')) LIKE ? OR LOWER(s.tls_json) LIKE ?))");params.extend([f"%{value.lower()}%",f"%{value.lower()}%"])
            elif key == "cpe": clauses.append("EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND LOWER(s.cpe) LIKE ?)");params.append(f"%{value.lower()}%")
            elif key == "vuln": clauses.append("EXISTS(SELECT 1 FROM host_vulnerability_matches v WHERE v.host_ip=h.ip AND UPPER(v.cve)=UPPER(?))");params.append(value)
            elif key == "before": clauses.append("h.last_seen<?");params.append(value+"T23:59:59")
            elif key == "after": clauses.append("h.last_seen>=?");params.append(value+"T00:00:00")
            elif key == "has_screenshot":
                if value.lower()=="true":clauses.append("0") # No screenshot storage is configured.
            elif key == "net":
                network=ipaddress.ip_network(value,strict=False);start=f"{int(network.network_address):032x}";end=f"{int(network.broadcast_address):032x}"
                clauses.append("h.ip_version=? AND h.ip_hex BETWEEN ? AND ?");params.extend([network.version,start,end])
    for token in free:
        like=f"%{token.lower()}%";clauses.append("(LOWER(h.ip) LIKE ? OR LOWER(h.hostname) LIKE ? OR LOWER(h.org) LIKE ? OR EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND (LOWER(s.service) LIKE ? OR LOWER(s.product) LIKE ? OR LOWER(s.banner) LIKE ?)))");params.extend([like]*6)
    return clauses,params


def _where(parsed: ParsedQuery) -> tuple[str, list[Any]]:
    groups=[(parsed.filters,parsed.free),*parsed.alternatives]
    group_sql=[];params=[]
    for filters,free in groups:
        clauses,values=_where_group(filters,free)
        if clauses:group_sql.append("("+" AND ".join(f"({clause})" for clause in clauses)+")");params.extend(values)
    clauses=["("+" OR ".join(group_sql)+")"] if group_sql else []
    for key,value in parsed.excluded:
        filters={key:[value]} if key else {};free=[] if key else [value]
        negative,values=_where_group(filters,free)
        if negative:clauses.append("NOT ("+" AND ".join(f"({item})" for item in negative)+")");params.extend(values)
    return (" WHERE "+" AND ".join(clauses) if clauses else ""),params


def search_hosts(db: sqlite3.Connection, parsed: ParsedQuery, page: int, sort: str="last_seen", per_page: int=PER_PAGE) -> dict[str, Any]:
    where,params=_where(parsed);total=db.execute("SELECT COUNT(*) FROM hosts h"+where,params).fetchone()[0]
    total_pages=math.ceil(total/per_page) if total else 0;page=min(page,total_pages) if total_pages else 1;offset=(page-1)*per_page
    order={"last_seen":"h.last_seen DESC,h.ip_version,h.ip_hex,h.ip","first_seen":"h.first_seen DESC,h.ip_version,h.ip_hex,h.ip","ip":"h.ip_version,h.ip_hex,h.ip"}[sort]
    rows=[dict(row) for row in db.execute("SELECT h.* FROM hosts h"+where+" ORDER BY "+order+" LIMIT ? OFFSET ?",params+[per_page,offset])]
    for host in rows:
        services=[]
        for row in db.execute("SELECT port,proto,service,product,banner,http_json,tls_json,source,last_seen,cpe FROM services WHERE host_ip=? ORDER BY port,proto",(host["ip"],)):
            service=dict(row);service["http"]=json.loads(service.pop("http_json") or "{}");service["tls"]=json.loads(service.pop("tls_json") or "{}");services.append(service)
        host["services"]=services
        host["hostnames"]=[dict(row) for row in db.execute("SELECT hostname,source,last_seen FROM hostnames WHERE ip=? ORDER BY last_seen DESC,hostname",(host["ip"],))]
    start=offset+1 if total else 0;end=min(offset+per_page,total)
    service_filter=where;passive_filter=where
    port_query="SELECT port,COUNT(DISTINCT ip) hosts FROM (SELECT s.port port,s.host_ip ip FROM services s JOIN hosts h ON h.ip=s.host_ip"+service_filter+" UNION ALL SELECT CAST(p.value AS INTEGER) port,pr.ip ip FROM passive_records pr JOIN hosts h ON h.ip=pr.ip "+_port_array_join()+" WHERE pr.record_type='internetdb-host'"+(" AND "+passive_filter[7:] if passive_filter else "")+") GROUP BY port ORDER BY hosts DESC,port LIMIT 50"
    port_facets=[dict(r) for r in db.execute(port_query,params+params)]
    country_facets=[dict(r) for r in db.execute("SELECT h.country,COUNT(DISTINCT h.ip) hosts FROM hosts h"+where+" AND h.country!='' GROUP BY h.country ORDER BY hosts DESC LIMIT 50" if where else "SELECT h.country,COUNT(DISTINCT h.ip) hosts FROM hosts h WHERE h.country!='' GROUP BY h.country ORDER BY hosts DESC LIMIT 50",params)]
    product_facets=[dict(r) for r in db.execute("SELECT s.product,COUNT(DISTINCT s.host_ip) hosts FROM services s JOIN hosts h ON h.ip=s.host_ip"+where+" AND s.product!='' GROUP BY s.product ORDER BY hosts DESC LIMIT 50" if where else "SELECT s.product,COUNT(DISTINCT s.host_ip) hosts FROM services s JOIN hosts h ON h.ip=s.host_ip WHERE s.product!='' GROUP BY s.product ORDER BY hosts DESC LIMIT 50",params)]
    return {"hosts":rows,"page":page,"per_page":per_page,"total":total,"total_pages":total_pages,"has_next":page<total_pages,"has_previous":page>1,"range_start":start,"range_end":end,"facets":{"ports":port_facets,"countries":country_facets,"products":product_facets}}


def asn_intelligence(db: sqlite3.Connection, asn: str, prefix_page: int = 1, metadata_page: int = 1) -> dict[str, Any]:
    prefix_per_page=25;metadata_per_page=25
    overview_row=db.execute("SELECT * FROM passive_records WHERE asn=? AND record_type='asn-overview' ORDER BY observed_at DESC LIMIT 1",(asn,)).fetchone()
    stats_row=db.execute("SELECT * FROM passive_records WHERE asn=? AND record_type='prefix-statistics' ORDER BY observed_at DESC LIMIT 1",(asn,)).fetchone()
    organization=(overview_row["org"] if overview_row else "") or db.execute("SELECT COALESCE(MAX(org),'') FROM hosts WHERE asn=?",(asn,)).fetchone()[0]
    prefix_total=db.execute("SELECT COUNT(DISTINCT prefix) FROM routing_prefixes WHERE asn=?",(asn,)).fetchone()[0]
    prefix_pages=math.ceil(prefix_total/prefix_per_page) if prefix_total else 0;prefix_page=max(1,min(prefix_page,prefix_pages or 1))
    prefixes=[dict(row) for row in db.execute("SELECT prefix,MAX(organization) organization,MAX(source) source,MAX(last_seen) last_seen FROM routing_prefixes WHERE asn=? GROUP BY prefix ORDER BY CASE WHEN instr(prefix,':')=0 THEN 4 ELSE 6 END,prefix LIMIT ? OFFSET ?",(asn,prefix_per_page,(prefix_page-1)*prefix_per_page))]
    metadata_total=db.execute("SELECT COUNT(*) FROM passive_records WHERE asn=? AND record_type NOT IN ('announced-prefix','asn-overview','prefix-statistics')",(asn,)).fetchone()[0]
    metadata_pages=math.ceil(metadata_total/metadata_per_page) if metadata_total else 0;metadata_page=max(1,min(metadata_page,metadata_pages or 1))
    metadata=[dict(row) for row in db.execute("SELECT * FROM passive_records WHERE asn=? AND record_type NOT IN ('announced-prefix','asn-overview','prefix-statistics') ORDER BY observed_at DESC,id DESC LIMIT ? OFFSET ?",(asn,metadata_per_page,(metadata_page-1)*metadata_per_page))]
    for row in metadata:row["value"]=json.loads(row.pop("value_json"))
    indexed_hosts=db.execute("SELECT COUNT(*) FROM hosts WHERE asn=?",(asn,)).fetchone()[0]
    indexed_services=db.execute("SELECT COUNT(*) FROM services s JOIN hosts h ON h.ip=s.host_ip WHERE h.asn=?",(asn,)).fetchone()[0]
    last_enrichment=db.execute("SELECT MAX(observed_at) FROM passive_records WHERE asn=?",(asn,)).fetchone()[0]
    sources=[row[0] for row in db.execute("SELECT DISTINCT source FROM passive_records WHERE asn=? ORDER BY source",(asn,))]
    overview=json.loads(overview_row["value_json"]) if overview_row else {}
    statistics=json.loads(stats_row["value_json"]) if stats_row else {}
    statistics.update({"ipv4_prefixes":db.execute("SELECT COUNT(DISTINCT prefix) FROM routing_prefixes WHERE asn=? AND instr(prefix,':')=0",(asn,)).fetchone()[0],"ipv6_prefixes":db.execute("SELECT COUNT(DISTINCT prefix) FROM routing_prefixes WHERE asn=? AND instr(prefix,':')>0",(asn,)).fetchone()[0],"total_prefixes":prefix_total})
    service_sources=[row[0] for row in db.execute("SELECT DISTINCT s.source FROM services s JOIN hosts h ON h.ip=s.host_ip WHERE h.asn=? AND s.source!='' ORDER BY s.source",(asn,))]
    return {"asn":asn,"organization":organization,"overview":overview,"statistics":statistics,"prefix_count":prefix_total,"indexed_host_count":indexed_hosts,"indexed_service_count":indexed_services,"last_enrichment":last_enrichment,"sources":sources,"host_intelligence":{"sources":service_sources,"coverage_complete":False,"message":"RIPEstat supplies routing prefixes, not a list of active hosts. Counts include only genuinely observed or attributed imported hosts/services."},"announced_networks":{"results":prefixes,"page":prefix_page,"per_page":prefix_per_page,"total":prefix_total,"total_pages":prefix_pages,"has_next":prefix_page<prefix_pages},"passive_metadata":{"results":metadata,"page":metadata_page,"per_page":metadata_per_page,"total":metadata_total,"total_pages":metadata_pages,"has_next":metadata_page<metadata_pages}}
