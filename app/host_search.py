from __future__ import annotations

import ipaddress
import json
import math
import sqlite3
from typing import Any

from .search import ParsedQuery

PER_PAGE = 10


def _where(parsed: ParsedQuery) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    for key, values in parsed.filters.items():
        for value in values:
            if key == "ip": clauses.append("h.ip=?");params.append(value)
            elif key == "asn": clauses.append("UPPER(h.asn)=?");params.append(value.upper())
            elif key == "country": clauses.append("UPPER(h.country)=?");params.append(value.upper())
            elif key == "org": clauses.append("LOWER(h.org) LIKE ?");params.append(f"%{value.lower()}%")
            elif key in {"hostname","domain"}:
                clauses.append("(LOWER(h.hostname) LIKE ? OR EXISTS(SELECT 1 FROM hostnames hn WHERE hn.ip=h.ip AND LOWER(hn.hostname) LIKE ?))");params.extend([f"%{value.lower()}%"]*2)
            elif key == "port": clauses.append("EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND s.port=?)");params.append(int(value))
            elif key == "service": clauses.append("EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND LOWER(s.service)=LOWER(?))");params.append(value)
            elif key == "product": clauses.append("EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND LOWER(s.product) LIKE ?)");params.append(f"%{value.lower()}%")
            elif key == "source": clauses.append("(LOWER(h.source)=LOWER(?) OR EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND LOWER(s.source)=LOWER(?)))");params.extend([value,value])
            elif key == "net":
                network=ipaddress.ip_network(value,strict=False);start=f"{int(network.network_address):032x}";end=f"{int(network.broadcast_address):032x}"
                clauses.append("h.ip_version=? AND h.ip_hex BETWEEN ? AND ?");params.extend([network.version,start,end])
    for token in parsed.free:
        like=f"%{token.lower()}%";clauses.append("(LOWER(h.ip) LIKE ? OR LOWER(h.hostname) LIKE ? OR LOWER(h.org) LIKE ? OR EXISTS(SELECT 1 FROM services s WHERE s.host_ip=h.ip AND (LOWER(s.service) LIKE ? OR LOWER(s.product) LIKE ? OR LOWER(s.banner) LIKE ?)))");params.extend([like]*6)
    return (" WHERE "+" AND ".join(f"({clause})" for clause in clauses) if clauses else ""),params


def search_hosts(db: sqlite3.Connection, parsed: ParsedQuery, page: int) -> dict[str, Any]:
    where,params=_where(parsed);total=db.execute("SELECT COUNT(*) FROM hosts h"+where,params).fetchone()[0]
    total_pages=math.ceil(total/PER_PAGE) if total else 0;page=min(page,total_pages) if total_pages else 1;offset=(page-1)*PER_PAGE
    rows=[dict(row) for row in db.execute("SELECT h.* FROM hosts h"+where+" ORDER BY h.last_seen DESC,h.ip_version,h.ip_hex,h.ip LIMIT ? OFFSET ?",params+[PER_PAGE,offset])]
    for host in rows:
        services=[]
        for row in db.execute("SELECT port,proto,service,product,banner,http_json,tls_json,source,last_seen FROM services WHERE host_ip=? ORDER BY port,proto",(host["ip"],)):
            service=dict(row);service["http"]=json.loads(service.pop("http_json") or "{}");service["tls"]=json.loads(service.pop("tls_json") or "{}");services.append(service)
        host["services"]=services
        host["hostnames"]=[dict(row) for row in db.execute("SELECT hostname,source,last_seen FROM hostnames WHERE ip=? ORDER BY last_seen DESC,hostname",(host["ip"],))]
    start=offset+1 if total else 0;end=min(offset+PER_PAGE,total)
    return {"hosts":rows,"page":page,"per_page":PER_PAGE,"total":total,"total_pages":total_pages,"has_next":page<total_pages,"has_previous":page>1,"range_start":start,"range_end":end}


def asn_intelligence(db: sqlite3.Connection, asn: str, prefix_page: int = 1, metadata_page: int = 1) -> dict[str, Any]:
    prefix_per_page=25;metadata_per_page=25
    overview_row=db.execute("SELECT * FROM passive_records WHERE asn=? AND record_type='asn-overview' ORDER BY observed_at DESC LIMIT 1",(asn,)).fetchone()
    stats_row=db.execute("SELECT * FROM passive_records WHERE asn=? AND record_type='prefix-statistics' ORDER BY observed_at DESC LIMIT 1",(asn,)).fetchone()
    organization=(overview_row["org"] if overview_row else "") or db.execute("SELECT COALESCE(MAX(org),'') FROM hosts WHERE asn=?",(asn,)).fetchone()[0]
    prefix_total=db.execute("SELECT COUNT(DISTINCT prefix) FROM routing_prefixes WHERE asn=?",(asn,)).fetchone()[0]
    prefix_pages=math.ceil(prefix_total/prefix_per_page) if prefix_total else 0;prefix_page=max(1,min(prefix_page,prefix_pages or 1))
    prefixes=[dict(row) for row in db.execute("SELECT prefix,organization,source,last_seen FROM routing_prefixes WHERE asn=? GROUP BY prefix ORDER BY CASE WHEN instr(prefix,':')=0 THEN 4 ELSE 6 END,prefix LIMIT ? OFFSET ?",(asn,prefix_per_page,(prefix_page-1)*prefix_per_page))]
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
