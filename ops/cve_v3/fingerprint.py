#!/usr/bin/env python3
"""Conservative CPE fingerprint enrichment from existing ScanLattice evidence.

Run in the production web container: docker exec -i CID python - < fingerprint.py
By default read-only; APPLY=1 fills ONLY empty services.cpe after review.
No active probes, port changes, or speculative OS identification.
"""
import json
import os
import re
from app.database import connection

APPLY = os.getenv("APPLY") == "1"
MAX_UPDATES = int(os.getenv("MAX_UPDATES", "50000"))
RULES = (
    (r"\bApache(?:/|(?:\s+httpd)?\s+)(\d+\.\d+(?:\.\d+){1,3})\b",
     ("a", "apache", "http_server")),
    (r"\bnginx/(\d+\.\d+(?:\.\d+){1,3})\b",
     ("a", "nginx", "nginx")),
    (r"\bOpenSSH[_/](\d+\.\d+(?:p\d+)?)\b",
     ("a", "openbsd", "openssh")),
)

def explicit_version(text):
    if not isinstance(text,str) or len(text)>16384: return None
    matches = []
    for pattern, ident in RULES:
        match = re.search(pattern,text,re.IGNORECASE)
        if match:
            matches.append((ident,match.group(1)))
    return matches[0] if len(set(matches)) == 1 else None

def server_header(http_json):
    try:
        doc=json.loads(http_json) if isinstance(http_json,str) else http_json
        if not isinstance(doc,dict):return ""
        headers=doc.get("headers",{})
        if isinstance(headers,dict):
            for k,v in headers.items():
                if str(k).lower()=="server" and isinstance(v,str):
                    return v
        value=doc.get("server")
        return value if isinstance(value,str) else ""
    except (ValueError,TypeError):
        return ""

def fingerprint(service):
    if service.get("cpe"):
        return None
    # Don't infer software from port numbers or generic product labels.
    hints=[service.get("banner") or "",service.get("ssh_id") or "",
           server_header(service.get("http_json") or "{}")]
    identified={candidate for hint in hints if (candidate:=explicit_version(hint))}
    if len(identified)!=1:
        return None
    (part,vendor,product),version=identified.pop()
    if not re.fullmatch(r"\d+(?:\.\d+){1,3}(?:p\d+)?",version):
        return None
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

def main():
    with connection() as db:
        rows=[dict(r) for r in db.execute(
            "SELECT s.id,s.host_ip,s.port,s.proto,s.service,s.product,"
            "s.banner,s.http_json,s.cpe,o.ssh_id FROM services s "
            "LEFT JOIN observations o ON o.id=s.last_observation_id "
            "WHERE s.cpe='' OR s.cpe IS NULL"
        ).fetchall()]
    candidates=[]
    for row in rows:
        result=fingerprint(row)
        if result:candidates.append((row["id"],row["host_ip"],row["port"],result))
    print(f"Unknown-CPE services: {len(rows)}; evidence-backed CPEs: {len(candidates)}")
    if len(candidates)>MAX_UPDATES:
        raise SystemExit("Exceeded MAX_UPDATES; no database changes")
    for _,ip,port,cpe in candidates[:25]:
        print(f"  {ip}:{port} -> {cpe}")
    if not APPLY:
        print("DRY RUN ONLY. Use APPLY=1 to fill empty CPE fields.")
        return
    updated=0
    with connection() as db:
        for sid,_,_,cpe in candidates:
            cur=db.execute("UPDATE services SET cpe=? WHERE id=? AND "
                           "(cpe='' OR cpe IS NULL)",(cpe,sid))
            updated+=cur.rowcount
    print("Applied fingerprints:",updated)

if __name__=="__main__":
    main()
