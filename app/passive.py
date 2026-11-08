from __future__ import annotations

import ipaddress
import json
import time
import urllib.error
import urllib.request
from typing import Any

from .search import ParsedQuery

APPROVED_RDAP_BASES = {"https://rdap.org/", "https://rdap.org/ip/", "https://rdap.db.ripe.net/ip/"}


def _contains(network: str, address: str) -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def _network_matches(query: str, row: dict[str, Any]) -> bool:
    try:
        wanted = ipaddress.ip_network(query, strict=False)
        if row["ip"] and ipaddress.ip_address(row["ip"]) in wanted:
            return True
        if row["network"]:
            candidate = ipaddress.ip_network(row["network"], strict=False)
            return candidate.subnet_of(wanted) or wanted.subnet_of(candidate)
    except ValueError:
        pass
    return False


def _matches(row: dict[str, Any], parsed: ParsedQuery) -> bool:
    filters = parsed.filters
    for key, values in filters.items():
        if key in {"port", "product", "service", "country"}:
            return False  # Passive records never imply an observed service.
        for value in values:
            if key == "net":
                if not _network_matches(value, row):
                    return False
            elif key == "ip" and row["ip"].lower() != value.lower():
                return False
            elif key == "domain" and value.lower() not in row["domain"].lower():
                return False
            elif key == "hostname" and value.lower() not in row["domain"].lower():
                return False
            elif key in {"asn", "source"} and row[key].lower() != value.lower():
                return False
            elif key == "org" and value.lower() not in row["org"].lower():
                return False
    haystack = " ".join(str(row.get(k, "")) for k in ("subject", "ip", "domain", "asn", "org", "network", "record_type", "value_json", "source")).lower()
    return all(token.lower() in haystack for token in parsed.free)


def search_cached(db, parsed: ParsedQuery) -> list[dict[str, Any]]:
    now = int(time.time())
    rows = [dict(row) for row in db.execute(
        "SELECT * FROM passive_records WHERE expires_at IS NULL OR expires_at>? ORDER BY observed_at DESC,id DESC",
        (now,),
    )]
    results = [row for row in rows if _matches(row, parsed)]
    for row in results:
        row["value"] = json.loads(row.pop("value_json"))
    return results


def enrich_from_approved_provider(db, parsed: ParsedQuery) -> dict[str, Any]:
    """Fetch exact-IP RDAP metadata only from a fixed registry endpoint allowlist."""
    values = parsed.filters.get("ip", [])
    if len(values) != 1:
        return {"live_lookup_attempted": False, "message": "Live enrichment requires one exact IP filter"}
    ip = str(ipaddress.ip_address(values[0]))
    now = int(time.time())
    providers = db.execute("SELECT * FROM passive_providers WHERE enabled=1 AND provider_type='rdap' ORDER BY id").fetchall()
    for provider in providers:
        config = json.loads(provider["config_json"])
        base = config.get("base_url", "https://rdap.org/ip/")
        if base not in APPROVED_RDAP_BASES:
            continue
        if db.execute("SELECT 1 FROM passive_negative_cache WHERE provider_id=? AND subject=? AND expires_at>?", (provider["id"], ip, now)).fetchone():
            continue
        window = now // 60
        usage = db.execute("SELECT request_count FROM passive_provider_usage WHERE provider_id=? AND window_start=?", (provider["id"], window)).fetchone()
        if usage and usage[0] >= provider["requests_per_minute"]:
            return {"live_lookup_attempted": False, "message": "Passive provider quota reached"}
        db.execute("INSERT INTO passive_provider_usage(provider_id,window_start,request_count) VALUES(?,?,1) ON CONFLICT(provider_id,window_start) DO UPDATE SET request_count=request_count+1", (provider["id"], window))
        request = urllib.request.Request(base + ip, headers={"Accept": "application/rdap+json", "User-Agent": "ScanLattice/0.2 passive-cache"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read(262144))
            network = ""
            if payload.get("startAddress") and payload.get("endAddress"):
                networks = ipaddress.summarize_address_range(ipaddress.ip_address(payload["startAddress"]), ipaddress.ip_address(payload["endAddress"]))
                network = str(next(networks))
            value = {key: payload[key] for key in ("handle", "name", "type", "country", "startAddress", "endAddress") if key in payload}
            db.execute("""INSERT INTO passive_records(subject,subject_type,ip,asn,org,network,record_type,value_json,source,observed_at,expires_at,provider_id)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(subject,record_type,source,value_json) DO UPDATE SET observed_at=excluded.observed_at,expires_at=excluded.expires_at""",
              (ip,"ip",ip,"",str(payload.get("name", ""))[:200],network,"rdap",json.dumps(value,sort_keys=True),provider["name"],time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(now)),now+86400,provider["id"]))
            return {"live_lookup_attempted": True, "provider": provider["name"], "message": "Approved RDAP provider result cached"}
        except (OSError, ValueError, KeyError, urllib.error.URLError):
            db.execute("INSERT INTO passive_negative_cache(provider_id,subject,expires_at) VALUES(?,?,?) ON CONFLICT(provider_id,subject) DO UPDATE SET expires_at=excluded.expires_at", (provider["id"], ip, now+300))
            return {"live_lookup_attempted": True, "provider": provider["name"], "message": "Provider returned no usable result"}
    return {"live_lookup_attempted": False, "message": "No approved live passive provider configured"}


def provider_status(db) -> dict[str, Any]:
    enabled = db.execute("SELECT COUNT(*) FROM passive_providers WHERE enabled=1").fetchone()[0]
    return {
        "live_lookup_attempted": False,
        "enabled_providers": enabled,
        "message": "Cached passive intelligence only" if enabled else "No live passive providers configured",
    }
