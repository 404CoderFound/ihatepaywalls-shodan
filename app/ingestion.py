"""Bounded-memory parsing and normalization for resumable observation dataset imports."""
from __future__ import annotations

import csv
import gzip
import ipaddress
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def _open_text(path: Path, encoding: str):
    return gzip.open(path, "rt", encoding="utf-8-sig", newline="") if encoding == "gzip" else path.open("r", encoding="utf-8-sig", newline="")


def _json_array_records(handle) -> Iterator[dict[str, Any]]:
    decoder = json.JSONDecoder(); buffer = ""; start = 0; first = True; eof = False; array = False
    while True:
        while start < len(buffer) and buffer[start].isspace(): start += 1
        if first:
            if start == len(buffer) and not eof:
                chunk=handle.read(65536)
                if not chunk:eof=True
                buffer+=chunk;continue
            if start < len(buffer) and buffer[start] == "[": start += 1
            array = start > 0 and buffer[start - 1] == "["
            first=False
        while start < len(buffer) and (buffer[start].isspace() or buffer[start] == ","): start += 1
        if start < len(buffer) and buffer[start] == "]":
            if not array: raise ValueError("Unexpected closing bracket in JSON dataset")
            start += 1
            while True:
                while start < len(buffer) and buffer[start].isspace(): start += 1
                if start < len(buffer): raise ValueError("Unexpected data after JSON array")
                if eof: return
                chunk=handle.read(65536)
                if not chunk: eof=True
                buffer=buffer[start:]+chunk;start=0
                if eof and not buffer.strip(): return
        if start == len(buffer):
            if eof:
                if array: raise ValueError("JSON array is missing its closing bracket")
                return
            chunk=handle.read(65536)
            if not chunk:eof=True
            buffer=buffer[start:]+chunk;start=0;continue
        try:
            item,end=decoder.raw_decode(buffer,start)
        except json.JSONDecodeError as exc:
            if eof: raise ValueError(f"Invalid JSON dataset near character {exc.pos}: {exc.msg}") from exc
            if start > 0: buffer=buffer[start:];start=0
            chunk=handle.read(65536)
            if not chunk:eof=True
            buffer+=chunk;continue
        if not isinstance(item,dict): raise ValueError("JSON dataset entries must be objects")
        yield item
        start=end
        if start > 65536: buffer=buffer[start:];start=0


def iter_dataset_records(path: Path, format_name: str, encoding: str) -> Iterator[dict[str, Any]]:
    with _open_text(path, encoding) as handle:
        if format_name == "csv":
            reader=csv.DictReader(handle)
            if not reader.fieldnames: raise ValueError("CSV header row is required")
            yield from reader
        elif format_name == "jsonl":
            for number,line in enumerate(handle,1):
                if not line.strip():continue
                try:item=json.loads(line)
                except json.JSONDecodeError as exc:raise ValueError(f"Invalid JSONL at input line {number}: {exc.msg}") from exc
                if not isinstance(item,dict):raise ValueError(f"JSONL line {number} must be an object")
                yield item
        elif format_name == "json":
            # JSON arrays are decoded incrementally; object-per-line datasets should select JSONL.
            yield from _json_array_records(handle)
        else:raise ValueError("format must be csv, json or jsonl")


def _hostnames(record: dict[str, Any]) -> list[str]:
    values=record.get("hostnames") or record.get("hostnames_list") or []
    if isinstance(values,str):values=[v.strip() for v in values.replace(";",",").split(",") if v.strip()]
    elif not isinstance(values,(list,tuple)):values=[]
    primary=record.get("hostname") or record.get("host") or record.get("reverse_dns")
    if primary:values=[primary,*values]
    result=[]
    for value in values:
        name=str(value).strip().rstrip(".").lower()
        if 1<=len(name)<=253 and name not in result:result.append(name)
    return result


def _service_rows(record: dict[str, Any]) -> list[dict[str, Any]]:
    children=record.get("data")
    if isinstance(children,list):
        shared={k:v for k,v in record.items() if k not in {"data","ports","services"}}
        return [{**shared,**child} for child in children if isinstance(child,dict)]
    services=record.get("services")
    if isinstance(services,list):
        return [{**{k:v for k,v in record.items() if k!="services"},**(s if isinstance(s,dict) else {"port":s})} for s in services]
    if isinstance(record.get("ports"),list) and not record.get("port"):
        return [{**record,"port":port} for port in record["ports"]]
    return [record]


def normalize_record(record: dict[str, Any], provenance: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return one host identity and zero or more service observations without inventing ports."""
    child_rows=_service_rows(record)
    first=child_rows[0] if child_rows else record
    ip_value=first.get("ip") or first.get("ip_str") or first.get("ip_address") or first.get("address") or record.get("ip") or record.get("ip_str") or record.get("ip_address")
    if ip_value is None:raise ValueError("record has no IP address")
    try:ip=ipaddress.ip_address(str(ip_value).strip())
    except ValueError as exc:raise ValueError(f"invalid IP address: {ip_value}") from exc
    loc=record.get("location") if isinstance(record.get("location"),dict) else {}
    asn_value=first.get("asn") or record.get("asn") or ""
    if asn_value:
        text=str(asn_value).upper().removeprefix("AS")
        if not text.isdigit():raise ValueError(f"invalid ASN: {asn_value}")
        asn_value=f"AS{int(text)}"
    host={"ip":str(ip),"asn":asn_value,"org":str(first.get("org") or first.get("organization") or record.get("org") or record.get("organization") or "")[:160],
          "country":str(first.get("country_code") or first.get("country") or record.get("country_code") or record.get("country") or loc.get("country_code") or "")[:8],
          "hostname":(_hostnames(record) or _hostnames(first) or [""])[0],"hostnames":_hostnames(record) or _hostnames(first),
          "os_name":str(record.get("os") or record.get("os_name") or "")[:160]}
    host_observed=record.get("observed_at") or record.get("timestamp") or record.get("seen_at") or ""
    if host_observed:
        try:
            parsed=datetime.fromisoformat(str(host_observed).replace("Z","+00:00"))
            if parsed.tzinfo is None:parsed=parsed.replace(tzinfo=timezone.utc)
            host_observed=parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError as exc:raise ValueError(f"invalid observation timestamp: {host_observed}") from exc
    host["observed_at"]=host_observed
    out=[]
    for row in child_rows:
        port_value=row.get("port")
        if port_value in (None,""):continue
        try:port=int(port_value)
        except (TypeError,ValueError) as exc:raise ValueError(f"invalid port: {port_value}") from exc
        if not 1<=port<=65535:raise ValueError(f"port outside 1..65535: {port}")
        http=row.get("http") if isinstance(row.get("http"),dict) else {}
        if not http:
            http={k:row[k] for k in ("http_title","http_status","http_server","http_headers") if row.get(k) is not None}
        tls=row.get("tls") if isinstance(row.get("tls"),dict) else row.get("ssl") if isinstance(row.get("ssl"),dict) else {}
        shodan=row.get("_shodan") if isinstance(row.get("_shodan"),dict) else {}
        service=str(row.get("service") or row.get("service_name") or shodan.get("module") or "")[:80]
        product=str(row.get("product") or row.get("software") or "")[:160]
        banner=row.get("banner") or row.get("banner_text") or (row.get("data") if isinstance(row.get("data"),str) else "")
        observed=row.get("observed_at") or row.get("timestamp") or row.get("seen_at") or record.get("observed_at") or record.get("timestamp") or ""
        if observed:
            try:
                parsed=datetime.fromisoformat(str(observed).replace("Z","+00:00"))
                if parsed.tzinfo is None:parsed=parsed.replace(tzinfo=timezone.utc)
                observed=parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
            except ValueError as exc:raise ValueError(f"invalid observation timestamp: {observed}") from exc
        out.append({"ip":str(ip),"port":port,"proto":str(row.get("proto") or row.get("transport") or "tcp").lower(),
                    "hostname":host["hostname"],"asn":asn_value,"org":host["org"],"country":host["country"],
                    "service":service,"product":product,"banner":str(banner or "")[:8192],"source":provenance,
                    "http":http,"tls":tls,"ssh_id":str(row.get("ssh_id") or row.get("ssh_version") or "")[:500],"observed_at":observed,
                    "cpe":str(row.get("cpe") or "")[:500],"os_name":str(row.get("os") or row.get("os_name") or "")[:160]})
    return host,out

