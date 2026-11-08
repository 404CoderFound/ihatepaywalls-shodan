from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass, field


class QueryError(ValueError):
    pass


KNOWN_FIELDS = {"ip", "asn", "port", "country", "org", "product", "service", "net", "source", "hostname", "domain", "os", "http.title", "http.headers", "ssl.cert.subject.cn", "ssl.cert.issuer.cn", "cpe", "vuln", "before", "after", "has_screenshot"}


@dataclass
class ParsedQuery:
    filters: dict[str, list[str]]
    free: list[str]
    excluded: list[tuple[str | None, str]] = field(default_factory=list)
    alternatives: list[tuple[dict[str, list[str]], list[str]]] = field(default_factory=list)


def parse_query(text: str) -> ParsedQuery:
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise QueryError(f"Invalid query: {exc}") from exc
    groups: list[tuple[dict[str, list[str]], list[str]]] = [({}, [])]
    excluded: list[tuple[str | None, str]] = []
    for token in tokens:
        token=token.strip("()")
        if not token:continue
        if token.upper()=="AND":continue
        if token.upper()=="OR":
            if not groups[-1][0] and not groups[-1][1]:raise QueryError("OR must separate two search expressions")
            groups.append(({},[]));continue
        is_excluded=token.startswith("-") and len(token)>1
        if is_excluded:token=token[1:]
        if ":" not in token:
            if is_excluded:excluded.append((None,token))
            else:groups[-1][1].append(token)
            continue
        key, value = token.split(":", 1)
        key = key.lower()
        if key not in KNOWN_FIELDS:
            raise QueryError(f"Unknown filter: {key}")
        if not value:
            raise QueryError(f"Missing value for {key}")
        if key == "port":
            try:
                port = int(value)
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError as exc:
                raise QueryError("Port must be between 1 and 65535") from exc
        elif key == "ip":
            try: ipaddress.ip_address(value)
            except ValueError as exc: raise QueryError("Invalid IP address") from exc
        elif key == "net":
            try: ipaddress.ip_network(value, strict=False)
            except ValueError as exc: raise QueryError("Invalid CIDR network") from exc
        elif key == "asn":
            number = value.upper().removeprefix("AS")
            if not number.isdigit() or int(number) < 0 or int(number) > 4294967295:
                raise QueryError("Invalid ASN")
            value = f"AS{int(number)}"
        elif key in {"before","after"}:
            from datetime import date
            try:value=date.fromisoformat(value).isoformat()
            except ValueError as exc:raise QueryError(f"{key} must use YYYY-MM-DD") from exc
        elif key=="has_screenshot" and value.lower() not in {"true","false"}:
            raise QueryError("has_screenshot must be true or false")
        if is_excluded:excluded.append((key,value))
        else:groups[-1][0].setdefault(key,[]).append(value)
    if len(groups)>1 and not groups[-1][0] and not groups[-1][1]:raise QueryError("OR must be followed by a search expression")
    primary=groups[0]
    return ParsedQuery(primary[0],primary[1],excluded,groups[1:])


def build_sql(parsed: ParsedQuery) -> tuple[str, list[object], list[ipaddress._BaseNetwork]]:
    wheres: list[str] = []
    params: list[object] = []
    networks = [ipaddress.ip_network(v, strict=False) for v in parsed.filters.get("net", [])]
    for key, values in parsed.filters.items():
        if key == "net": continue
        for value in values:
            if key == "port":
                wheres.append("o.port=?"); params.append(int(value))
            elif key in {"ip", "asn", "country", "source", "service"}:
                wheres.append(f"LOWER(o.{key})=LOWER(?)"); params.append(value)
            elif key in {"hostname", "domain"}:
                wheres.append("LOWER(COALESCE(o.hostname,'')) LIKE ?"); params.append(f"%{value.lower()}%")
            else:
                wheres.append(f"LOWER(o.{key}) LIKE ?"); params.append(f"%{value.lower()}%")
    for token in parsed.free:
        wheres.append("(LOWER(o.banner) LIKE ? OR LOWER(o.product) LIKE ? OR LOWER(o.org) LIKE ? OR LOWER(o.ip) LIKE ? OR LOWER(COALESCE(o.hostname,'')) LIKE ?)")
        params.extend([f"%{token.lower()}%"] * 5)
    return (" WHERE " + " AND ".join(wheres) if wheres else ""), params, networks
