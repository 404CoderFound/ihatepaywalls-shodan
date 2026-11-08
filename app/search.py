from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass


class QueryError(ValueError):
    pass


KNOWN_FIELDS = {"ip", "asn", "port", "country", "org", "product", "service", "net", "source", "hostname", "domain"}


@dataclass
class ParsedQuery:
    filters: dict[str, list[str]]
    free: list[str]


def parse_query(text: str) -> ParsedQuery:
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise QueryError(f"Invalid query: {exc}") from exc
    filters: dict[str, list[str]] = {}
    free: list[str] = []
    for token in tokens:
        if ":" not in token:
            free.append(token)
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
        filters.setdefault(key, []).append(value)
    return ParsedQuery(filters, free)


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
