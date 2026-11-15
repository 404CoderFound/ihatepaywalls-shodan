"""Conservative NVD 2.0 configuration evaluator for ScanLattice.

Evaluates the entire AND/OR/negate tree. Unknown inventory is NOT treated as
an absent or vulnerable product. Results are only version-exposure signals,
not verified vulnerabilities or exploitability claims.
"""
import re
from enum import IntEnum

class Truth(IntEnum):
    UNKNOWN = -1
    FALSE = 0
    TRUE = 1

def all_of(values):
    values = list(values)
    if not values:
        return Truth.UNKNOWN
    if Truth.FALSE in values:
        return Truth.FALSE
    return Truth.UNKNOWN if Truth.UNKNOWN in values else Truth.TRUE

def any_of(values):
    values = list(values)
    if not values:
        return Truth.UNKNOWN
    if Truth.TRUE in values:
        return Truth.TRUE
    return Truth.UNKNOWN if Truth.UNKNOWN in values else Truth.FALSE

def split_cpe(cpe):
    """Split CPE 2.3 respecting escaped colons; return 11 CPE fields."""
    if not isinstance(cpe, str) or not cpe.startswith("cpe:2.3:"):
        return None
    fields, part, escaped = [], "", False
    for char in cpe[8:]:
        if escaped:
            part += char
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append(part)
            part = ""
        else:
            part += char
    fields.append(part)
    return fields if len(fields) == 11 else None

def key(cpe):
    fields = split_cpe(cpe)
    if not fields or any(v in ("", "-", "*", "?") for v in fields[:3]):
        return None
    return ":".join(x.lower() for x in fields[:3])

def _version(value):
    """Only order numeric-dot and OpenSSH pN versions; fail closed otherwise."""
    match = re.fullmatch(r"(\d+(?:\.\d+){0,10})(?:p(\d+))?", str(value).lower())
    if not match:
        return None
    values = [int(x) for x in match.group(1).split(".")]
    # Padding places an OpenSSH p suffix beyond the numeric release.
    values += [0] * (11 - len(values))
    values.append(int(match.group(2)) if match.group(2) else 0)
    return tuple(values)

def _scalar(observed, expected):
    if expected == "*":
        return Truth.TRUE
    if expected in ("", "?"):
        return Truth.UNKNOWN
    if observed in ("", "*", "?"):
        return Truth.UNKNOWN
    return Truth.TRUE if observed.lower() == expected.lower() else Truth.FALSE

def criterion(criterion, observations):
    """Return 3-state presence of one NVD criterion on a host.

    NVD vulnerable:false is an environment condition, NOT negation.
    """
    fields = split_cpe(criterion.get("criteria"))
    if not fields or any(v in ("", "-", "*", "?") for v in fields[:3]):
        return Truth.UNKNOWN
    host_product = ":".join(x.lower() for x in fields[:3])
    related = [split_cpe(x) for x in observations if key(x) == host_product]
    if not related:
        return Truth.UNKNOWN
    candidates = []
    for seen in related:
        if not seen:
            continue
        checks = []
        for index, expected in enumerate(fields):
            if index == 3 and any(criterion.get(name) for name in
                    ("versionStartIncluding","versionStartExcluding",
                     "versionEndIncluding","versionEndExcluding")):
                checks.append(_scalar(seen[index], expected))
            else:
                checks.append(_scalar(seen[index], expected))
        # Exact observed CPE field comparisons are necessary for target_sw,
        # edition and other constraints, not merely part/vendor/product/version.
        for name, sign in (("versionStartIncluding", ">="),
                           ("versionStartExcluding", ">"),
                           ("versionEndIncluding", "<="),
                           ("versionEndExcluding", "<")):
            bound = criterion.get(name)
            if bound is None:
                continue
            a, b = _version(seen[3]), _version(bound)
            if a is None or b is None:
                checks.append(Truth.UNKNOWN)
            else:
                checks.append(Truth.TRUE if {
                    ">=": a >= b, ">": a > b, "<=": a <= b, "<": a < b
                }[sign] else Truth.FALSE)
        candidates.append(all_of(checks))
    return any_of(candidates)

def node_result(node, observations):
    if not isinstance(node, dict):
        return Truth.UNKNOWN
    items = [criterion(c, observations) for c in node.get("cpeMatch", [])
             if isinstance(c, dict)]
    children = node.get("children", []) or node.get("nodes", []) or []
    items += [node_result(n, observations) for n in children]
    result = all_of(items) if node.get("operator", "OR").upper() == "AND" \
        else any_of(items)
    if node.get("negate"):
        return {Truth.TRUE: Truth.FALSE, Truth.FALSE: Truth.TRUE,
                Truth.UNKNOWN: Truth.UNKNOWN}[result]
    return result

def _vulnerable_leaves(data):
    if isinstance(data, list):
        for x in data:
            yield from _vulnerable_leaves(x)
    elif isinstance(data, dict):
        for item in data.get("cpeMatch", []) or []:
            if isinstance(item, dict) and item.get("vulnerable") is True:
                yield item
        for field in ("nodes", "children"):
            yield from _vulnerable_leaves(data.get(field, []) or [])

def assess(configurations, observations):
    """None, needs_evidence or potential; never returns 'confirmed vulnerable'."""
    supported = [c for c in _vulnerable_leaves(configurations)
                 if criterion(c, observations) == Truth.TRUE]
    if not supported:
        return None
    configs = configurations if isinstance(configurations, list) else [configurations]
    overall = any_of(any_of(node_result(n, observations)
                   for n in cfg.get("nodes", [])) for cfg in configs if isinstance(cfg, dict))
    if overall == Truth.TRUE:
        return "potential"
    if overall == Truth.UNKNOWN:
        return "needs_evidence"
    return None

def candidates(configurations):
    return {k for c in _vulnerable_leaves(configurations)
            if (k := key(c.get("criteria"))) is not None}
