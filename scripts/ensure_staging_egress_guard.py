#!/usr/bin/env python3
"""Install-if-absent and verify the dedicated ScanLattice staging nft guard.

The helper never edits Docker's chains, shared nftables tables, or any other
host firewall rules. If the named table already exists, it verifies the exact
expected policy and fails closed on any difference.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

TABLE = "scanlattice_v2_staging"
BRIDGE = "slv2stage0"
PRIVATE_BRIDGE = "slv2priv0"
POLICY = Path("/etc/scanlattice-v2-staging/egress-guard.nft")


class GuardError(RuntimeError):
    pass


def _normal(value: Any) -> Any:
    if isinstance(value, dict) and set(value) == {"string"}:
        return value["string"]
    return value


def verify_policy(payload: dict[str, Any]) -> None:
    entries = payload.get("nftables")
    if not isinstance(entries, list):
        raise GuardError("nft returned an invalid JSON ruleset")
    chains: dict[str, dict[str, Any]] = {}
    rules: dict[str, list[dict[str, Any]]] = {"input_guard": [], "forward_guard": []}
    table_rule_count = 0
    for entry in entries:
        chain = entry.get("chain")
        if chain and chain.get("family") == "inet" and chain.get("table") == TABLE:
            chains[chain.get("name", "")] = chain
        rule = entry.get("rule")
        if rule and rule.get("family") == "inet" and rule.get("table") == TABLE:
            table_rule_count += 1
            name = rule.get("chain")
            if name in rules:
                rules[name].append(rule)

    for name in ("input_guard", "forward_guard"):
        chain = chains.get(name)
        if not chain or chain.get("type") != "filter" or chain.get("hook") != ("input" if name == "input_guard" else "forward"):
            raise GuardError(f"missing or invalid {name} base chain")
        if chain.get("policy") != "accept":
            raise GuardError(f"unexpected {name} chain policy")
        if chain.get("prio") != -5:
            raise GuardError(f"unexpected {name} chain priority")
        if len(rules[name]) != 2:
            raise GuardError(f"expected exactly two scoped rules in {name}")
    if set(chains) != {"input_guard", "forward_guard"} or table_rule_count != 4:
        raise GuardError("staging firewall table contains unexpected chains or rules")

    def matches(rule: dict[str, Any]) -> set[tuple[str, str, Any]]:
        found: set[tuple[str, str, Any]] = set()
        drops = 0
        verdicts = 0
        match_count = 0
        for expr in rule.get("expr", []):
            if any(key in expr for key in ("drop", "accept", "reject", "jump", "goto", "return")):
                verdicts += 1
            if "drop" in expr:
                drops += 1
            match = expr.get("match")
            if not match:
                continue
            match_count += 1
            left = match.get("left", {})
            meta_key = (left.get("meta") or {}).get("key")
            if meta_key:
                found.add((meta_key, match.get("op", ""), _normal(match.get("right"))))
        if drops != 1 or verdicts != 1:
            raise GuardError("each staging firewall rule must have exactly one drop verdict")
        if match_count != len(found):
            raise GuardError("staging firewall rule contains an unexpected match expression")
        return found

    expected = {
        "input_guard": {
            frozenset({("iifname", "==", BRIDGE)}),
            frozenset({("iifname", "==", PRIVATE_BRIDGE)}),
        },
        "forward_guard": {
            frozenset({("iifname", "==", BRIDGE), ("oifname", "!=", BRIDGE)}),
            frozenset({("iifname", "==", PRIVATE_BRIDGE), ("oifname", "!=", PRIVATE_BRIDGE)}),
        },
    }
    for name in ("input_guard", "forward_guard"):
        actual = {frozenset(matches(rule)) for rule in rules[name]}
        if actual != expected[name]:
            raise GuardError(f"{name} host/egress rules do not exactly cover both staging bridges")


def nft_json(*args: str, check: bool = True) -> dict[str, Any] | None:
    result = subprocess.run(["/usr/sbin/nft", *args], text=True, capture_output=True, check=False)
    if check and result.returncode:
        raise GuardError("nft command failed; firewall state was not changed")
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise GuardError("nft returned invalid JSON") from exc


def ensure(policy: Path = POLICY) -> None:
    current = nft_json("-j", "list", "table", "inet", TABLE, check=False)
    if current is None:
        if not policy.is_file():
            raise GuardError(f"firewall policy file does not exist: {policy}")
        subprocess.run(["/usr/sbin/nft", "-c", "-f", str(policy)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        subprocess.run(["/usr/sbin/nft", "-f", str(policy)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    verified = nft_json("-j", "list", "table", "inet", TABLE)
    assert verified is not None
    verify_policy(verified)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ensure", action="store_true", help="add the table only if absent, then verify")
    parser.add_argument("--check", action="store_true", help="verify an existing table without changing rules")
    parser.add_argument("--policy-file", type=Path, default=POLICY, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.ensure == args.check:
        parser.error("select exactly one of --ensure or --check")
    try:
        if args.ensure:
            ensure(args.policy_file)
        else:
            result = nft_json("-j", "list", "table", "inet", TABLE)
            assert result is not None
            verify_policy(result)
    except (GuardError, subprocess.CalledProcessError) as exc:
        detail = str(exc) if isinstance(exc, GuardError) else "nftables rejected the staging policy"
        print(f"NO-GO: {detail}", file=sys.stderr)
        return 1
    print("PASS: dedicated staging host-input and egress-drop rules verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
