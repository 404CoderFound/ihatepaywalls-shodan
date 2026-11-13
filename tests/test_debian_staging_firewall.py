from pathlib import Path

import pytest

from scripts.ensure_staging_egress_guard import GuardError, verify_policy


ROOT = Path(__file__).parents[1]


def _match(key, op, value):
    return {"match": {"op": op, "left": {"meta": {"key": key}}, "right": {"string": value}}}


def _policy_payload():
    return {"nftables": [
        {"chain": {"family": "inet", "table": "scanlattice_v2_staging", "name": "input_guard",
                   "type": "filter", "hook": "input", "prio": -5, "policy": "accept"}},
        {"chain": {"family": "inet", "table": "scanlattice_v2_staging", "name": "forward_guard",
                   "type": "filter", "hook": "forward", "prio": -5, "policy": "accept"}},
        {"rule": {"family": "inet", "table": "scanlattice_v2_staging", "chain": "input_guard",
                   "expr": [_match("iifname", "==", "slv2stage0"), {"drop": None}]}},
        {"rule": {"family": "inet", "table": "scanlattice_v2_staging", "chain": "input_guard",
                   "expr": [_match("iifname", "==", "slv2priv0"), {"drop": None}]}},
        {"rule": {"family": "inet", "table": "scanlattice_v2_staging", "chain": "forward_guard",
                   "expr": [_match("iifname", "==", "slv2stage0"), _match("oifname", "!=", "slv2stage0"),
                            {"drop": None}]}},
        {"rule": {"family": "inet", "table": "scanlattice_v2_staging", "chain": "forward_guard",
                   "expr": [_match("iifname", "==", "slv2priv0"), _match("oifname", "!=", "slv2priv0"),
                            {"drop": None}]}},
    ]}


def test_staging_firewall_verifies_only_the_expected_scoped_drop_rules():
    verify_policy(_policy_payload())
    payload = _policy_payload()
    payload["nftables"][-1]["rule"]["expr"][0]["match"]["right"] = {"string": "web_default"}
    with pytest.raises(GuardError, match="egress"):
        verify_policy(payload)


def test_staging_firewall_refuses_extra_or_missing_rules():
    payload = _policy_payload()
    payload["nftables"].append(payload["nftables"][-1])
    with pytest.raises(GuardError, match="exactly two"):
        verify_policy(payload)
    with pytest.raises(GuardError, match="invalid JSON"):
        verify_policy({})
    payload = _policy_payload()
    payload["nftables"].append({"chain": {"family": "inet", "table": "scanlattice_v2_staging",
                                           "name": "foreign", "type": "filter", "hook": "input",
                                           "prio": -5, "policy": "accept"}})
    with pytest.raises(GuardError, match="unexpected chains"):
        verify_policy(payload)
    payload = _policy_payload()
    del payload["nftables"][3]
    with pytest.raises(GuardError, match="exactly two"):
        verify_policy(payload)
    payload = _policy_payload()
    payload["nftables"][2]["rule"]["expr"].insert(0, {"match": {
        "op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
        "right": {"prefix": {"addr": "192.0.2.0", "len": 24}},
    }})
    with pytest.raises(GuardError, match="unexpected match expression"):
        verify_policy(payload)


def test_compose_pins_stable_bridge_for_persistent_host_firewall():
    compose = (ROOT / "deploy" / "compose.debian-v2-staging.yaml").read_text()
    nft = (ROOT / "deploy" / "scanlattice-v2-staging-egress.nft").read_text()
    unit = (ROOT / "deploy" / "scanlattice-v2-staging-egress.service").read_text()
    assert 'com.docker.network.bridge.name: "slv2stage0"' in compose
    assert 'com.docker.network.bridge.name: "slv2priv0"' in compose
    assert 'iifname "slv2stage0" oifname != "slv2stage0" counter drop' in nft
    assert 'iifname "slv2stage0" counter drop' in nft
    assert 'iifname "slv2priv0" counter drop' in nft
    assert "PartOf=nftables.service" in unit
    assert "After=nftables.service docker.service" in unit


def test_runbook_creates_network_and_verifies_guard_before_any_startup():
    runbook = (ROOT / "deploy" / "DEBIAN_V2_STAGING_RUNBOOK.md").read_text()
    prepare = runbook.index("create --no-build --no-recreate postgres web",
                            runbook.index("## Prepare isolated networks"))
    guard_install = runbook.index("sudo systemctl enable --now", prepare)
    guard_check = runbook.index("--check", guard_install)
    start = runbook.index("## Start isolated staging")
    app_start = runbook.index(" up -d --no-recreate postgres web", start)
    assert prepare < guard_install < guard_check < start < app_start
    assert "Install the repository's dedicated nftables table and systemd unit." in runbook
    assert "it does not start PostgreSQL" in runbook
