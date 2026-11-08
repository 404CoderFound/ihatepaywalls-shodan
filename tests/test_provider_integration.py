"""Opt-in live tests. These contact intelligence providers, never target services."""
import os

import pytest

from app.enrichment import RIPEstatProvider


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("RUN_PROVIDER_INTEGRATION") != "1", reason="set RUN_PROVIDER_INTEGRATION=1 to query RIPEstat")
def test_live_ripestat_asn_overview_and_prefixes():
    result=RIPEstatProvider().lookup("asn","AS30925","RIPEstat")
    assert not result.error
    assert any(record["record_type"]=="asn-overview" for record in result.records)
    assert any(record["record_type"]=="announced-prefix" for record in result.records)
