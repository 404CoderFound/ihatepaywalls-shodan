from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "script",
    ["validate_staging.sh", "validate_postgresql_staging.sh"],
)
def test_staging_validation_removes_project_volume_by_default(script):
    path = Path(__file__).parents[1] / "scripts" / script
    source = path.read_text()
    cleanup = source.split("cleanup() {", 1)[1].split("\n}", 1)[0]

    assert 'KEEP_STAGING:-false' in cleanup
    assert "compose down --volumes" in cleanup
