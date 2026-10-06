import json
from pathlib import Path

import pytest

from pathfromhttp.reach import check_reachability

FIXTURES = Path(__file__).parent / "fixtures_fastapi"
DIRS = sorted(p for p in FIXTURES.iterdir() if p.is_dir())


@pytest.mark.parametrize("fixture", DIRS, ids=lambda p: p.name)
def test_fastapi_fixture(fixture):
    exp = json.loads((fixture / "expected.json").read_text())
    res = check_reachability(fixture, exp["target"])
    assert res["entry_points"] == sorted(exp["entry_points"])
    assert res["verdict"] == exp["verdict"]
    assert res["path"] == exp["path"]