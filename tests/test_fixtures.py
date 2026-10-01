import ast
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
VERDICTS = {"REACHABLE", "NOT_REACHABLE", "UNKNOWN"}
DIRS = sorted(p for p in FIXTURES.iterdir() if p.is_dir())


def defined_functions(py_file):
    tree = ast.parse(py_file.read_text())
    return {
        n.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def check_qname(fixture, qname):
    parts = qname.split(".")
    py = fixture / (parts[0] + ".py")
    assert py.exists(), f"{qname}: missing file {py.name}"
    assert parts[-1] in defined_functions(py), f"{qname}: function not defined"


def test_fixture_count():
    assert len(DIRS) == 8


@pytest.mark.parametrize("fixture", DIRS, ids=lambda p: p.name)
def test_fixture(fixture):
    for py in fixture.glob("*.py"):
        ast.parse(py.read_text())
    exp = json.loads((fixture / "expected.json").read_text())
    assert set(exp) == {"target", "entry_points", "verdict", "path"}
    assert exp["verdict"] in VERDICTS
    check_qname(fixture, exp["target"])
    assert exp["entry_points"]
    for ep in exp["entry_points"]:
        check_qname(fixture, ep)
    if exp["verdict"] == "REACHABLE":
        assert exp["path"][0] in exp["entry_points"]
        assert exp["path"][-1] == exp["target"]
        for q in exp["path"]:
            check_qname(fixture, q)
    else:
        assert exp["path"] is None
