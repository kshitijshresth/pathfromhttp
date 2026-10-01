import json
from pathlib import Path

import pytest

from pathfromhttp.cli import main
from pathfromhttp.reach import TargetError, check_reachability

FIXTURES = Path(__file__).parent / "fixtures"
DIRS = sorted(p for p in FIXTURES.iterdir() if p.is_dir())


@pytest.mark.parametrize("fixture", DIRS, ids=lambda p: p.name)
def test_fixture_verdict_and_path(fixture):
    exp = json.loads((fixture / "expected.json").read_text())
    res = check_reachability(fixture, exp["target"])
    assert res["verdict"] == exp["verdict"]
    assert res["path"] == exp["path"]


def write(tmp_path, files):
    for rel, text in files.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return tmp_path


HDR = "from flask import Flask\napp = Flask(__name__)\n"


def test_unresolved_call_outside_searched_region_does_not_cause_unknown(tmp_path):
    write(tmp_path, {"app.py": HDR + (
        "def vuln():\n    return 1\n"
        "def unused(cb):\n    return cb()\n"
        "@app.route('/x')\ndef index():\n    return 'ok'\n"
    )})
    assert check_reachability(tmp_path, "app.vuln")["verdict"] == "NOT_REACHABLE"


def test_reachable_wins_even_with_unresolved_elsewhere(tmp_path):
    write(tmp_path, {"app.py": HDR + (
        "def vuln():\n    return 1\n"
        "@app.route('/x')\ndef index(cb):\n    cb()\n    return vuln()\n"
    )})
    res = check_reachability(tmp_path, "app.vuln")
    assert res["verdict"] == "REACHABLE"
    assert res["path"] == ["app.index", "app.vuln"]


def test_no_entry_points_is_unknown_not_not_reachable(tmp_path):
    write(tmp_path, {"lib.py": "def vuln():\n    return 1\ndef f():\n    return 2\n"})
    res = check_reachability(tmp_path, "lib.vuln")
    assert res["verdict"] == "UNKNOWN"
    assert "no HTTP entry points" in res["reason"]


def test_target_is_itself_an_entry_point(tmp_path):
    write(tmp_path, {"app.py": HDR + "@app.route('/x')\ndef index():\n    return 1\n"})
    res = check_reachability(tmp_path, "app.index")
    assert res["verdict"] == "REACHABLE"
    assert res["path"] == ["app.index"]


def test_suffix_target_match_and_ambiguity(tmp_path):
    write(tmp_path, {
        "app.py": HDR + "@app.route('/x')\ndef index():\n    return 1\n",
        "a.py": "def vuln():\n    return 1\n",
        "b.py": "def vuln():\n    return 1\n",
        "c.py": "def only_one():\n    return 1\n",
    })
    assert check_reachability(tmp_path, "only_one")["target"] == "c.only_one"
    with pytest.raises(TargetError):
        check_reachability(tmp_path, "vuln")
    with pytest.raises(TargetError):
        check_reachability(tmp_path, "nope")


def test_ambiguous_calls_reported_on_not_reachable(tmp_path):
    write(tmp_path, {"app.py": HDR + (
        "class S:\n    def get(self):\n        return 1\n"
        "def vuln():\n    return 1\n"
        "@app.route('/x')\ndef index(d):\n    return d.get('k')\n"
    )})
    res = check_reachability(tmp_path, "app.vuln")
    assert res["verdict"] == "NOT_REACHABLE"
    assert len(res["ambiguous"]) == 1


def test_cli_exit_codes_and_output(tmp_path, capsys):
    write(tmp_path, {"app.py": HDR + (
        "def vuln():\n    return 1\n"
        "def other():\n    return 1\n"
        "@app.route('/x')\ndef index():\n    return vuln()\n"
    )})
    assert main(["check", str(tmp_path), "--target", "app.vuln"]) == 1
    out = capsys.readouterr().out
    assert "Verdict: REACHABLE" in out and "app.index" in out and "-> app.vuln" in out
    assert main(["check", str(tmp_path), "--target", "app.other"]) == 0
    assert "Verdict: NOT_REACHABLE" in capsys.readouterr().out
    assert main(["check", str(tmp_path), "--target", "missing"]) == 3
    assert main(["check", str(tmp_path / "nope"), "--target", "x"]) == 3


def test_cli_json_output(tmp_path, capsys):
    write(tmp_path, {"app.py": HDR + (
        "def vuln():\n    return 1\n@app.route('/x')\ndef index():\n    return vuln()\n"
    )})
    assert main(["check", str(tmp_path), "--target", "app.vuln", "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "REACHABLE"
    assert data["path"] == ["app.index", "app.vuln"]
    assert data["path_locations"] == ["app.py:6", "app.py:3"]


def test_cli_unknown_exit_code(tmp_path, capsys):
    write(tmp_path, {"app.py": HDR + (
        "def vuln():\n    return 1\n@app.route('/x')\ndef index(cb):\n    return cb()\n"
    )})
    assert main(["check", str(tmp_path), "--target", "app.vuln"]) == 2
    out = capsys.readouterr().out
    assert "Verdict: UNKNOWN" in out and "Unresolved calls" in out
