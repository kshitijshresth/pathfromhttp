import json
from pathlib import Path
import pytest
from pathfromhttp.triage import triage, SarifError, render_triage_text
from pathfromhttp.cli import main

FIXTURES = Path(__file__).parent


def write_sarif(tmp_path, results):
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "test"}},
                "results": results
            }
        ]
    }
    sarif_path = tmp_path / "findings.sarif"
    sarif_path.write_text(json.dumps(sarif))
    return sarif_path


def test_basic_fixture_matches_expected():
    result = triage(FIXTURES / "fixtures_triage" / "basic", FIXTURES / "fixtures_triage" / "basic" / "findings.sarif")
    with open(FIXTURES / "fixtures_triage" / "basic" / "expected.json") as f:
        expected = json.load(f)
    for r, e in zip(result["results"], expected["results"]):
        assert r["rule_id"] == e["rule_id"]
        assert r["file"] == e["file"]
        assert r["line"] == e["line"]
        assert r["function"] == e["function"]
        assert r["verdict"] == e["verdict"]
        assert r["path"] == e["path"]
    assert result["summary"] == expected["summary"]
    likely = [r for r in result["results"] if r["verdict"] == "LIKELY_REACHABLE"][0]
    assert likely["approx_hops"] == [["app.export", "reports.Report.render"]]
    assert len(likely["path_locations"]) == 2
    first = result["results"][0]
    assert first["path_locations"] == ["app.py:11", "db.py:1"]


def test_dynamic_fixture_is_unknown():
    result = triage(FIXTURES / "fixtures_triage" / "dynamic", FIXTURES / "fixtures_triage" / "dynamic" / "findings.sarif")
    with open(FIXTURES / "fixtures_triage" / "dynamic" / "expected.json") as f:
        expected = json.load(f)
    assert result["results"][0]["rule_id"] == expected["results"][0]["rule_id"]
    assert result["results"][0]["file"] == expected["results"][0]["file"]
    assert result["results"][0]["line"] == expected["results"][0]["line"]
    assert result["results"][0]["function"] == expected["results"][0]["function"]
    assert result["results"][0]["verdict"] == expected["results"][0]["verdict"]
    assert "could not be resolved" in result["results"][0]["reason"]
    assert result["unresolved"] == [{"function": "app.run", "location": "app.py:11", "call": "fn"}]


def test_uri_forms_all_locate_the_same_function(tmp_path):
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef index():\n    return 1\n")
    sub = tmp_path / "sub dir"
    sub.mkdir()
    (sub / "views.py").write_text("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef index():\n    return 1\n")
    results = [
        {"ruleId": "r1", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 6}}}]},
        {"ruleId": "r2", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "./app.py"}, "region": {"startLine": 6}}}]},
        {"ruleId": "r3", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 6}}}]},
        {"ruleId": "r4", "locations": [{"physicalLocation": {"artifactLocation": {"uri": (tmp_path / "app.py").as_uri()}, "region": {"startLine": 6}}}]},
        {"ruleId": "r5", "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(tmp_path / "app.py")}, "region": {"startLine": 6}}}]},
        {"ruleId": "r6", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "sub%20dir/views.py"}, "region": {"startLine": 6}}}]},
    ]
    sarif_path = write_sarif(tmp_path, results)
    result = triage(tmp_path, sarif_path)
    assert result["results"][0]["function"] == "app.index"
    assert result["results"][0]["verdict"] == "REACHABLE"
    assert result["results"][0]["path"] == ["app.index"]
    assert result["results"][1]["function"] == "app.index"
    assert result["results"][1]["verdict"] == "REACHABLE"
    assert result["results"][1]["path"] == ["app.index"]
    assert result["results"][2]["function"] == "app.index"
    assert result["results"][2]["verdict"] == "REACHABLE"
    assert result["results"][2]["path"] == ["app.index"]
    assert result["results"][3]["function"] == "app.index"
    assert result["results"][3]["verdict"] == "REACHABLE"
    assert result["results"][3]["path"] == ["app.index"]
    assert result["results"][4]["function"] == "app.index"
    assert result["results"][4]["verdict"] == "REACHABLE"
    assert result["results"][4]["path"] == ["app.index"]
    assert result["results"][5]["function"] == "sub dir.views.index"
    assert result["results"][5]["verdict"] == "REACHABLE"


def test_result_without_usable_location_is_unlocated(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    return 1\n")
    results = [
        {"ruleId": "r1"},
        {"ruleId": "r2", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}]},
        {"ruleId": "r3", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 0}}}]},
        {"ruleId": "r4", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "missing.py"}, "region": {"startLine": 1}}}]},
    ]
    sarif_path = write_sarif(tmp_path, results)
    result = triage(tmp_path, sarif_path)
    for i in range(3):
        assert result["results"][i]["verdict"] == "UNLOCATED"
        assert result["results"][i]["reason"] == "no usable location in the result"
        assert result["results"][i]["function"] is None
    assert result["results"][3]["verdict"] == "UNLOCATED"
    assert result["results"][3]["reason"] == "no analyzed function contains this location"
    assert result["results"][3]["function"] is None


def test_multiple_runs_and_order_preserved(tmp_path):
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef index():\n    return 1\n")
    (tmp_path / "helpers.py").write_text("def helper():\n    return 1\n")
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "test"}},
                "results": [
                    {"ruleId": "r1", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "helpers.py"}, "region": {"startLine": 2}}}]},
                    {"ruleId": "r2", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 6}}}]},
                ]
            },
            {
                "tool": {"driver": {"name": "test"}},
                "results": [
                    {"ruleId": "r3", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 6}}}]},
                ]
            },
            {}
        ]
    }
    sarif_path = tmp_path / "findings.sarif"
    sarif_path.write_text(json.dumps(sarif))
    result = triage(tmp_path, sarif_path)
    assert [r["rule_id"] for r in result["results"]] == ["r1", "r2", "r3"]
    assert result["results"][0]["verdict"] == "NOT_REACHABLE"
    assert result["results"][1]["verdict"] == "REACHABLE"
    assert result["results"][2]["verdict"] == "REACHABLE"


def test_rule_id_fallbacks(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    return 1\n")
    results = [
        {"ruleId": "a/b", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 1}}}]},
        {"rule": {"id": "from-rule"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 1}}}]},
        {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 1}}}]},
        {"ruleId": "", "rule": {"id": "x"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 1}}}]},
    ]
    sarif_path = write_sarif(tmp_path, results)
    result = triage(tmp_path, sarif_path)
    assert [r["rule_id"] for r in result["results"]] == ["a/b", "from-rule", "unknown", "x"]
    assert result["results"][0]["message"] == ""
    assert result["results"][0]["level"] == "warning"


def test_invalid_inputs_raise_sarif_error(tmp_path):
    (tmp_path / "bad.txt").write_text("not json")
    with pytest.raises(SarifError):
        triage(tmp_path, tmp_path / "bad.txt")
    (tmp_path / "array.txt").write_text("[]")
    with pytest.raises(SarifError):
        triage(tmp_path, tmp_path / "array.txt")
    (tmp_path / "empty.txt").write_text("{}")
    with pytest.raises(SarifError):
        triage(tmp_path, tmp_path / "empty.txt")
    (tmp_path / "nolist.txt").write_text('{"runs": 5}')
    with pytest.raises(SarifError):
        triage(tmp_path, tmp_path / "nolist.txt")
    with pytest.raises(SarifError):
        triage(tmp_path, tmp_path / "nosuch.txt")


def test_unparseable_file_turns_not_reachable_into_unknown(tmp_path):
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef index():\n    return 1\n")
    (tmp_path / "helpers.py").write_text("def helper():\n    return 1\n")
    (tmp_path / "broken.py").write_text("def (:\n")
    results = [
        {"ruleId": "r1", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "helpers.py"}, "region": {"startLine": 2}}}]},
    ]
    sarif_path = write_sarif(tmp_path, results)
    result = triage(tmp_path, sarif_path)
    assert result["results"][0]["verdict"] == "UNKNOWN"
    assert "could not be parsed" in result["results"][0]["reason"]
    assert result["skipped_files"] == ["broken.py"]


def test_empty_sarif_summary(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    return 1\n")
    sarif_path = tmp_path / "empty.sarif"
    sarif_path.write_text('{"version": "2.1.0", "runs": []}')
    result = triage(tmp_path, sarif_path)
    assert result["results"] == []
    assert result["summary"] == {"total": 0, "REACHABLE": 0, "LIKELY_REACHABLE": 0, "NOT_REACHABLE": 0, "UNKNOWN": 0, "UNLOCATED": 0}
    assert result["unresolved"] == []
    assert result["skipped_files"] == []


def test_cli_text_json_and_fail_flag(tmp_path, capsys):
    result = main(["triage", str(FIXTURES / "fixtures_triage" / "basic"), str(FIXTURES / "fixtures_triage" / "basic" / "findings.sarif")])
    assert result == 0
    captured = capsys.readouterr()
    assert "Triage: 6 finding(s)" in captured.out
    assert "  REACHABLE: 2" in captured.out
    assert "[REACHABLE] py/sql-injection  db.py:2  db.run_query" in captured.out
    assert "  path: app.users -> db.run_query" in captured.out
    assert "[LIKELY_REACHABLE] py/unsafe-render  reports.py:3  reports.Report.render" in captured.out
    assert "  path: app.export ~> reports.Report.render" in captured.out
    assert "[UNLOCATED] py/outdated-dependency  requirements.txt:3  -" in captured.out
    assert "  reason: no analyzed function contains this location" in captured.out
    result = main(["triage", str(FIXTURES / "fixtures_triage" / "basic"), str(FIXTURES / "fixtures_triage" / "basic" / "findings.sarif"), "--json"])
    assert result == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["summary"]["REACHABLE"] == 2
    result = main(["triage", str(FIXTURES / "fixtures_triage" / "basic"), str(FIXTURES / "fixtures_triage" / "basic" / "findings.sarif"), "--fail-on-reachable"])
    assert result == 1
    result = main(["triage", str(FIXTURES / "fixtures_triage" / "dynamic"), str(FIXTURES / "fixtures_triage" / "dynamic" / "findings.sarif"), "--fail-on-reachable"])
    assert result == 0
