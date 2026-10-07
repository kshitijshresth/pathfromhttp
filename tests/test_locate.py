from pathlib import Path
import pytest
from pathfromhttp.callgraph import build_call_graph
from pathfromhttp.locate import locate
from pathfromhttp.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def write_graph(tmp_path, files):
    for rel, text in files.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return build_call_graph(tmp_path)


def test_line_in_function_body(tmp_path):
    g = write_graph(tmp_path, {"app.py": "def f():\n    x = 1\n    return x\n"})
    assert locate(g, tmp_path, "app.py", 2) == "app.f"
    assert locate(g, tmp_path, "app.py", 3) == "app.f"


def test_def_line_and_last_line(tmp_path):
    g = write_graph(tmp_path, {"app.py": "def f():\n    return 1\n\n\ndef g():\n    return 2\n"})
    assert locate(g, tmp_path, "app.py", 1) == "app.f"
    assert locate(g, tmp_path, "app.py", 2) == "app.f"
    assert locate(g, tmp_path, "app.py", 5) == "app.g"
    assert locate(g, tmp_path, "app.py", 6) == "app.g"


def test_decorator_line_maps_to_function(tmp_path):
    g = write_graph(tmp_path, {"app.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef index():\n    return 1\n"})
    assert locate(g, tmp_path, "app.py", 4) == "app.index"
    assert locate(g, tmp_path, "app.py", 5) == "app.index"
    assert locate(g, tmp_path, "app.py", 6) == "app.index"
    assert locate(g, tmp_path, "app.py", 3) is None


def test_blank_line_between_functions_is_none(tmp_path):
    g = write_graph(tmp_path, {"app.py": "def f():\n    return 1\n\n\ndef g():\n    return 2\n"})
    assert locate(g, tmp_path, "app.py", 3) is None
    assert locate(g, tmp_path, "app.py", 4) is None


def test_module_level_line_is_none(tmp_path):
    g = write_graph(tmp_path, {"app.py": "X = 1\n\ndef f():\n    return X\n\nprint(f())\n"})
    assert locate(g, tmp_path, "app.py", 1) is None
    assert locate(g, tmp_path, "app.py", 6) is None


def test_method_line_and_class_body_line(tmp_path):
    g = write_graph(tmp_path, {"app.py": "class C:\n    attr = 1\n\n    def m(self):\n        return self.attr\n"})
    assert locate(g, tmp_path, "app.py", 4) == "app.C.m"
    assert locate(g, tmp_path, "app.py", 5) == "app.C.m"
    assert locate(g, tmp_path, "app.py", 1) is None
    assert locate(g, tmp_path, "app.py", 2) is None


def test_nested_function_maps_to_enclosing_function(tmp_path):
    g = write_graph(tmp_path, {"app.py": "def outer():\n    def inner():\n        return 1\n    return inner()\n"})
    assert locate(g, tmp_path, "app.py", 2) == "app.outer"
    assert locate(g, tmp_path, "app.py", 3) == "app.outer"


def test_windows_separators_and_dot_slash_prefix(tmp_path):
    g = write_graph(tmp_path, {"pkg/__init__.py": "", "pkg/views.py": "def h():\n    return 1\n"})
    assert locate(g, tmp_path, "pkg\\views.py", 2) == "pkg.views.h"
    assert locate(g, tmp_path, "./pkg/views.py", 2) == "pkg.views.h"


def test_absolute_path_inside_root(tmp_path):
    g = write_graph(tmp_path, {"app.py": "def f():\n    return 1\n"})
    abs_path = str(tmp_path / "app.py")
    assert locate(g, tmp_path, abs_path, 2) == "app.f"


def test_unanalyzed_file_is_none(tmp_path):
    g = write_graph(tmp_path, {"app.py": "def f():\n    return 1\n"})
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def f():\n    return 1\n")
    assert locate(g, tmp_path, "tests/test_x.py", 2) is None
    assert locate(g, tmp_path, "missing.py", 1) is None
    assert locate(g, tmp_path, str(tmp_path.parent / "other.py"), 1) is None


def test_spans_in_to_dict(tmp_path):
    g = write_graph(tmp_path, {"app.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef index():\n    return 1\n"})
    assert g.to_dict()["spans"]["app.index"] == {"file": "app.py", "start": 4, "end": 6}


def test_cli_found(tmp_path, capsys):
    write_graph(tmp_path, {"app.py": "def f():\n    return 1\n"})
    assert main(["locate", str(tmp_path), "app.py:2"]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "app.f"


def test_cli_not_found_exit_1(tmp_path, capsys):
    write_graph(tmp_path, {"app.py": "def f():\n    return 1\n"})
    assert main(["locate", str(tmp_path), "app.py:99"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no function contains" in captured.err


def test_cli_malformed_exit_3(tmp_path, capsys):
    write_graph(tmp_path, {"app.py": "def f():\n    return 1\n"})
    assert main(["locate", str(tmp_path), "app.py"]) == 3
    assert main(["locate", str(tmp_path), "app.py:abc"]) == 3
    assert main(["locate", str(tmp_path), "app.py:0"]) == 3


def test_cli_json(tmp_path, capsys):
    write_graph(tmp_path, {"app.py": "def f():\n    return 1\n"})
    assert main(["locate", str(tmp_path), "app.py:2", "--json"]) == 0
    captured = capsys.readouterr()
    import json
    result = json.loads(captured.out)
    assert result == {"location": "app.py:2", "file": "app.py", "line": 2, "function": "app.f", "span": {"file": "app.py", "start": 1, "end": 2}}
    assert main(["locate", str(tmp_path), "app.py:99", "--json"]) == 1
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["function"] is None
    assert result["span"] is None


def test_fixture_method_call_and_multi_module():
    g = build_call_graph(FIXTURES / "method_call")
    assert locate(g, FIXTURES / "method_call", "app.py", 7) == "app.vuln"
    assert locate(g, FIXTURES / "method_call", "app.py", 12) == "app.Service.run"
    assert locate(g, FIXTURES / "method_call", "app.py", 15) == "app.Service.inner"
    assert locate(g, FIXTURES / "method_call", "app.py", 18) == "app.index"
    assert locate(g, FIXTURES / "method_call", "app.py", 21) == "app.index"
    assert locate(g, FIXTURES / "method_call", "app.py", 3) is None
    assert locate(g, FIXTURES / "method_call", "app.py", 9) is None
    assert locate(g, FIXTURES / "method_call", "app.py", 10) is None
    g = build_call_graph(FIXTURES / "multi_module")
    assert locate(g, FIXTURES / "multi_module", "helpers.py", 5) == "helpers.process"
