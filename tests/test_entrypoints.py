import json
from pathlib import Path

import pytest

from pathfromhttp.entrypoints import find_entry_points

FIXTURES = Path(__file__).parent / "fixtures"
DIRS = sorted(p for p in FIXTURES.iterdir() if p.is_dir())


@pytest.mark.parametrize("fixture", DIRS, ids=lambda p: p.name)
def test_fixture_entry_points(fixture):
    exp = json.loads((fixture / "expected.json").read_text())
    assert find_entry_points(fixture) == sorted(exp["entry_points"])


def write(tmp_path, rel, text):
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    return f


def test_add_url_rule(tmp_path):
    write(tmp_path, "app.py", (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "def view():\n    return 1\n"
        "def other():\n    return 2\n"
        "app.add_url_rule('/a', 'a', view)\n"
        "app.add_url_rule('/b', view_func=other)\n"
    ))
    assert find_entry_points(tmp_path) == ["app.other", "app.view"]


def test_method_decorators_and_hooks(tmp_path):
    write(tmp_path, "app.py", (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.get('/a')\ndef a():\n    return 1\n"
        "@app.before_request\ndef pre():\n    return None\n"
        "@app.errorhandler(404)\ndef nf(e):\n    return 1\n"
    ))
    assert find_entry_points(tmp_path) == ["app.a", "app.pre"]


def test_plain_functions_not_detected(tmp_path):
    write(tmp_path, "app.py", "def f():\n    return 1\n\nclass C:\n    def g(self):\n        return 2\n")
    assert find_entry_points(tmp_path) == []


def test_package_module_name_and_skip_dirs(tmp_path):
    code = (
        "from flask import Blueprint\n"
        "bp = Blueprint('b', __name__)\n"
        "@bp.route('/x')\ndef h():\n    return 1\n"
    )
    write(tmp_path, "pkg/views.py", code)
    write(tmp_path, "pkg/__init__.py", code)
    write(tmp_path, ".venv/lib/x.py", code)
    write(tmp_path, "node_modules/y.py", code)
    assert find_entry_points(tmp_path) == ["pkg.h", "pkg.views.h"]


def test_syntax_error_file_skipped(tmp_path):
    write(tmp_path, "bad.py", "def (:\n")
    assert find_entry_points(tmp_path) == []
