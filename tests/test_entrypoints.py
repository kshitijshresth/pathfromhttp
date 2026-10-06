import json
import warnings
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
    assert find_entry_points(tmp_path) == ["app.a", "app.nf", "app.pre"]

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


def test_class_based_route_decorator(tmp_path):
    write(tmp_path, "app.py", (
        "from flask_restx import Namespace, Resource\n"
        "ns = Namespace('x')\n"
        "@ns.route('/x')\n"
        "class Res(Resource):\n"
        "    def get(self): return 1\n"
        "    def post(self): return 2\n"
        "    def helper(self): return 3\n"
    ))
    assert find_entry_points(tmp_path) == ["app.Res.get", "app.Res.post"]


def test_add_resource(tmp_path):
    write(tmp_path, "app.py", (
        "class Res:\n"
        "    def get(self): return 1\n"
        "    def put(self): return 2\n"
        "    def helper(self): return 3\n"
        "api.add_resource(Res, '/r')\n"
    ))
    assert find_entry_points(tmp_path) == ["app.Res.get", "app.Res.put"]


def test_as_view(tmp_path):
    write(tmp_path, "app.py", (
        "from flask.views import MethodView\n"
        "class V(MethodView):\n"
        "    def get(self): return 1\n"
        "app.add_url_rule('/v', view_func=V.as_view('v'))\n"
    ))
    assert find_entry_points(tmp_path) == ["app.V.get"]


def test_call_style_hook_registration(tmp_path):
    write(tmp_path, "app.py", (
        "def close_db(): return 1\n"
        "def nf(): return 2\n"
        "def helper(): return 3\n"
        "app.teardown_appcontext(close_db)\n"
        "app.register_error_handler(404, nf)\n"
    ))
    assert find_entry_points(tmp_path) == ["app.close_db", "app.nf"]


def test_hook_decorator_on_imported_blueprint(tmp_path):
    write(tmp_path, "other.py", "bp = Blueprint('b', __name__)\n")
    write(tmp_path, "app.py", (
        "from other import bp\n"
        "@bp.before_app_request\ndef f(): return 1\n"
    ))
    assert find_entry_points(tmp_path) == ["app.f"]


def test_test_code_is_skipped(tmp_path):
    code = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/x')\ndef index(): return 1\n"
    )
    write(tmp_path, "tests/x.py", code)
    write(tmp_path, "test_a.py", code)
    write(tmp_path, "a_test.py", code)
    write(tmp_path, "conftest.py", code)
    write(tmp_path, "real.py", code)
    assert find_entry_points(tmp_path) == ["real.index"]


def test_no_syntax_warning_for_invalid_escape(tmp_path):
    write(tmp_path, "app.py", "x = '\\s'\n")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert find_entry_points(tmp_path) == []

def test_fastapi_verbs_on_known_receivers(tmp_path):
    write(tmp_path, "app.py", (
        "from fastapi import FastAPI, APIRouter\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "\n"
        "@app.get('/a')\n"
        "def a(): return 1\n"
        "\n"
        "@router.post('')\n"
        "def b(): return 1\n"
        "\n"
        "@router.head('/h')\n"
        "def c(): return 1\n"
        "\n"
        "@router.options('/o')\n"
        "async def d(): return 1\n"
        "\n"
        "@router.websocket('/ws')\n"
        "async def e(ws): return 1\n"
        "\n"
        "@router.api_route('/x', methods=['GET'])\n"
        "def f(): return 1\n"
        "\n"
        "def helper(): return 1\n"
    ))
    assert find_entry_points(tmp_path) == ["app.a", "app.b", "app.c", "app.d", "app.e", "app.f"]

def test_verb_decorator_on_imported_receiver_needs_path_literal(tmp_path):
    write(tmp_path, "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    write(tmp_path, "other.py", "class Thing:\n    def get(self, key): return None\ncache = Thing()\n")
    write(tmp_path, "routes.py", (
        "from main import app\n"
        "from other import thing, cache\n"
        "\n"
        "@app.get('/x')\n"
        "def a(): return 1\n"
        "\n"
        "@app.get('')\n"
        "def b(): return 1\n"
        "\n"
        "@app.get(path='/c')\n"
        "def c(): return 1\n"
        "\n"
        "@thing.get('key')\n"
        "def d(): return 1\n"
        "\n"
        "@thing.get()\n"
        "def e(): return 1\n"
        "\n"
        "@cache.post(some_var)\n"
        "def f(): return 1\n"
    ))
    assert find_entry_points(tmp_path) == ["routes.a", "routes.b", "routes.c"]

def test_middleware_and_exception_handler_hooks(tmp_path):
    write(tmp_path, "app.py", (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "\n"
        "@app.middleware('http')\n"
        "async def mw(request, call_next): return 1\n"
        "\n"
        "@app.exception_handler(ValueError)\n"
        "async def eh(request, exc): return 1\n"
        "\n"
        "def ke(request, exc): return 1\n"
        "app.add_exception_handler(KeyError, ke)\n"
        "\n"
        "@app.on_event('startup')\n"
        "def boot(): return 1\n"
        "\n"
        "def helper(): return 1\n"
    ))
    assert find_entry_points(tmp_path) == ["app.eh", "app.ke", "app.mw"]
