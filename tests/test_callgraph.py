from pathlib import Path
import pytest
from pathfromhttp.callgraph import build_call_graph

FIXTURES = Path(__file__).parent / "fixtures"

def graph(name):
    return build_call_graph(FIXTURES / name)
def write(tmp_path, files):
    for rel, text in files.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return build_call_graph(tmp_path)


def test_direct_hit():
    g = graph("direct_hit")
    assert g.edges["app.index"] == {"app.vuln"}
    assert not g.unresolved["app.index"]


def test_transitive_hit():
    g = graph("transitive_hit")
    assert g.edges["app.upload"] == {"app.step_a"}
    assert g.edges["app.step_a"] == {"app.step_b"}
    assert g.edges["app.step_b"] == {"app.vuln"}


def test_dead_code():
    g = graph("dead_code")
    assert g.edges["app.index"] == set()
    assert not g.unresolved["app.index"]


def test_method_call():
    g = graph("method_call")
    assert g.edges["app.index"] == {"app.Service.run"}
    assert g.edges["app.Service.run"] == {"app.Service.inner"}
    assert g.edges["app.Service.inner"] == {"app.vuln"}


def test_dynamic_getattr_is_unresolved_not_guessed():
    g = graph("dynamic_getattr")
    assert g.edges["app.index"] == set()
    assert [u[1] for u in g.unresolved["app.index"]] == ["fn"]


def test_blueprint():
    assert graph("blueprint").edges["app.handler"] == {"app.vuln"}


def test_multi_module():
    g = graph("multi_module")
    assert g.edges["app.index"] == {"helpers.process"}
    assert g.edges["helpers.process"] == {"util.vuln"}


def test_module_level_calls_are_ignored():
    g = graph("unreachable_helper")
    assert g.edges["app.index"] == set()
    assert g.edges["app.cli_only"] == {"app.vuln"}


def test_every_function_is_a_node():
    g = graph("multi_module")
    assert set(g.functions) == {"app.index", "helpers.process", "util.vuln"}
    assert g.functions["util.vuln"] == "util.py:1"


def test_constructor_and_self_calls(tmp_path):
    g = write(tmp_path, {"a.py": (
        "class S:\n"
        "    def __init__(self):\n        self.setup()\n"
        "    def setup(self):\n        return 1\n"
        "def f():\n    s = S()\n    return s.setup()\n"
    )})
    assert g.edges["a.f"] == {"a.S.__init__", "a.S.setup"}
    assert g.edges["a.S.__init__"] == {"a.S.setup"}


def test_inheritance_and_override(tmp_path):
    g = write(tmp_path, {"a.py": (
        "class Base:\n"
        "    def run(self):\n        return self.step()\n"
        "    def step(self):\n        return 1\n"
        "class Child(Base):\n"
        "    def step(self):\n        return 2\n"
        "def f():\n    c = Child()\n    return c.run()\n"
    )})
    assert g.edges["a.f"] == {"a.Base.run"}
    assert g.edges["a.Base.run"] == {"a.Base.step", "a.Child.step"}


def test_module_alias_and_dotted_import(tmp_path):
    g = write(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/util.py": "def helper():\n    return 1\n",
        "a.py": (
            "import pkg.util\nimport pkg.util as u\n"
            "def f():\n    return pkg.util.helper()\n"
            "def g():\n    return u.helper()\n"
        ),
    })
    assert g.edges["a.f"] == {"pkg.util.helper"}
    assert g.edges["a.g"] == {"pkg.util.helper"}


def test_relative_import(tmp_path):
    g = write(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/util.py": "def helper():\n    return 1\n",
        "pkg/views.py": "from .util import helper\ndef f():\n    return helper()\n",
        "pkg/other.py": "from . import util\ndef g():\n    return util.helper()\n",
    })
    assert g.edges["pkg.views.f"] == {"pkg.util.helper"}
    assert g.edges["pkg.other.g"] == {"pkg.util.helper"}


def test_reexport_through_package(tmp_path):
    g = write(tmp_path, {
        "pkg/__init__.py": "from .util import helper\n",
        "pkg/util.py": "def helper():\n    return 1\n",
        "a.py": "from pkg import helper\ndef f():\n    return helper()\n",
    })
    assert g.edges["a.f"] == {"pkg.util.helper"}


def test_function_passed_as_callback_is_an_edge(tmp_path):
    g = write(tmp_path, {"a.py": (
        "def work():\n    return 1\n"
        "def f(pool):\n    return pool.submit(work)\n"
    )})
    assert g.edges["a.f"] == {"a.work"}


def test_param_call_and_subscript_call_are_unresolved(tmp_path):
    g = write(tmp_path, {"a.py": (
        "def f(cb, table):\n    cb()\n    return table['x']()\n"
    )})
    assert len(g.unresolved["a.f"]) == 2


def test_unknown_receiver_flagged_only_when_name_is_project_defined(tmp_path):
    g = write(tmp_path, {"a.py": (
        "class S:\n    def process(self):\n        return 1\n"
        "def f(obj):\n    return obj.process()\n"
        "def h(obj):\n    return obj.something_else()\n"
    )})
    assert len(g.unresolved["a.f"]) == 1
    assert not g.unresolved["a.h"]

def test_builtin_method_name_collision_is_ambiguous_not_unresolved(tmp_path):
    g = write(tmp_path, {"a.py": (
        "class S:\n    def get(self):\n        return 1\n"
        "def f(d):\n    return d.get('k')\n"
    )})
    assert not g.unresolved["a.f"]
    assert len(g.ambiguous["a.f"]) == 1


def test_external_calls_ignored(tmp_path):
    g = write(tmp_path, {"a.py": (
        "import os\nfrom flask import request\n"
        "def f():\n    print(len(os.path.join('a', 'b')))\n    return request.get_json()\n"
    )})
    assert g.edges["a.f"] == set()
    assert not g.unresolved["a.f"] and not g.ambiguous["a.f"]

def test_module_level_instance(tmp_path):
    g = write(tmp_path, {
        "svc.py": "class S:\n    def run(self):\n        return 1\nshared = S()\n",
        "a.py": "from svc import shared\ndef f():\n    return shared.run()\n",
    })
    assert g.edges["a.f"] == {"svc.S.run"}

def test_nested_function_call_is_not_unresolved(tmp_path):
    g = write(tmp_path, {"a.py": (
        "def target():\n    return 1\n"
        "def f():\n    def inner():\n        return target()\n    return inner()\n"
    )})
    assert g.edges["a.f"] == {"a.target"}
    assert not g.unresolved["a.f"]



def test_to_dict_is_json_serialisable(tmp_path):
    import json
    g = write(tmp_path, {"a.py": "def f():\n    return 1\n"})
    json.dumps(g.to_dict())
