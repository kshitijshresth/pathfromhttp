import ast
import warnings
from pathlib import Path

SKIP_DIRS = {
    ".git", "__pycache__", ".venv", "venv", "node_modules",
    "site-packages", ".pytest_cache", "build", "dist",
}
ROUTE_ATTRS = {"get", "post", "put", "delete", "patch"}
HOOK_ATTRS = {
    "before_request", "after_request", "teardown_request",
    "teardown_appcontext", "before_first_request", "before_app_request",
    "after_app_request", "teardown_app_request", "before_app_first_request",
    "errorhandler", "app_errorhandler", "context_processor",
    "app_context_processor", "url_value_preprocessor", "url_defaults",
    "template_filter", "template_global", "template_test",
}
CLASS_METHOD_ATTRS = {"get", "post", "put", "delete", "patch", "head", "options"}
FACTORIES = {"Flask", "Blueprint"}


def module_name(root, path):
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def iter_py_files(root):
    for p in sorted(root.rglob("*.py")):
        dirs = p.relative_to(root).parts[:-1]
        if any(d in SKIP_DIRS or d.endswith(".egg-info") for d in dirs):
            continue
        if any(d in ("tests", "test") for d in dirs):
            continue
        name = p.name
        if name == "conftest.py" or name.startswith("test_") or name.endswith("_test.py"):
            continue
        yield p


def parse_source(path):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ast.parse(path.read_text(encoding="utf-8"))


def _factory_name(call):
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _known_receivers(tree):
    names = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and _factory_name(node.value) in FACTORIES
        ):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
    return names


def _decorator_parts(dec):
    node = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    return None, None


def _is_entry_decorator(dec, receivers):
    recv, attr = _decorator_parts(dec)
    if attr is None:
        return False
    if attr == "route":
        return True
    return recv in receivers and (attr in ROUTE_ATTRS or attr in HOOK_ATTRS)


def _is_hook_decorator(dec):
    recv, attr = _decorator_parts(dec)
    if attr is None:
        return False
    return attr in HOOK_ATTRS


def _is_route_decorator(dec):
    recv, attr = _decorator_parts(dec)
    if attr is None:
        return False
    return attr == "route"


def _view_func_name(call):
    for kw in call.keywords:
        if kw.arg == "view_func":
            if isinstance(kw.value, ast.Name):
                return kw.value.id
            if isinstance(kw.value, ast.Call):
                cls = _get_as_view_class(kw.value)
                if cls:
                    return f"__as_view__:{cls}"
    if len(call.args) >= 3 and isinstance(call.args[2], ast.Name):
        return call.args[2].id
    return None


def _is_as_view_call(call):
    if not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr != "as_view":
        return False
    return True


def _get_as_view_class(call):
    if not _is_as_view_call(call):
        return None
    if isinstance(call.func.value, ast.Name):
        return call.func.value.id
    return None


def entry_points_in_file(tree, mod):
    receivers = _known_receivers(tree)
    defined_funcs = {
        n.name for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    defined_classes = {
        n.name: n for n in tree.body
        if isinstance(n, ast.ClassDef)
    }
    found = set()
    route_decorated_classes = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            if any(_is_route_decorator(d) for d in node.decorator_list):
                route_decorated_classes.add(node.name)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_resource"
            and len(node.args) >= 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in defined_classes
        ):
            route_decorated_classes.add(node.args[0].id)

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(_is_entry_decorator(d, receivers) for d in node.decorator_list):
                found.add(f"{mod}.{node.name}")
            if any(_is_hook_decorator(d) for d in node.decorator_list):
                found.add(f"{mod}.{node.name}")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in HOOK_ATTRS
            and len(node.args) >= 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in defined_funcs
        ):
            found.add(f"{mod}.{node.args[0].id}")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "register_error_handler"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Name)
            and node.args[1].id in defined_funcs
        ):
            found.add(f"{mod}.{node.args[1].id}")
    for cls_name in route_decorated_classes:
        cls_node = defined_classes[cls_name]
        for m in cls_node.body:
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if m.name in CLASS_METHOD_ATTRS:
                    found.add(f"{mod}.{cls_name}.{m.name}")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_url_rule"
        ):
            vf = _view_func_name(node)
            if vf:
                if vf.startswith("__as_view__:"):
                    cls_name = vf.split(":", 1)[1]
                    if cls_name in defined_classes:
                        cls_node = defined_classes[cls_name]
                        for m in cls_node.body:
                            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                if m.name in CLASS_METHOD_ATTRS:
                                    found.add(f"{mod}.{cls_name}.{m.name}")
                elif vf in defined_funcs:
                    found.add(f"{mod}.{vf}")
    return found


def find_entry_points(root):
    root = Path(root)
    found = set()
    for py in iter_py_files(root):
        try:
            tree = parse_source(py)
        except (SyntaxError, UnicodeDecodeError, ValueError):
            continue
        found |= entry_points_in_file(tree, module_name(root, py))
    return sorted(found)
