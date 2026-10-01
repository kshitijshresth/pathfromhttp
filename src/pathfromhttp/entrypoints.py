import ast
from pathlib import Path

SKIP_DIRS = {
    ".git", "__pycache__", ".venv", "venv", "node_modules",
    "site-packages", ".pytest_cache", "build", "dist",
}
ROUTE_ATTRS = {"get", "post", "put", "delete", "patch"}
HOOK_ATTRS = {
    "before_request", "after_request",
    "before_app_request", "after_app_request",
}
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
        yield p


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


def _view_func_name(call):
    for kw in call.keywords:
        if kw.arg == "view_func" and isinstance(kw.value, ast.Name):
            return kw.value.id
    if len(call.args) >= 3 and isinstance(call.args[2], ast.Name):
        return call.args[2].id
    return None


def entry_points_in_file(tree, mod):
    receivers = _known_receivers(tree)
    defined = {
        n.name for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    found = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(_is_entry_decorator(d, receivers) for d in node.decorator_list):
                found.add(f"{mod}.{node.name}")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_url_rule"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in receivers
        ):
            name = _view_func_name(node)
            if name in defined:
                found.add(f"{mod}.{name}")
    return found


def find_entry_points(root):
    root = Path(root)
    found = set()
    for py in iter_py_files(root):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        found |= entry_points_in_file(tree, module_name(root, py))
    return sorted(found)
