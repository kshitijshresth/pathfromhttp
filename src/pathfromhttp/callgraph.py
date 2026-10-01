import ast
import builtins
from collections import defaultdict
from pathlib import Path

from pathfromhttp.entrypoints import iter_py_files, module_name

BUILTIN_NAMES = set(dir(builtins))
BUILTIN_METHODS = set()
for _t in (str, bytes, list, dict, set, frozenset, tuple, int, float):
    BUILTIN_METHODS |= {m for m in dir(_t) if not m.startswith("_")}

FUNC_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


class CallGraph:
    def __init__(self):
        self.functions = {}
        self.edges = {}
        self.unresolved = {}
        self.ambiguous = {}

    def to_dict(self):
        def calls(d):
            return {
                k: [{"line": ln, "call": t} for ln, t in sorted(v)]
                for k, v in sorted(d.items()) if v
            }

        return {
            "functions": dict(sorted(self.functions.items())),
            "edges": {k: sorted(v) for k, v in sorted(self.edges.items())},
            "unresolved": calls(self.unresolved),
            "ambiguous": calls(self.ambiguous),
        }


class _ClassInfo:
    def __init__(self, qname, mod, node):
        self.qname = qname
        self.mod = mod
        self.node = node
        self.methods = {}
        self.bases = None
        self.ext_base = False


class _ModuleInfo:
    def __init__(self, name, tree, is_pkg, path):
        self.name = name
        self.tree = tree
        self.is_pkg = is_pkg
        self.path = path
        self.funcs = {}
        self.classes = {}
        self.env_cache = None
        self.inst_cache = None


class _Ctx:
    def __init__(self, mod, cq, first):
        self.mod = mod
        self.cq = cq
        self.first = first
        self.locals = set()
        self.nested = set()
        self.types = defaultdict(set)
        self.edges = set()
        self.unresolved = []
        self.ambiguous = []


def _flatten(n):
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return parts[::-1]
    return None


def _text(node):
    t = ast.unparse(node)
    return t if len(t) <= 80 else t[:77] + "..."


class _Builder:
    def __init__(self, root):
        self.root = Path(root)
        self.mods = {}
        self.classes = {}
        self.all_names = set()
        self.subs = None
        self.graph = CallGraph()

    def load(self):
        for py in iter_py_files(self.root):
            try:
                tree = ast.parse(py.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            name = module_name(self.root, py)
            if not name:
                continue
            rel = py.relative_to(self.root).as_posix()
            mi = _ModuleInfo(name, tree, py.name == "__init__.py", rel)
            for n in tree.body:
                if isinstance(n, FUNC_NODES):
                    mi.funcs[n.name] = (f"{name}.{n.name}", n)
                    self.all_names.add(n.name)
                elif isinstance(n, ast.ClassDef):
                    ci = _ClassInfo(f"{name}.{n.name}", name, n)
                    for m in n.body:
                        if isinstance(m, FUNC_NODES):
                            ci.methods[m.name] = f"{ci.qname}.{m.name}"
                            self.all_names.add(m.name)
                    mi.classes[n.name] = ci
                    self.classes[ci.qname] = ci
                    self.all_names.add(n.name)
            self.mods[name] = mi

    def is_proj_prefix(self, m):
        return m in self.mods or any(k.startswith(m + ".") for k in self.mods)

    def mod_entry(self, m):
        return ("module", m) if self.is_proj_prefix(m) else ("external", m)

    def from_base(self, mi, n):
        if n.level == 0:
            return n.module
        parts = mi.name.split(".")
        pkg = parts if mi.is_pkg else parts[:-1]
        up = n.level - 1
        if up > len(pkg):
            return None
        base = pkg[: len(pkg) - up]
        if n.module:
            base = base + n.module.split(".")
        return ".".join(base)

    def env(self, mod):
        mi = self.mods[mod]
        if mi.env_cache is not None:
            return mi.env_cache
        mi.env_cache = env = {}
        for n in ast.walk(mi.tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        env[a.asname] = self.mod_entry(a.name)
                    else:
                        top = a.name.split(".")[0]
                        env[top] = self.mod_entry(top)
            elif isinstance(n, ast.ImportFrom):
                base = self.from_base(mi, n)
                if base is None:
                    continue
                for a in n.names:
                    if a.name == "*":
                        if base in self.mods:
                            bm = self.mods[base]
                            for k, (q, _) in bm.funcs.items():
                                env.setdefault(k, ("func", q))
                            for k, ci in bm.classes.items():
                                env.setdefault(k, ("class", ci.qname))
                        continue
                    env[a.asname or a.name] = self.import_from_entry(base, a.name)
        return env

    def import_from_entry(self, base, name):
        full = f"{base}.{name}" if base else name
        if self.is_proj_prefix(full):
            return ("module", full)
        if base in self.mods:
            return self.export(base, name) or ("external", full)
        return ("external", full)

    def export(self, mod, name):
        mi = self.mods[mod]
        if name in mi.funcs:
            return ("func", mi.funcs[name][0])
        if name in mi.classes:
            return ("class", mi.classes[name].qname)
        inst = self.instances(mod).get(name)
        if inst:
            return ("instance", frozenset(inst))
        return self.env(mod).get(name)

    def instances(self, mod):
        mi = self.mods[mod]
        if mi.inst_cache is not None:
            return mi.inst_cache
        mi.inst_cache = inst = {}
        for n in mi.tree.body:
            if (
                isinstance(n, ast.Assign)
                and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
                and isinstance(n.value, ast.Call)
            ):
                cq = self.class_of(mod, n.value.func)
                if cq:
                    inst.setdefault(n.targets[0].id, set()).add(cq)
        return inst

    def lookup(self, mod, name):
        mi = self.mods[mod]
        if name in mi.funcs:
            return ("func", mi.funcs[name][0])
        if name in mi.classes:
            return ("class", mi.classes[name].qname)
        inst = self.instances(mod).get(name)
        if inst:
            return ("instance", frozenset(inst))
        return self.env(mod).get(name)

    def descend(self, m, rest):
        i = 0
        while i < len(rest) - 1 and self.is_proj_prefix(f"{m}.{rest[i]}"):
            m = f"{m}.{rest[i]}"
            i += 1
        return m, rest[i:]

    def dotted(self, mod, chain):
        head = self.lookup(mod, chain[0])
        if head is None or head[0] != "module" or len(chain) < 2:
            return None
        m, rest = self.descend(head[1], chain[1:])
        if m not in self.mods:
            return ("external", None)
        if len(rest) == 1:
            return self.export(m, rest[0]) or ("missing", rest[0])
        if len(rest) == 2:
            first = self.export(m, rest[0])
            if first and first[0] == "class":
                return ("method", first[1], rest[1])
            if first and first[0] == "instance":
                return ("imethod", first[1], rest[1])
            return ("missing", rest[0])
        return None

    def class_of(self, mod, f):
        if isinstance(f, ast.Name):
            e = self.lookup(mod, f.id)
        elif isinstance(f, ast.Attribute):
            chain = _flatten(f)
            e = self.dotted(mod, chain) if chain else None
        else:
            e = None
        return e[1] if e and e[0] == "class" else None

    def bases(self, ci):
        if ci.bases is None:
            ci.bases = []
            for b in ci.node.bases:
                cq = self.class_of(ci.mod, b)
                if cq:
                    ci.bases.append(cq)
                elif not (isinstance(b, ast.Name) and b.id == "object"):
                    ci.ext_base = True
        return ci.bases

    def lookup_method(self, cq, name, seen):
        if cq in seen:
            return None, False
        seen.add(cq)
        ci = self.classes[cq]
        if name in ci.methods:
            return ci.methods[name], False
        bases = self.bases(ci)
        ext = ci.ext_base
        for b in bases:
            q, e = self.lookup_method(b, name, seen)
            if q:
                return q, False
            ext = ext or e
        return None, ext

    def descendants(self, cq):
        if self.subs is None:
            self.subs = defaultdict(set)
            for ci in self.classes.values():
                for b in self.bases(ci):
                    self.subs[b].add(ci.qname)
        out, todo = set(), [cq]
        while todo:
            for d in self.subs.get(todo.pop(), ()):
                if d not in out:
                    out.add(d)
                    todo.append(d)
        return out

    def method_targets(self, cq, name):
        q, ext = self.lookup_method(cq, name, set())
        targets = {q} if q else set()
        for d in self.descendants(cq):
            if name in self.classes[d].methods:
                targets.add(self.classes[d].methods[name])
        if targets:
            return targets, "ok"
        return targets, ("ext" if ext else "missing")

    # ---- per-function analysis ----

    def apply_method(self, cq, name, line, text, ctx):
        targets, status = self.method_targets(cq, name)
        ctx.edges |= targets
        if not targets and status == "missing":
            ctx.unresolved.append((line, text))

    def unknown(self, name, line, text, ctx):
        if name in self.all_names:
            if name in BUILTIN_METHODS:
                ctx.ambiguous.append((line, text))
            else:
                ctx.unresolved.append((line, text))

    def apply_entry(self, e, name, line, text, ctx):
        kind = e[0]
        if kind == "func":
            ctx.edges.add(e[1])
        elif kind == "class":
            targets, _ = self.method_targets(e[1], "__init__")
            ctx.edges |= targets
        elif kind == "instance":
            for cq in e[1]:
                self.apply_method(cq, "__call__", line, text, ctx)
        elif kind == "method":
            self.apply_method(e[1], e[2], line, text, ctx)
        elif kind == "imethod":
            for cq in e[1]:
                self.apply_method(cq, e[2], line, text, ctx)
        elif kind == "missing":
            self.unknown(e[1], line, text, ctx)

    def call(self, c, ctx):
        f = c.func
        line, text = c.lineno, _text(c.func)
        if isinstance(f, ast.Name):
            name = f.id
            if name in ctx.locals:
                if name not in ctx.nested:
                    ctx.unresolved.append((line, text))
                return
            e = self.lookup(ctx.mod, name)
            if e is None:
                if name not in BUILTIN_NAMES:
                    self.unknown(name, line, text, ctx)
                return
            self.apply_entry(e, name, line, text, ctx)
            return
        if not isinstance(f, ast.Attribute):
            ctx.unresolved.append((line, text))
            return
        chain = _flatten(f)
        attr = f.attr
        if chain is None or len(chain) < 2:
            self.unknown(attr, line, text, ctx)
            return
        head = chain[0]
        if ctx.first and ctx.cq and head == ctx.first and len(chain) == 2:
            self.apply_method(ctx.cq, attr, line, text, ctx)
            return
        if head in ctx.locals:
            if len(chain) == 2:
                for t in ctx.types.get(head) or {None}:
                    if t is None:
                        self.unknown(attr, line, text, ctx)
                    else:
                        self.apply_method(t, attr, line, text, ctx)
            else:
                self.unknown(attr, line, text, ctx)
            return
        e = self.lookup(ctx.mod, head)
        if e is None:
            if head not in BUILTIN_NAMES:
                self.unknown(attr, line, text, ctx)
            return
        kind = e[0]
        if kind == "external":
            return
        if kind == "class" and len(chain) == 2:
            self.apply_method(e[1], attr, line, text, ctx)
        elif kind == "instance" and len(chain) == 2:
            for cq in e[1]:
                self.apply_method(cq, attr, line, text, ctx)
        elif kind == "module":
            ent = self.dotted(ctx.mod, chain)
            if ent is None:
                self.unknown(attr, line, text, ctx)
            elif ent[0] != "external":
                self.apply_entry(ent, attr, line, text, ctx)
        else:
            self.unknown(attr, line, text, ctx)

    def analyze(self, fq, node, mi, cq, static):
        first = None
        if cq and not static:
            params = node.args.posonlyargs + node.args.args
            first = params[0].arg if params else None
        ctx = _Ctx(mi.name, cq, first)
        typed = set()
        for n in ast.walk(node):
            if isinstance(n, ast.arg):
                ctx.locals.add(n.arg)
                ctx.types[n.arg].add(None)
            elif isinstance(n, FUNC_NODES) and n is not node:
                ctx.locals.add(n.name)
                ctx.nested.add(n.name)
            elif isinstance(n, ast.ClassDef):
                ctx.locals.add(n.name)
                ctx.types[n.name].add(None)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                ctx.locals.add(n.name)
                ctx.types[n.name].add(None)
            elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
                k = self.class_of(mi.name, n.value.func)
                if k:
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            ctx.locals.add(t.id)
                            ctx.types[t.id].add(k)
                            typed.add(id(t))
        for n in ast.walk(node):
            if (
                isinstance(n, ast.Name)
                and isinstance(n.ctx, (ast.Store, ast.Del))
                and id(n) not in typed
            ):
                ctx.locals.add(n.id)
                ctx.types[n.id].add(None)
        call_funcs = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                call_funcs.add(id(n.func))
                self.call(n, ctx)
        for n in ast.walk(node):
            if id(n) in call_funcs:
                continue
            if (
                isinstance(n, ast.Name)
                and isinstance(n.ctx, ast.Load)
                and n.id not in ctx.locals
            ):
                e = self.lookup(mi.name, n.id)
                if e and e[0] == "func":
                    ctx.edges.add(e[1])
            elif (
                isinstance(n, ast.Attribute)
                and isinstance(n.ctx, ast.Load)
                and isinstance(n.value, ast.Name)
                and ctx.first
                and ctx.cq
                and n.value.id == ctx.first
            ):
                targets, _ = self.method_targets(ctx.cq, n.attr)
                ctx.edges |= targets
        g = self.graph
        g.functions[fq] = f"{mi.path}:{node.lineno}"
        g.edges[fq] = ctx.edges
        g.unresolved[fq] = ctx.unresolved
        g.ambiguous[fq] = ctx.ambiguous

    def run(self):
        self.load()
        for mi in self.mods.values():
            for q, node in mi.funcs.values():
                self.analyze(q, node, mi, None, False)
            for ci in mi.classes.values():
                for m in ci.node.body:
                    if not isinstance(m, FUNC_NODES):
                        continue
                    static = any(
                        isinstance(d, ast.Name) and d.id == "staticmethod"
                        for d in m.decorator_list
                    )
                    self.analyze(ci.methods[m.name], m, mi, ci.qname, static)
        return self.graph


def build_call_graph(root):
    return _Builder(root).run()
