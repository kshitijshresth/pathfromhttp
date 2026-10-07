import ast
import builtins
from collections import defaultdict
from pathlib import Path

from pathfromhttp.entrypoints import iter_py_files, module_name, parse_source

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
        self.approx = {}
        self.extra_entries = set()
        self.skipped_files = []
        self.spans = {}

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
            "approx_edges": {k: sorted(v) for k, v in sorted(self.approx.items()) if v},
            "extra_entry_points": sorted(self.extra_entries),
            "skipped_files": self.skipped_files,
            "spans": dict(sorted(self.spans.items())),
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
        self.ext_vars = None


class _Ctx:
    def __init__(self, mod, cq, first, q):
        self.mod = mod
        self.cq = cq
        self.first = first
        self.q = q
        self.locals = set()
        self.nested = set()
        self.types = defaultdict(set)
        self.edges = set()
        self.approx = set()
        self.unresolved = []
        self.ambiguous = []
        self.decorator_param = None


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
        self.all_methods = set()
        self.subs = None
        self.graph = CallGraph()
        self.decorator_map = defaultdict(set)
        self.decorator_params = defaultdict(set)

    def load(self):
        for py in iter_py_files(self.root):
            try:
                tree = parse_source(py)
            except (SyntaxError, UnicodeDecodeError, ValueError):
                rel = py.relative_to(self.root).as_posix()
                self.graph.skipped_files.append(rel)
                continue
            name = module_name(self.root, py)
            if not name:
                continue
            rel = py.relative_to(self.root).as_posix()
            mi = _ModuleInfo(name, tree, py.name == "__init__.py", rel)
            for n in tree.body:
                if isinstance(n, FUNC_NODES):
                    qname = f"{name}.{n.name}"
                    mi.funcs[n.name] = (qname, n)
                    self.all_names.add(n.name)
                    start = n.lineno
                    for dec in n.decorator_list:
                        if dec.lineno < start:
                            start = dec.lineno
                    self.graph.spans[qname] = {"file": rel, "start": start, "end": n.end_lineno}
                elif isinstance(n, ast.ClassDef):
                    ci = _ClassInfo(f"{name}.{n.name}", name, n)
                    for m in n.body:
                        if isinstance(m, FUNC_NODES):
                            mqname = f"{ci.qname}.{m.name}"
                            ci.methods[m.name] = mqname
                            self.all_methods.add(m.name)
                            self.all_names.add(m.name)
                            start = m.lineno
                            for dec in m.decorator_list:
                                if dec.lineno < start:
                                    start = dec.lineno
                            self.graph.spans[mqname] = {"file": rel, "start": start, "end": m.end_lineno}
                    mi.classes[n.name] = ci
                    self.classes[ci.qname] = ci
                    self.all_names.add(n.name)
            self.mods[name] = mi
        self.graph.skipped_files.sort()

    def is_proj_prefix(self, m):
        return m in self.mods or any(k.startswith(m + ".") for k in self.mods)

    def mod_entry(self, m):
        return ("module", m) if self.is_proj_prefix(m) else ("external_module", m)

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
                            for k, v in self.ext_vars(base).items():
                                env.setdefault(k, ("extvar", True))
                        continue
                    entry = self.import_from_entry(base, a.name)
                    if entry:
                        env[a.asname or a.name] = entry
                    else:
                        env[a.asname or a.name] = ("external", base if base else a.name)
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
        ev = self.ext_vars(mod).get(name)
        if ev:
            return ("extvar", ev)
        e = self.env(mod).get(name)
        if e and e[0] == "extvar":
            return ("extvar", True)
        return self.env(mod).get(name)

    def ext_vars(self, mod):
        mi = self.mods[mod]
        if mi.ext_vars is not None:
            return mi.ext_vars
        mi.ext_vars = ev = {}
        for n in mi.tree.body:
            if (
                isinstance(n, ast.Assign)
                and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
                and isinstance(n.value, ast.Call)
            ):
                fn = n.value.func
                is_external = False
                if isinstance(fn, ast.Name):
                    if fn.id in mi.funcs or fn.id in mi.classes:
                        continue
                    e = self.env(mod).get(fn.id)
                    if e and e[0] in ("external", "external_module"):
                        is_external = True
                elif isinstance(fn, ast.Attribute):
                    chain = _flatten(fn)
                    if chain is None:
                        continue
                    if chain[0] in mi.funcs or chain[0] in mi.classes:
                        continue
                    e = self.dotted(mod, chain) if chain else None
                    if e and e[0] in ("external", "external_module"):
                        is_external = True
                if is_external:
                    ev[n.targets[0].id] = True
        return ev

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
        ev = self.ext_vars(mod).get(name)
        if ev:
            return ("extvar", True)
        return self.env(mod).get(name)

    def descend(self, m, rest):
        i = 0
        while i < len(rest) - 1 and self.is_proj_prefix(f"{m}.{rest[i]}"):
            m = f"{m}.{rest[i]}"
            i += 1
        return m, rest[i:]

    def dotted(self, mod, chain):
        head = self.lookup(mod, chain[0])
        if head is None or head[0] not in ("module", "external_module") or len(chain) < 2:
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
            if first and first[0] == "extvar":
                return ("extvar_method", rest[1])
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

    def method_targets(self, cq, name, include_self=True):
        if include_self:
            q, ext = self.lookup_method(cq, name, set())
            targets = {q} if q else set()
            for d in self.descendants(cq):
                if name in self.classes[d].methods:
                    targets.add(self.classes[d].methods[name])
            if targets:
                return targets, "ok"
            return targets, ("ext" if ext else "missing")
        else:
            seen = set()
            if cq in seen:
                return set(), False
            seen.add(cq)
            ci = self.classes[cq]
            targets = set()
            ext = ci.ext_base
            for b in self.bases(ci):
                q, e = self.lookup_method(b, name, seen)
                if q:
                    targets.add(q)
                ext = ext or e
            if targets:
                return targets, "ok"
            return targets, ("ext" if ext else "missing")

    def resolve_decorator(self, mod, dec):
        if isinstance(dec, ast.Name):
            e = self.lookup(mod, dec.id)
            if e and e[0] == "func":
                return e[1]
        elif isinstance(dec, ast.Call):
            f = dec.func
            if isinstance(f, ast.Name):
                e = self.lookup(mod, f.id)
                if e and e[0] == "func":
                    return e[1]
            elif isinstance(f, ast.Attribute):
                chain = _flatten(f)
                if chain:
                    e = self.dotted(mod, chain)
                    if e and e[0] == "func":
                        return e[1]
        elif isinstance(dec, ast.Attribute):
            chain = _flatten(dec)
            if chain:
                e = self.dotted(mod, chain)
                if e and e[0] == "func":
                    return e[1]
        return None

    # ---- per-function analysis ----

    def apply_method(self, cq, name, line, text, ctx):
        targets, status = self.method_targets(cq, name, include_self=True)
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

    def handle_super(self, c, ctx):
        f = c.func
        is_super_call = False
        name = None
        if isinstance(f, ast.Name) and f.id == "super":
            is_super_call = True
        elif isinstance(f, ast.Attribute) and f.attr == "super":
            is_super_call = True
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Call):
            inner = f.value
            if isinstance(inner.func, ast.Name) and inner.func.id == "super":
                is_super_call = True
                name = f.attr
        if not is_super_call:
            return False
        if not ctx.cq:
            return False
        if not isinstance(f, ast.Attribute):
            return False
        name = f.attr
        ci = self.classes[ctx.cq]
        line, text = c.lineno, _text(c.func)
        targets, status = self.method_targets(ctx.cq, name, include_self=False)
        if targets:
            ctx.edges |= targets
            return True
        if ci.ext_base:
            return True
        if not ci.bases and name == "__init__":
            return True
        approx_targets = set()
        for cq, ci in self.classes.items():
            if cq != ctx.cq and name in ci.methods:
                approx_targets.add(ci.methods[name])
        if approx_targets:
            ctx.approx |= approx_targets
        return True

    def call(self, c, ctx):
        f = c.func
        line, text = c.lineno, _text(c.func)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Call):
            inner = f.value
            if isinstance(inner.func, ast.Name) and inner.func.id == "super":
                if self.handle_super(c, ctx):
                    return
        if self.handle_super(c, ctx):
            return
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Call):
            inner = f.value
            if isinstance(inner.func, ast.Name) and inner.func.id == "super":
                return
        if isinstance(f, ast.Name):
            name = f.id
            if ctx.q in self.decorator_params and name in self.decorator_params[ctx.q]:
                ctx.edges |= self.decorator_map[ctx.q]
                return
            if name in ctx.locals:
                if name not in ctx.nested:
                    ctx.unresolved.append((line, text))
                return
            e = self.lookup(ctx.mod, name)
            if e is None:
                if name not in BUILTIN_NAMES:
                    self.unknown(name, line, text, ctx)
                return
            kind = e[0]
            if kind == "external":
                return
            if kind == "external_module":
                return
            if kind == "extvar":
                return
            self.apply_entry(e, name, line, text, ctx)
            return
        if not isinstance(f, ast.Attribute):
            if isinstance(f, ast.Call):
                inner = f.func
                e = None
                if isinstance(inner, ast.Name):
                    e = self.lookup(ctx.mod, inner.id)
                elif isinstance(inner, ast.Attribute):
                    chain = _flatten(inner)
                    if chain:
                        e = self.dotted(ctx.mod, chain)
                if e and e[0] == "func":
                    return
            ctx.unresolved.append((line, text))
            return
        chain = _flatten(f)
        attr = f.attr
        if chain is None or len(chain) < 2:
            self.add_approx(attr, line, text, ctx)
            return
        head = chain[0]
        if ctx.first and ctx.cq and head == ctx.first and len(chain) == 2:
            self.apply_method(ctx.cq, attr, line, text, ctx)
            return
        if ctx.q in self.decorator_params and head in self.decorator_params[ctx.q] and len(chain) == 2:
            ctx.edges |= self.decorator_map[ctx.q]
            return
        if head in ctx.locals:
            if len(chain) == 2:
                for t in ctx.types.get(head) or {None}:
                    if t is None:
                        self.add_approx(attr, line, text, ctx)
                    else:
                        self.apply_method(t, attr, line, text, ctx)
            else:
                self.add_approx(attr, line, text, ctx)
            return
        e = self.lookup(ctx.mod, head)
        if e is None:
            if head not in BUILTIN_NAMES:
                self.unknown(attr, line, text, ctx)
            return
        kind = e[0]
        if kind == "external":
            self.add_approx(attr, line, text, ctx)
            return
        if kind == "external_module":
            return
        if kind == "extvar":
            return
        if kind == "class" and len(chain) == 2:
            self.apply_method(e[1], attr, line, text, ctx)
        elif kind == "instance" and len(chain) == 2:
            for cq in e[1]:
                self.apply_method(cq, attr, line, text, ctx)
        elif kind == "module":
            ent = self.dotted(ctx.mod, chain)
            if ent is None:
                self.add_approx(attr, line, text, ctx)
            elif ent[0] == "external":
                return
            elif ent[0] != "external":
                self.apply_entry(ent, attr, line, text, ctx)
        else:
            self.add_approx(attr, line, text, ctx)

    def add_approx(self, attr, line, text, ctx):
        if attr not in self.all_methods:
            if attr in self.all_names:
                ctx.ambiguous.append((line, text))
            return
        if attr in BUILTIN_METHODS:
            ctx.ambiguous.append((line, text))
            return
        targets = set()
        for cq, ci in self.classes.items():
            if attr in ci.methods:
                targets.add(ci.methods[attr])
        if targets:
            ctx.approx |= (targets - ctx.edges)

    def analyze(self, fq, node, mi, cq, static):
        first = None
        if cq and not static:
            params = node.args.posonlyargs + node.args.args
            first = params[0].arg if params else None
        ctx = _Ctx(mi.name, cq, first, fq)
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
        g.approx[fq] = ctx.approx
        g.unresolved[fq] = ctx.unresolved
        g.ambiguous[fq] = ctx.ambiguous

    def run(self):
        self.load()
        for mi in self.mods.values():
            for q, node in mi.funcs.values():
                for dec in node.decorator_list:
                    d = self.resolve_decorator(mi.name, dec)
                    if d:
                        self.decorator_map[d].add(q)
            for ci in mi.classes.values():
                for m in ci.node.body:
                    if not isinstance(m, FUNC_NODES):
                        continue
                    for dec in m.decorator_list:
                        d = self.resolve_decorator(mi.name, dec)
                        if d:
                            self.decorator_map[d].add(ci.methods[m.name])
        for mi in self.mods.values():
            for q, node in mi.funcs.values():
                if q in self.decorator_map:
                    params = node.args.posonlyargs + node.args.args
                    if params:
                        self.decorator_params[q].add(params[0].arg)
                    for n in ast.walk(node):
                        if isinstance(n, FUNC_NODES) and n is not node:
                            params = n.args.posonlyargs + n.args.args
                            if params:
                                self.decorator_params[q].add(params[0].arg)
            for ci in mi.classes.values():
                for m in ci.node.body:
                    if not isinstance(m, FUNC_NODES):
                        continue
                    mq = ci.methods[m.name]
                    if mq in self.decorator_map:
                        params = m.args.posonlyargs + m.args.args
                        if params:
                            self.decorator_params[mq].add(params[0].arg)
                        for n in ast.walk(m):
                            if isinstance(n, FUNC_NODES) and n is not m:
                                params = n.args.posonlyargs + n.args.args
                                if params:
                                    self.decorator_params[mq].add(params[0].arg)
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
        for mi in self.mods.values():
            for q, node in mi.funcs.values():
                for dec in node.decorator_list:
                    d = self.resolve_decorator(mi.name, dec)
                    if d:
                        self.graph.edges[q].add(d)
            for ci in mi.classes.values():
                for m in ci.node.body:
                    if not isinstance(m, FUNC_NODES):
                        continue
                    for dec in m.decorator_list:
                        d = self.resolve_decorator(mi.name, dec)
                        if d:
                            self.graph.edges[ci.methods[m.name]].add(d)
        self._collect_dependency_entries()
        self._collect_route_entries()
        return self.graph

    def _get_dependency_arg(self, call):
        for kw in call.keywords:
            if kw.arg == "dependency":
                return kw.value
        if call.args:
            arg = call.args[0]
            if isinstance(arg, ast.Call):
                f = arg.func
                if isinstance(f, ast.Name) and f.id in ("Depends", "Security"):
                    if arg.args:
                        return arg.args[0]
                elif isinstance(f, ast.Attribute) and f.attr in ("Depends", "Security"):
                    if arg.args:
                        return arg.args[0]
            return arg
        return None

    def _get_endpoint_arg(self, call):
        for kw in call.keywords:
            if kw.arg == "endpoint":
                return kw.value
        if len(call.args) >= 2:
            return call.args[1]
        return None

    def _resolve_dependency_target(self, mod, node):
        if isinstance(node, ast.Name):
            e = self.lookup(mod, node.id)
        elif isinstance(node, ast.Attribute):
            chain = _flatten(node)
            if chain:
                e = self.dotted(mod, chain)
            else:
                e = None
        else:
            e = None
        if e is None:
            return None
        kind = e[0]
        if kind == "func":
            return {e[1]}
        if kind == "class":
            targets, _ = self.method_targets(e[1], "__init__")
            return targets
        if kind == "instance":
            out = set()
            for cq in e[1]:
                out |= self.method_targets(cq, "__call__")[0]
            return out
        if kind == "method":
            targets, _ = self.method_targets(e[1], e[2])
            return targets
        if kind == "imethod":
            out = set()
            for cq in e[1]:
                out |= self.method_targets(cq, e[2])[0]
            return out
        return None

    def _collect_dependency_entries(self):
        for mi in self.mods.values():
            for node in ast.walk(mi.tree):
                if isinstance(node, ast.Call):
                    f = node.func
                    is_depends = False
                    if isinstance(f, ast.Name) and f.id in ("Depends", "Security"):
                        is_depends = True
                    elif isinstance(f, ast.Attribute) and f.attr in ("Depends", "Security"):
                        is_depends = True
                    if is_depends:
                        arg = self._get_dependency_arg(node)
                        if arg is None:
                            continue
                        targets = self._resolve_dependency_target(mi.name, arg)
                        if targets:
                            for t in targets:
                                if t in self.graph.functions:
                                    self.graph.extra_entries.add(t)

    def _collect_route_entries(self):
        route_attrs = {"add_api_route", "add_api_websocket_route", "add_websocket_route", "add_route"}
        route_constructors = {"APIRoute", "APIWebSocketRoute", "Route", "WebSocketRoute"}
        for mi in self.mods.values():
            for node in ast.walk(mi.tree):
                if isinstance(node, ast.Call):
                    f = node.func
                    is_route = False
                    if isinstance(f, ast.Attribute) and f.attr in route_attrs:
                        is_route = True
                    elif isinstance(f, ast.Name) and f.id in route_constructors:
                        is_route = True
                    elif isinstance(f, ast.Attribute) and f.attr in route_constructors:
                        is_route = True
                    if is_route:
                        arg = self._get_endpoint_arg(node)
                        if arg is None:
                            continue
                        targets = self._resolve_dependency_target(mi.name, arg)
                        if targets:
                            for t in targets:
                                if t in self.graph.functions:
                                    self.graph.extra_entries.add(t)


def build_call_graph(root):
    return _Builder(root).run()
