from collections import deque
from pathlib import Path

from pathfromhttp.callgraph import build_call_graph
from pathfromhttp.entrypoints import find_entry_points


class TargetError(Exception):
    pass

def resolve_target(graph, target):
    if target in graph.functions:
        return target
    matches = sorted(q for q in graph.functions if q.endswith("." + target))
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise TargetError(f"target not found: {target}")
    raise TargetError(
        f"ambiguous target {target}; candidates: " + ", ".join(matches)
    )


def _sites(graph, visited, table):
    out = []
    for fn in sorted(visited):
        loc = graph.functions[fn].split(":")[0]
        for line, text in sorted(table.get(fn, ())):
            out.append({"function": fn, "location": f"{loc}:{line}", "call": text})
    return out


def check_reachability(root, target):
    root = Path(root)
    graph = build_call_graph(root)
    entries = sorted(e for e in find_entry_points(root) if e in graph.functions)
    tgt = resolve_target(graph, target)

    parent = {e: None for e in entries}
    queue = deque(entries)
    while queue:
        fn = queue.popleft()
        for callee in sorted(graph.edges.get(fn, ())):
            if callee not in parent:
                parent[callee] = fn
                queue.append(callee)
    visited = set(parent)

    path = None
    reason = None
    approx_hops = []
    if tgt in parent:
        verdict = "REACHABLE"
        path = []
        cur = tgt
        while cur is not None:
            path.append(cur)
            cur = parent[cur]
        path.reverse()
    else:
        parent2 = {e: None for e in entries}
        queue = deque(entries)
        while queue:
            fn = queue.popleft()
            for callee in sorted(graph.edges.get(fn, ())):
                if callee not in parent2:
                    parent2[callee] = fn
                    queue.append(callee)
            for callee in sorted(graph.approx.get(fn, ())):
                if callee not in parent2:
                    parent2[callee] = fn
                    queue.append(callee)
        visited2 = set(parent2)
        if tgt in parent2:
            verdict = "LIKELY_REACHABLE"
            path = []
            cur = tgt
            while cur is not None:
                path.append(cur)
                cur = parent2[cur]
            path.reverse()
            for i in range(len(path) - 1):
                if path[i+1] not in graph.edges.get(path[i], set()):
                    approx_hops.append([path[i], path[i+1]])
            n = len(approx_hops)
            reason = f"{n} hop(s) matched by method name only"
        elif not entries:
            verdict = "UNKNOWN"
            reason = "no HTTP entry points were detected"
        else:
            unresolved = _sites(graph, visited2, graph.unresolved)
            if unresolved:
                verdict = "UNKNOWN"
                reason = (
                    f"the search crossed {len(unresolved)} call(s) that could not be resolved"
                )
            else:
                verdict = "NOT_REACHABLE"

    final_visited = visited if verdict == "REACHABLE" else (visited2 if verdict == "LIKELY_REACHABLE" else (visited2 if verdict == "UNKNOWN" else visited))
    return {
        "target": tgt,
        "target_location": graph.functions[tgt],
        "verdict": verdict,
        "reason": reason,
        "path": path,
        "path_locations": [graph.functions[p] for p in path] if path else None,
        "entry_points": entries,
        "functions_searched": len(final_visited),
        "unresolved": _sites(graph, final_visited, graph.unresolved),
        "ambiguous": _sites(graph, final_visited, graph.ambiguous),
        "approx_hops": approx_hops,
    }


def render_text(result):
    lines = [f"Verdict: {result['verdict']}"]
    lines.append(f"Target: {result['target']} ({result['target_location']})")
    if result["reason"]:
        lines.append(f"Reason: {result['reason']}")
    if result["path"]:
        lines.append("Path:")
        for i, (q, loc) in enumerate(zip(result["path"], result["path_locations"])):
            if i == 0:
                prefix = "  "
            else:
                prev = result["path"][i-1]
                if [prev, q] in result["approx_hops"]:
                    prefix = "  ~> "
                else:
                    prefix = "  -> "
            lines.append(f"{prefix}{q} ({loc})")
        if result["approx_hops"]:
            lines.append("  (~> means matched by method name only)")
    else:
        lines.append(
            f"Searched {result['functions_searched']} function(s) reachable from "
            f"{len(result['entry_points'])} entry point(s)."
        )
    if result["verdict"] not in ("REACHABLE", "LIKELY_REACHABLE"):
        if result["unresolved"]:
            lines.append("Unresolved calls on the searched paths:")
            for u in result["unresolved"]:
                lines.append(f"  {u['location']}  {u['function']}  {u['call']}")
        if result["ambiguous"]:
            n = len(result["ambiguous"])
            lines.append(
                f"Confidence reduced: {n} ambiguous call(s) could not be ruled out:"
            )
            for u in result["ambiguous"]:
                lines.append(f"  {u['location']}  {u['function']}  {u['call']}")
    return "\n".join(lines)
