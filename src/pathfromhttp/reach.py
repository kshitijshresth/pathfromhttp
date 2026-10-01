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

    unresolved = _sites(graph, visited, graph.unresolved)
    ambiguous = _sites(graph, visited, graph.ambiguous)

    path = None
    reason = None
    if tgt in parent:
        verdict = "REACHABLE"
        path = []
        cur = tgt
        while cur is not None:
            path.append(cur)
            cur = parent[cur]
        path.reverse()
    elif not entries:
        verdict = "UNKNOWN"
        reason = "no HTTP entry points were detected"
    elif unresolved:
        verdict = "UNKNOWN"
        reason = (
            f"the search crossed {len(unresolved)} call(s) that could not be resolved"
        )
    else:
        verdict = "NOT_REACHABLE"

    return {
        "target": tgt,
        "target_location": graph.functions[tgt],
        "verdict": verdict,
        "reason": reason,
        "path": path,
        "path_locations": [graph.functions[p] for p in path] if path else None,
        "entry_points": entries,
        "functions_searched": len(visited),
        "unresolved": unresolved,
        "ambiguous": ambiguous,
    }


def render_text(result):
    lines = [f"Verdict: {result['verdict']}"]
    lines.append(f"Target: {result['target']} ({result['target_location']})")
    if result["reason"]:
        lines.append(f"Reason: {result['reason']}")
    if result["path"]:
        lines.append("Path:")
        for i, (q, loc) in enumerate(zip(result["path"], result["path_locations"])):
            prefix = "  " if i == 0 else "  -> "
            lines.append(f"{prefix}{q} ({loc})")
    else:
        lines.append(
            f"Searched {result['functions_searched']} function(s) reachable from "
            f"{len(result['entry_points'])} entry point(s)."
        )
    if result["verdict"] != "REACHABLE":
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
