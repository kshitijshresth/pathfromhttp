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


def collect_entry_points(root, graph):
    base = set(find_entry_points(root))
    base.update(graph.extra_entries)
    return sorted(e for e in base if e in graph.functions)


def analyze(root):
    root = Path(root)
    graph = build_call_graph(root)
    entries = collect_entry_points(root, graph)

    parent_precise = {e: None for e in entries}
    queue = deque(entries)
    while queue:
        fn = queue.popleft()
        for callee in sorted(graph.edges.get(fn, ())):
            if callee not in parent_precise:
                parent_precise[callee] = fn
                queue.append(callee)
    visited_precise = set(parent_precise)

    parent_loose = {e: None for e in entries}
    queue = deque(entries)
    while queue:
        fn = queue.popleft()
        for callee in sorted(graph.edges.get(fn, ())):
            if callee not in parent_loose:
                parent_loose[callee] = fn
                queue.append(callee)
        for callee in sorted(graph.approx.get(fn, ())):
            if callee not in parent_loose:
                parent_loose[callee] = fn
                queue.append(callee)
    visited_loose = set(parent_loose)

    return {
        "graph": graph,
        "entries": entries,
        "parent_precise": parent_precise,
        "parent_loose": parent_loose,
        "visited": visited_precise,
        "visited_loose": visited_loose,
        "unresolved": _sites(graph, visited_loose, graph.unresolved),
        "ambiguous": _sites(graph, visited_loose, graph.ambiguous),
        "skipped_files": graph.skipped_files,
    }


def verdict_for(analysis, target):
    graph = analysis["graph"]
    entries = analysis["entries"]
    parent_precise = analysis["parent_precise"]
    parent_loose = analysis["parent_loose"]
    visited_precise = analysis["visited"]
    visited_loose = analysis["visited_loose"]
    unresolved = analysis["unresolved"]
    ambiguous = analysis["ambiguous"]
    skipped_files = analysis["skipped_files"]

    path = None
    reason = None
    approx_hops = []
    if target in parent_precise:
        verdict = "REACHABLE"
        path = []
        cur = target
        while cur is not None:
            path.append(cur)
            cur = parent_precise[cur]
        path.reverse()
    else:
        if target in parent_loose:
            verdict = "LIKELY_REACHABLE"
            path = []
            cur = target
            while cur is not None:
                path.append(cur)
                cur = parent_loose[cur]
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
            if unresolved:
                verdict = "UNKNOWN"
                reason = (
                    f"the search crossed {len(unresolved)} call(s) that could not be resolved"
                )
            else:
                verdict = "NOT_REACHABLE"
        if verdict == "NOT_REACHABLE" and skipped_files:
            verdict = "UNKNOWN"
            reason = f"{len(skipped_files)} file(s) could not be parsed"

    final_visited = visited_precise if verdict == "REACHABLE" else (visited_loose if verdict == "LIKELY_REACHABLE" else (visited_loose if verdict == "UNKNOWN" else visited_precise))
    return {
        "target": target,
        "target_location": graph.functions[target],
        "verdict": verdict,
        "reason": reason,
        "path": path,
        "path_locations": [graph.functions[p] for p in path] if path else None,
        "entry_points": entries,
        "functions_searched": len(final_visited),
        "unresolved": _sites(graph, final_visited, graph.unresolved),
        "ambiguous": _sites(graph, final_visited, graph.ambiguous),
        "approx_hops": approx_hops,
        "skipped_files": skipped_files,
    }


def check_reachability(root, target):
    analysis = analyze(root)
    tgt = resolve_target(analysis["graph"], target)
    return verdict_for(analysis, tgt)


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
        if result["skipped_files"]:
            lines.append("Files that could not be parsed (not analyzed):")
            for f in result["skipped_files"][:10]:
                lines.append(f"  {f}")
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
