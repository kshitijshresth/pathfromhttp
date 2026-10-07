import argparse
import json
import sys
from pathlib import Path

from pathfromhttp.callgraph import build_call_graph
from pathfromhttp.entrypoints import find_entry_points
from pathfromhttp.locate import locate
from pathfromhttp.reach import TargetError, check_reachability, collect_entry_points, render_text
from pathfromhttp.triage import triage, SarifError, render_triage_text

EXIT_CODES = {"NOT_REACHABLE": 0, "REACHABLE": 1, "LIKELY_REACHABLE": 1, "UNKNOWN": 2}


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="pathfromhttp",
        description="Can this code be reached from an external HTTP endpoint?",
        epilog="exit codes for check: 0 NOT_REACHABLE, 1 REACHABLE or LIKELY_REACHABLE, 2 UNKNOWN, 3 error",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check if a target function is reachable")
    c.add_argument("repo")
    c.add_argument("--target", required=True)
    c.add_argument("--json", action="store_true", help="print machine-readable output")
    e = sub.add_parser("entrypoints", help="list detected HTTP entry points")
    e.add_argument("repo")
    g = sub.add_parser("callgraph", help="dump the call graph as JSON")
    g.add_argument("repo")
    l = sub.add_parser("locate", help="map a file:line to the function that contains it")
    l.add_argument("repo")
    l.add_argument("location")
    l.add_argument("--json", action="store_true")
    t = sub.add_parser("triage", help="reachability verdicts for the findings in a SARIF file")
    t.add_argument("repo")
    t.add_argument("sarif")
    t.add_argument("--json", action="store_true")
    t.add_argument("--fail-on-reachable", action="store_true")
    args = p.parse_args(argv)

    root = Path(args.repo)
    if not root.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 3
    if args.cmd == "entrypoints":
        graph = build_call_graph(root)
        entries = collect_entry_points(root, graph)
        print(json.dumps(entries, indent=2))
        return 0
    if args.cmd == "callgraph":
        print(json.dumps(build_call_graph(root).to_dict(), indent=2))
        return 0
    if args.cmd == "locate":
        if ":" not in args.location:
            print("error: expected <path>:<line>", file=sys.stderr)
            return 3
        parts = args.location.rsplit(":", 1)
        path = parts[0]
        try:
            line = int(parts[1])
        except ValueError:
            print("error: expected <path>:<line>", file=sys.stderr)
            return 3
        if line < 1:
            print("error: expected <path>:<line>", file=sys.stderr)
            return 3
        graph = build_call_graph(root)
        qname = locate(graph, root, path, line)
        if args.json:
            result = {
                "location": args.location,
                "file": path,
                "line": line,
                "function": qname,
                "span": graph.spans.get(qname) if qname else None,
            }
            print(json.dumps(result, indent=2))
        else:
            if qname:
                print(qname)
            else:
                print(f"no function contains {args.location}", file=sys.stderr)
        return 0 if qname else 1
    if args.cmd == "triage":
        try:
            result = triage(root, args.sarif)
        except SarifError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
        print(json.dumps(result, indent=2) if args.json else render_triage_text(result))
        if args.fail_on_reachable:
            has_reachable = any(r["verdict"] in ("REACHABLE", "LIKELY_REACHABLE") for r in result["results"])
            return 1 if has_reachable else 0
        return 0
    try:
        result = check_reachability(root, args.target)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(result, indent=2) if args.json else render_text(result))
    return EXIT_CODES[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
