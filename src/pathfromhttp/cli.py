import argparse
import json
import sys
from pathlib import Path

from pathfromhttp.callgraph import build_call_graph
from pathfromhttp.entrypoints import find_entry_points
from pathfromhttp.reach import TargetError, check_reachability, render_text

EXIT_CODES = {"NOT_REACHABLE": 0, "REACHABLE": 1, "UNKNOWN": 2}


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="pathfromhttp",
        description="Can this code be reached from an external HTTP endpoint?",
        epilog="exit codes for check: 0 NOT_REACHABLE, 1 REACHABLE, 2 UNKNOWN, 3 error",
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
    args = p.parse_args(argv)

    root = Path(args.repo)
    if not root.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 3
    if args.cmd == "entrypoints":
        print(json.dumps(find_entry_points(root), indent=2))
        return 0
    if args.cmd == "callgraph":
        print(json.dumps(build_call_graph(root).to_dict(), indent=2))
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
