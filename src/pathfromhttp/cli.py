import argparse
import json
import sys
from pathlib import Path

from pathfromhttp.callgraph import build_call_graph
from pathfromhttp.entrypoints import find_entry_points


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="pathfromhttp",
        description="Can this code be reached from an external HTTP endpoint?",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check if a target function is reachable")
    c.add_argument("repo")
    c.add_argument("--target", required=True)
    e = sub.add_parser("entrypoints", help="list detected HTTP entry points")
    e.add_argument("repo")
    g = sub.add_parser("callgraph", help="dump the call graph as JSON")
    g.add_argument("repo")
    args = p.parse_args(argv)
    if args.cmd == "entrypoints":
        print(json.dumps(find_entry_points(Path(args.repo)), indent=2))
        return 0
    if args.cmd == "callgraph":
        print(json.dumps(build_call_graph(Path(args.repo)).to_dict(), indent=2))
        return 0
    print("not implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
