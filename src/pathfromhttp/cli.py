import argparse
import sys


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="pathfromhttp",
        description="Can this code be reached from an external HTTP endpoint?",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check if a target function is reachable")
    c.add_argument("repo")
    c.add_argument("--target", required=True)
    p.parse_args(argv)
    print("not implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
