# pathfromhttp

Can this code be reached from an external HTTP endpoint?

pathfromhttp answers that question with static analysis. It finds the functions a web framework invokes when an HTTP request arrives (entry points), builds a call graph of your project, and searches for a path from any entry point to a target function. When it finds one, it prints the exact call chain as evidence.

## Install

Requires Python 3.9 or newer.

```
git clone <this repository>
cd pathfromhttp
python -m pip install -e .
```

## Usage

```
pathfromhttp check <repo> --target <function>
pathfromhttp entrypoints <repo>
pathfromhttp callgraph <repo>
```

`--target` takes a qualified name such as `app.models.User.verify_password`. A unique suffix such as `verify_password` also works. Add `--json` to `check` for machine-readable output.

Example:

```
$ pathfromhttp check tests/fixtures/multi_module --target util.vuln
Verdict: REACHABLE
Target: util.vuln (util.py:1)
Path:
  app.index (app.py:9)
  -> helpers.process (helpers.py:4)
  -> util.vuln (util.py:1)
```

## Verdicts

| Verdict | Meaning |
|---|---|
| REACHABLE | A path exists using only calls that were resolved precisely. The path is printed. |
| LIKELY_REACHABLE | A path exists, but at least one hop was matched by method name only because the receiver type is unknown. Hops marked `~>` are those. This can be a false positive. |
| NOT_REACHABLE | The search finished without crossing any call it could not resolve. |
| UNKNOWN | The search crossed a call it could not resolve (for example a call through a variable), or no entry points were detected, so absence cannot be proven. |

UNKNOWN is a deliberate answer: the tool never turns "I could not see" into "no".

Exit codes for `check`: 0 NOT_REACHABLE, 1 REACHABLE or LIKELY_REACHABLE, 2 UNKNOWN, 3 error.

## What it recognizes

Entry points (Python, Flask family):

- `@app.route`, `@bp.route`, and `get`/`post`/`put`/`delete`/`patch` shortcuts on Flask or Blueprint objects
- `add_url_rule`, including `view_func=Cls.as_view(...)`
- class-based handlers decorated with `X.route(...)` and `X.add_resource(Cls, ...)` (verb methods are the entry points)
- request hooks such as `before_request`, `after_request`, `teardown_appcontext`, `errorhandler`, in decorator form and call form

Call graph: imports (absolute, relative, aliased, re-exported), methods and `self` calls, inheritance and overrides, `super()`, constructors, local and module-level instances, decorators and the functions they wrap, functions passed as callbacks. Test directories and test files are skipped.

## Evaluation

Checked against 13 hand-verified targets in three open-source Flask apps (the Flask tutorial app, microblog, Flasky): 12 gave the correct answer (REACHABLE, LIKELY_REACHABLE or NOT_REACHABLE as appropriate), 1 returned UNKNOWN because its search path contains a genuinely dynamic call, and none were confidently wrong. This is a small sample and says little about other codebases.

## Limitations

- Python and the Flask family only. FastAPI and Django are not supported yet.
- Static analysis only: routes registered at runtime, configuration, feature flags and reverse-proxy rules are not seen.
- Calls through variables, reflection (`getattr`) and registries cannot be resolved and produce UNKNOWN when they are on the searched paths.
- Dispatch that goes through data rather than calls (task queues referenced by name, signals, ORM event listeners) is not modeled.
- Name-matched hops (LIKELY_REACHABLE) can be false positives.
- A call on an untyped value whose method name is also a method name of a builtin type (`get`, `update`, `pop`, ...) is reported as ambiguous and does not block NOT_REACHABLE, so NOT_REACHABLE results list those calls as reduced confidence.
- Class-based handlers are only detected when the registration is in the same file as the class.
- Module-level code that runs at import time is ignored.

## Development

```
python -m pip install pytest
python -m pytest
```

Fixtures in `tests/fixtures` each carry an `expected.json` with the correct verdict and path.