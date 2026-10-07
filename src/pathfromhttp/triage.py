import json
import urllib.parse
from pathlib import Path

from pathfromhttp.locate import locate
from pathfromhttp.reach import analyze, verdict_for


class SarifError(Exception):
    pass


def _normalize_uri(uri):
    uri = urllib.parse.unquote(uri)
    if uri.startswith("file://"):
        path = uri[7:]
        if len(path) >= 3 and path[0] == "/" and path[2] == ":" and path[1].isalpha():
            path = path[1:]
        uri = path
    uri = uri.replace("\\", "/")
    return uri


def _read_sarif(sarif_path):
    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise SarifError(f"cannot read SARIF file: {e}")
    if not isinstance(data, dict):
        raise SarifError("not a SARIF file: not a JSON object")
    if "runs" not in data:
        raise SarifError("not a SARIF file: missing 'runs' key")
    runs = data["runs"]
    if not isinstance(runs, list):
        raise SarifError("not a SARIF file: 'runs' is not a list")
    return runs


def _extract_result(result):
    rule_id = result.get("ruleId")
    if not rule_id:
        rule = result.get("rule", {})
        if isinstance(rule, dict):
            rule_id = rule.get("id")
    if not rule_id:
        rule_id = "unknown"
    message = ""
    if "message" in result:
        msg = result["message"]
        if isinstance(msg, dict):
            message = msg.get("text", "")
    level = result.get("level", "warning")
    locations = result.get("locations", [])
    if not locations:
        return {
            "rule_id": rule_id,
            "message": message,
            "level": level,
            "file": None,
            "line": None,
            "unlocated": True,
            "unlocated_reason": "no usable location in the result",
        }
    loc = locations[0]
    phys = loc.get("physicalLocation", {})
    art = phys.get("artifactLocation", {})
    uri = art.get("uri")
    region = phys.get("region", {})
    line = region.get("startLine")
    if not uri or not line or not isinstance(line, int) or line < 1:
        return {
            "rule_id": rule_id,
            "message": message,
            "level": level,
            "file": uri,
            "line": line,
            "unlocated": True,
            "unlocated_reason": "no usable location in the result",
        }
    file = _normalize_uri(uri)
    return {
        "rule_id": rule_id,
        "message": message,
        "level": level,
        "file": file,
        "line": line,
        "unlocated": False,
    }


def triage(root, sarif_path):
    root = Path(root)
    sarif_path = Path(sarif_path)
    runs = _read_sarif(sarif_path)
    analysis = analyze(root)
    graph = analysis["graph"]

    results = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            extracted = _extract_result(result)
            if extracted["unlocated"]:
                results.append({
                    "rule_id": extracted["rule_id"],
                    "message": extracted["message"],
                    "level": extracted["level"],
                    "file": extracted["file"],
                    "line": extracted["line"],
                    "function": None,
                    "verdict": "UNLOCATED",
                    "reason": extracted["unlocated_reason"],
                    "path": None,
                    "path_locations": None,
                    "approx_hops": [],
                })
                continue
            file = extracted["file"]
            line = extracted["line"]
            qname = locate(graph, root, file, line)
            if qname is None:
                results.append({
                    "rule_id": extracted["rule_id"],
                    "message": extracted["message"],
                    "level": extracted["level"],
                    "file": file,
                    "line": line,
                    "function": None,
                    "verdict": "UNLOCATED",
                    "reason": "no analyzed function contains this location",
                    "path": None,
                    "path_locations": None,
                    "approx_hops": [],
                })
                continue
            verdict = verdict_for(analysis, qname)
            results.append({
                "rule_id": extracted["rule_id"],
                "message": extracted["message"],
                "level": extracted["level"],
                "file": file,
                "line": line,
                "function": qname,
                "verdict": verdict["verdict"],
                "reason": verdict["reason"] if verdict["verdict"] not in ("REACHABLE", "NOT_REACHABLE") else None,
                "path": verdict["path"],
                "path_locations": verdict["path_locations"],
                "approx_hops": verdict["approx_hops"],
            })

    summary = {
        "total": len(results),
        "REACHABLE": 0,
        "LIKELY_REACHABLE": 0,
        "NOT_REACHABLE": 0,
        "UNKNOWN": 0,
        "UNLOCATED": 0,
    }
    for r in results:
        summary[r["verdict"]] += 1

    return {
        "root": str(root),
        "sarif": str(sarif_path),
        "summary": summary,
        "results": results,
        "unresolved": analysis["unresolved"],
        "skipped_files": analysis["skipped_files"],
    }


def render_triage_text(result):
    lines = [f"Triage: {result['summary']['total']} finding(s)"]
    lines.append(f"  REACHABLE: {result['summary']['REACHABLE']}")
    lines.append(f"  LIKELY_REACHABLE: {result['summary']['LIKELY_REACHABLE']}")
    lines.append(f"  NOT_REACHABLE: {result['summary']['NOT_REACHABLE']}")
    lines.append(f"  UNKNOWN: {result['summary']['UNKNOWN']}")
    lines.append(f"  UNLOCATED: {result['summary']['UNLOCATED']}")
    lines.append("")
    for r in result["results"]:
        file_line = f"{r['file']}:{r['line']}" if r["file"] is not None and r["line"] is not None else "-"
        function = r["function"] if r["function"] is not None else "-"
        lines.append(f"[{r['verdict']}] {r['rule_id']}  {file_line}  {function}")
        if r["path"]:
            path_str = " -> ".join(r["path"])
            for src, dst in r["approx_hops"]:
                path_str = path_str.replace(f"{src} -> {dst}", f"{src} ~> {dst}")
            lines.append(f"  path: {path_str}")
        if r["reason"]:
            lines.append(f"  reason: {r['reason']}")
        lines.append("")
    return "\n".join(lines)
