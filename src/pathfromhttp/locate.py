from pathlib import Path


def locate(graph, root, path, line):
    path = path.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]
    abs_path = Path(path)
    if abs_path.is_absolute():
        resolved = abs_path.resolve()
        try:
            rel = resolved.relative_to(Path(root).resolve())
        except ValueError:
            return None
        path = rel.as_posix()
    candidates = []
    for qname, span in graph.spans.items():
        if span["file"] == path and span["start"] <= line <= span["end"]:
            size = span["end"] - span["start"]
            candidates.append((size, qname, span))
    if not candidates:
        return None
    candidates.sort()
    return candidates[0][1]
