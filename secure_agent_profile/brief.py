from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Brief:
    task_id: str
    title: str
    allowed_paths: list[str]
    protected_paths: list[str]
    network_mode: str
    verifiers: list[str]
    body: str


def parse_brief(path: Path) -> Brief:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError("brief must start with YAML-like front matter")
    _, raw_front, body = text.split("---", 2)
    data = _parse_front_matter(raw_front)
    repo_scope = data.get("repo_scope", {})
    network = data.get("network", {})
    raw_verifiers = data.get("verifiers", [])
    verifiers = [str(item["command"]) for item in raw_verifiers if isinstance(item, dict) and "command" in item] if isinstance(raw_verifiers, list) else []
    return Brief(
        task_id=str(data.get("task_id") or path.stem),
        title=str(data.get("title") or path.stem),
        allowed_paths=list(repo_scope.get("allowed_paths", [])),
        protected_paths=list(repo_scope.get("protected_paths", [])),
        network_mode=str(network.get("mode") or "deny"),
        verifiers=verifiers,
        body=body.strip(),
    )


def _parse_front_matter(raw: str) -> dict[str, object]:
    root: dict[str, object] = {}
    stack: list[tuple[int, object]] = [(-1, root)]
    last_key: dict[int, str] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if stripped.startswith("- "):
            value = stripped[2:]
            if isinstance(parent, list):
                if ": " in value:
                    key, raw_value = value.split(": ", 1)
                    item = {key: _scalar(raw_value)}
                    parent.append(item)
                    stack.append((indent, item))
                else:
                    parent.append(_scalar(value))
            continue
        key, sep, raw_value = stripped.partition(":")
        if not sep:
            continue
        key = key.strip()
        if raw_value.strip():
            if isinstance(parent, dict):
                parent[key] = _scalar(raw_value.strip())
        else:
            container: object = [] if _next_nonempty_starts_list(raw, line) else {}
            if isinstance(parent, dict):
                parent[key] = container
            last_key[indent] = key
            stack.append((indent, container))
    return root


def _next_nonempty_starts_list(raw: str, current: str) -> bool:
    lines = raw.splitlines()
    try:
        idx = lines.index(current)
    except ValueError:
        return False
    for line in lines[idx + 1 :]:
        if line.strip():
            return line.strip().startswith("- ")
    return False


def _scalar(value: str) -> object:
    value = value.strip().strip('"').strip("'")
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value
