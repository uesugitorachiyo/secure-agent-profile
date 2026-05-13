from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]

ROLE_DEPS = {
    "guarded-code-change": {
        "intake": [],
        "repo-scan": ["intake"],
        "scope-classify": ["repo-scan"],
        "risk-classify": ["scope-classify"],
        "guarded-plan": ["risk-classify"],
        "implementation": ["guarded-plan"],
        "verifier-run": ["implementation"],
        "security-review": ["verifier-run"],
        "closure": ["security-review"],
        "evidence-pack-export": ["closure"],
        "verify-pack": ["evidence-pack-export"],
    },
    "dependency-review": {
        "intake": [],
        "manifest-discovery": ["intake"],
        "dependency-diff": ["manifest-discovery"],
        "package-risk-classify": ["dependency-diff"],
        "lockfile-check": ["package-risk-classify"],
        "dependency-review-report": ["lockfile-check"],
        "evidence-pack-export": ["dependency-review-report"],
        "verify-pack": ["evidence-pack-export"],
    },
    "pr-evidence": {
        "intake": [],
        "diff-collect": ["intake"],
        "changed-file-classify": ["diff-collect"],
        "test-discovery": ["changed-file-classify"],
        "risk-report": ["test-discovery"],
        "review-summary": ["risk-report"],
        "evidence-pack-export": ["review-summary"],
        "verify-pack": ["evidence-pack-export"],
    },
}

HOST_TAGS = {
    "intake": ["repo-safe"],
    "repo-scan": ["repo-safe"],
    "scope-classify": ["repo-safe"],
    "risk-classify": ["repo-safe"],
    "guarded-plan": ["live-codex"],
    "implementation": ["live-codex"],
    "verifier-run": ["repo-safe"],
    "security-review": ["repo-safe"],
    "closure": ["repo-safe"],
    "evidence-pack-export": ["repo-safe"],
    "verify-pack": ["repo-safe"],
    "manifest-discovery": ["repo-safe"],
    "dependency-diff": ["repo-safe"],
    "package-risk-classify": ["repo-safe"],
    "lockfile-check": ["repo-safe"],
    "dependency-review-report": ["repo-safe"],
    "diff-collect": ["repo-safe"],
    "changed-file-classify": ["repo-safe"],
    "test-discovery": ["repo-safe"],
    "risk-report": ["repo-safe"],
    "review-summary": ["repo-safe"],
}


def materialize_runspec(workflow: str, *, run_id: str, brief: Path, repo: Path, run_dir: Path, fake_adapter: bool = True) -> dict[str, Any]:
    if workflow not in ROLE_DEPS:
        raise ValueError(f"unsupported workflow: {workflow}")
    tasks = []
    for role, deps in ROLE_DEPS[workflow].items():
        tasks.append(
            {
                "id": role,
                "kind": "shell",
                "deps": deps,
                "hostTags": HOST_TAGS[role],
                "spec": {
                    "command": _command(workflow=workflow, role=role, run_id=run_id, brief=brief, repo=repo, run_dir=run_dir, fake_adapter=fake_adapter)
                },
            }
        )
    return {
        "apiVersion": "ao.dev/v1",
        "kind": "Run",
        "metadata": {"name": _safe(run_id), "profile": f"secure-agent:{workflow}"},
        "spec": {
            "workspace": {"source": str(repo), "mode": "temp-copy", "apply_to_source": False},
            "policy": {"profile": "policy/secure-agent.policy.yaml", "default": "deny"},
            "evidence": {"required": True, "pack_template": "secure-agent", "verify_after_export": True},
            "tasks": tasks,
        },
    }


def render_runspec_yaml(runspec: dict[str, Any]) -> str:
    lines = [
        f"apiVersion: {runspec['apiVersion']}",
        f"kind: {runspec['kind']}",
        "metadata:",
        f"  name: \"{runspec['metadata']['name']}\"",
        f"  profile: \"{runspec['metadata']['profile']}\"",
        "spec:",
        "  workspace:",
        f"    source: \"{runspec['spec']['workspace']['source']}\"",
        "    mode: \"temp-copy\"",
        "    apply_to_source: false",
        "  policy:",
        "    profile: \"policy/secure-agent.policy.yaml\"",
        "    default: \"deny\"",
        "  evidence:",
        "    required: true",
        "    pack_template: \"secure-agent\"",
        "    verify_after_export: true",
        "  tasks:",
    ]
    for task in runspec["spec"]["tasks"]:
        lines.extend(
            [
                f"    - id: {task['id']}",
                "      kind: shell",
                "      hostTags: " + _yaml_list(task["hostTags"]),
                "      deps: " + _yaml_list(task["deps"]),
                "      spec:",
                f"        command: {shlex.quote(task['spec']['command'])}",
            ]
        )
    return "\n".join(lines) + "\n"


def write_runspec(path: Path, runspec: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_runspec_yaml(runspec), encoding="utf-8")
    return path


def _command(*, workflow: str, role: str, run_id: str, brief: Path, repo: Path, run_dir: Path, fake_adapter: bool) -> str:
    parts = [
        sys.executable,
        "-m",
        "secure_agent_profile.ao_tasks",
        "--workflow",
        workflow,
        "--role",
        role,
        "--run-id",
        run_id,
        "--brief",
        str(brief),
        "--repo",
        str(repo),
        "--run-dir",
        str(run_dir),
    ]
    if fake_adapter:
        parts.append("--fake-adapter")
    return f"PYTHONPATH={shlex.quote(str(PROJECT_ROOT))} " + " ".join(shlex.quote(part) for part in parts)


def _yaml_list(values: list[str]) -> str:
    return "[" + ", ".join(f'"{value}"' for value in values) + "]"


def _safe(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-." else "-" for ch in value).strip("-")
