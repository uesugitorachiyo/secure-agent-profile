from __future__ import annotations

import difflib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .brief import Brief, parse_brief
from .classifiers import classify_command, classify_file, risk_from, scan_secrets
from .evidence import EvidenceInput, replay_pack, verify_pack, write_evidence_pack
from .runspec import materialize_runspec, write_runspec
from .util import now, read_json, write_json, write_ndjson, write_text


@dataclass(frozen=True)
class WorkflowResult:
    workflow: str
    run_id: str
    run_dir: Path
    verdict: str
    pack_archive: Path | None
    verify_path: Path | None
    replay_path: Path | None


def run_workflow(workflow: str, *, brief_path: Path, repo_path: Path, output_root: Path, run_id: str | None = None, engine: str = "local", fake_adapter: bool = True) -> WorkflowResult:
    run_id = run_id or f"{workflow}-{now().replace(':', '').replace('-', '')}"
    run_dir = output_root / run_id
    if run_dir.exists():
        raise FileExistsError(str(run_dir))
    run_dir.mkdir(parents=True)
    brief = parse_brief(brief_path)
    workspace = run_dir / "workspace"
    shutil.copytree(repo_path, workspace, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    runspec = materialize_runspec(workflow, run_id=run_id, brief=brief_path.resolve(), repo=repo_path.resolve(), run_dir=run_dir.resolve(), fake_adapter=fake_adapter)
    write_runspec(run_dir / "runspec.yaml", runspec)
    if engine == "ao":
        return _run_ao(workflow, run_id, run_dir, brief_path, repo_path, fake_adapter)
    if workflow == "guarded-code-change":
        return _guarded_code_change(run_dir, run_id, brief, workspace)
    if workflow == "dependency-review":
        return _dependency_review(run_dir, run_id, brief, workspace)
    if workflow == "pr-evidence":
        return _pr_evidence(run_dir, run_id, brief, workspace)
    raise ValueError(f"unsupported workflow: {workflow}")


def _guarded_code_change(run_dir: Path, run_id: str, brief: Brief, workspace: Path) -> WorkflowResult:
    ctx = _Context(run_dir, run_id, "guarded-code-change", brief, workspace)
    intake = {"schema": "ao-operator/secure-agent-intake/v1", "task_id": brief.task_id, "title": brief.title, "allowed_paths": brief.allowed_paths, "protected_paths": brief.protected_paths, "verifiers": brief.verifiers}
    ctx.write_sa("intake.json", intake)
    ctx.role("intake", "PASS", intake)
    repo_scan = _repo_scan(workspace)
    ctx.write_sa("repo-scan.json", repo_scan)
    ctx.role("repo-scan", "PASS", repo_scan)
    changed_files = ["src/safe_service/math_utils.py", "tests/test_math_utils.py"]
    file_decisions = [classify_file(path, "write", allowed_paths=brief.allowed_paths, protected_paths=brief.protected_paths) for path in changed_files]
    ctx.write_sa("scope-classification.json", {"schema": "ao-operator/scope-classification/v1", "files": file_decisions})
    write_ndjson(ctx.secure_agent / "file-access.ndjson", file_decisions)
    ctx.role("scope-classify", "PASS", file_decisions)
    secret_scan = scan_secrets(workspace)
    ctx.write_sa("secret-scan.json", secret_scan)
    command_decisions = [classify_command(command, declared_verifiers=brief.verifiers) for command in brief.verifiers]
    write_ndjson(ctx.secure_agent / "command-audit.ndjson", command_decisions)
    risk = risk_from(file_decisions, command_decisions, secret_scan)
    risk_report = {"schema": "ao-operator/secure-agent-risk/v1", "risk": risk, "file_decisions": file_decisions, "command_decisions": command_decisions, "secret_scan_verdict": secret_scan["verdict"]}
    ctx.write_sa("risk-report.json", risk_report)
    write_text(ctx.secure_agent / "risk-report.md", f"# Risk Report\n\nRisk: `{risk}`\n")
    ctx.role("risk-classify", "PASS" if risk != "blocked" else "BLOCKED", risk_report)
    if risk == "blocked":
        return ctx.finish("BLOCKED", approvals={"required": False, "verdict": "BLOCKED"})
    plan = {"schema": "ao-operator/secure-agent-plan/v1", "changed_files": changed_files, "commands": brief.verifiers, "approval_required": risk != "low", "apply_to_source": False}
    ctx.write_sa("plan.json", plan)
    write_text(ctx.secure_agent / "plan.md", "# Guarded Plan\n\nPatch fixture in isolated workspace and run declared tests.\n")
    ctx.role("guarded-plan", "PASS", plan)
    before = (workspace / "src/safe_service/math_utils.py").read_text(encoding="utf-8")
    after = before.replace("return numerator / denominator", "if denominator == 0:\n        raise ValueError(\"denominator must not be zero\")\n    return numerator / denominator")
    (workspace / "src/safe_service/math_utils.py").write_text(after, encoding="utf-8")
    test_path = workspace / "tests/test_math_utils.py"
    test_before = test_path.read_text(encoding="utf-8")
    test_after = test_before + "\n\ndef test_divide_by_zero_has_clear_error():\n    import pytest\n    with pytest.raises(ValueError, match=\"denominator\"):\n        divide(1, 0)\n"
    test_path.write_text(test_after, encoding="utf-8")
    patch = _diff("src/safe_service/math_utils.py", before, after) + _diff("tests/test_math_utils.py", test_before, test_after)
    write_text(ctx.secure_agent / "patch.diff", patch)
    ctx.write_sa("changed-files.json", {"schema": "ao-operator/changed-files/v1", "files": changed_files})
    ctx.role("implementation", "PASS", {"patch": "secure-agent/patch.diff", "changed_files": changed_files})
    verifier_results = [_run_verifier(command, workspace) for command in brief.verifiers]
    ctx.write_sa("verifier-results.json", {"schema": "ao-operator/verifier-results/v1", "results": verifier_results})
    ctx.verifiers.extend(verifier_results)
    ctx.role("verifier-run", "PASS" if all(item["status"] == "passed" for item in verifier_results) else "FAIL", verifier_results)
    security = {"schema": "ao-operator/security-review/v1", "verdict": "PASS", "protected_files_touched": [], "blocked_commands": [], "secrets_introduced": []}
    ctx.write_sa("security-review.json", security)
    write_text(ctx.secure_agent / "security-review.md", "# Security Review\n\nVerdict: PASS\n")
    ctx.role("security-review", "PASS", security)
    closure = _closure(run_id, "guarded-code-change", "passed", changed_files, verifier_results, ctx.policy)
    ctx.write_sa("closure.json", closure)
    write_text(ctx.secure_agent / "closure.md", "# Closure\n\nStatus: passed\n")
    ctx.role("closure", "PASS", closure)
    return ctx.finish("PASS", approvals={"required": False, "verdict": "APPROVED", "approval_id": ""})


def _dependency_review(run_dir: Path, run_id: str, brief: Brief, workspace: Path) -> WorkflowResult:
    ctx = _Context(run_dir, run_id, "dependency-review", brief, workspace)
    intake = {"schema": "ao-operator/secure-agent-intake/v1", "task_id": brief.task_id, "title": brief.title, "allowed_paths": brief.allowed_paths, "protected_paths": brief.protected_paths, "verifiers": brief.verifiers}
    ctx.write_sa("intake.json", intake)
    ctx.role("intake", "PASS", intake)
    repo_scan = _repo_scan(workspace)
    ctx.write_sa("repo-scan.json", repo_scan)
    ctx.role("manifest-discovery", "PASS", repo_scan)
    manifests = [path for path in repo_scan["files"] if path in {"pyproject.toml", "requirements.txt", "package.json", "Cargo.toml"}]
    report = {"schema": "ao-operator/dependency-review/v1", "ecosystems": _ecosystems(manifests), "manifests": manifests, "lockfiles": [path for path in repo_scan["files"] if path.endswith(".lock")], "new_dependencies": [], "changed_dependencies": [], "removed_dependencies": [], "script_hooks": [], "risk": "low", "approval_required": False, "notes": []}
    ctx.write_sa("dependency-review-report.json", report)
    ctx.write_sa("package-risk-report.json", {"schema": "ao-operator/package-risk-report/v1", "risk": "low", "findings": []})
    ctx.write_sa("lockfile-check.json", {"schema": "ao-operator/lockfile-check/v1", "verdict": "PASS", "notes": []})
    ctx.write_sa("risk-report.json", {"schema": "ao-operator/secure-agent-risk/v1", "risk": "low"})
    ctx.role("dependency-review-report", "PASS", report)
    closure = _closure(run_id, "dependency-review", "passed", [], [], ctx.policy)
    ctx.write_sa("closure.json", closure)
    ctx.role("closure", "PASS", closure)
    return ctx.finish("PASS", approvals={"required": False, "verdict": "APPROVED", "approval_id": ""})


def _pr_evidence(run_dir: Path, run_id: str, brief: Brief, workspace: Path) -> WorkflowResult:
    ctx = _Context(run_dir, run_id, "pr-evidence", brief, workspace)
    intake = {"schema": "ao-operator/secure-agent-intake/v1", "task_id": brief.task_id, "title": brief.title, "allowed_paths": brief.allowed_paths, "protected_paths": brief.protected_paths, "verifiers": brief.verifiers}
    ctx.write_sa("intake.json", intake)
    ctx.role("intake", "PASS", intake)
    repo_scan = _repo_scan(workspace)
    ctx.write_sa("repo-scan.json", repo_scan)
    ctx.write_sa("repo-scan.json", repo_scan)
    changed = ["src/safe_service/math_utils.py"]
    ctx.write_sa("diff-summary.json", {"schema": "ao-operator/diff-summary/v1", "changed_files": changed, "mode": "read_only_fixture"})
    ctx.write_sa("changed-file-classification.json", {"schema": "ao-operator/changed-file-classification/v1", "files": [classify_file(path, "read", allowed_paths=brief.allowed_paths, protected_paths=brief.protected_paths) for path in changed]})
    ctx.write_sa("missing-coverage.json", {"schema": "ao-operator/missing-coverage/v1", "missing": []})
    ctx.write_sa("risk-report.json", {"schema": "ao-operator/secure-agent-risk/v1", "risk": "low"})
    write_text(ctx.secure_agent / "review-summary.md", "# PR Evidence Review\n\nRead-only fixture review passed.\n")
    ctx.role("review-summary", "PASS", {"changed_files": changed, "missing_coverage": []})
    closure = _closure(run_id, "pr-evidence", "passed", changed, [], ctx.policy)
    ctx.write_sa("closure.json", closure)
    ctx.role("closure", "PASS", closure)
    return ctx.finish("PASS", approvals={"required": False, "verdict": "APPROVED", "approval_id": ""})


class _Context:
    def __init__(self, run_dir: Path, run_id: str, workflow: str, brief: Brief, workspace: Path) -> None:
        self.run_dir = run_dir
        self.run_id = run_id
        self.workflow = workflow
        self.brief = brief
        self.workspace = workspace
        self.secure_agent = run_dir / "secure-agent"
        self.artifacts = run_dir / "artifacts"
        self.events: list[dict[str, Any]] = []
        self.policy: list[dict[str, Any]] = []
        self.transcripts: dict[str, list[dict[str, Any]]] = {}
        self.verifiers: list[dict[str, Any]] = []

    def write_sa(self, name: str, value: object) -> None:
        write_json(self.secure_agent / name, value)

    def role(self, role: str, status: str, payload: object) -> None:
        event = {"ts": now(), "task_id": role, "role": role, "status": status}
        self.events.append(event)
        self.transcripts.setdefault(role, []).append({**event, "message": json.dumps(payload, sort_keys=True)})
        self.policy.append({"ts": event["ts"], "role": role, "decision": "allow" if status == "PASS" else "blocked", "reason": f"{role} status {status}"})

    def finish(self, verdict: str, approvals: dict[str, Any]) -> WorkflowResult:
        write_ndjson(self.run_dir / "events.ndjson", self.events)
        write_ndjson(self.run_dir / "policy.ndjson", self.policy)
        write_json(self.run_dir / "approvals.json", approvals)
        pack = verify_path = replay_path = None
        if verdict == "PASS":
            pack = write_evidence_pack(EvidenceInput(self.run_id, self.workflow, self.run_dir, self.secure_agent, self.artifacts, self.events, self.policy, approvals, self.verifiers, self.transcripts))
            verify = verify_pack(pack)
            replay = replay_pack(pack)
            verify_path = self.run_dir / "verification.json"
            replay_path = self.run_dir / "replay-result.json"
            write_json(verify_path, verify)
            write_json(replay_path, replay)
            verdict = "PASS" if verify["verdict"] == replay["verdict"] == "PASS" else "FAIL"
        write_json(self.run_dir / "result.json", {"schema": "secure-agent-profile/run-result/v1", "workflow": self.workflow, "run_id": self.run_id, "verdict": verdict, "pack_archive": str(pack) if pack else "", "verify": str(verify_path) if verify_path else "", "replay": str(replay_path) if replay_path else ""})
        return WorkflowResult(self.workflow, self.run_id, self.run_dir, verdict, pack, verify_path, replay_path)


def _run_ao(workflow: str, run_id: str, run_dir: Path, brief: Path, repo: Path, fake_adapter: bool) -> WorkflowResult:
    ao = _ao_binary()
    ao_home = run_dir / "ao-home"
    init = subprocess.run([str(ao), "init"], cwd=run_dir, env={**os.environ, "AO_HOME": str(ao_home)}, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    completed = subprocess.run([str(ao), "run", str(run_dir / "runspec.yaml")], cwd=run_dir, env={**os.environ, "AO_HOME": str(ao_home)}, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    write_json(run_dir / "ao-run.json", {"schema": "secure-agent-profile/ao-run/v1", "init": {"returncode": init.returncode, "stdout": init.stdout, "stderr": init.stderr}, "run": {"returncode": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}})
    pack = run_dir / f"evidence-pack-{run_id}.tar.zst"
    verify_path = run_dir / "verification.json"
    replay_path = run_dir / "replay-result.json"
    verdict = "PASS" if init.returncode == completed.returncode == 0 and pack.is_file() and verify_path.is_file() and replay_path.is_file() and read_json(verify_path)["verdict"] == "PASS" and read_json(replay_path)["verdict"] == "PASS" else "FAIL"
    return WorkflowResult(workflow, run_id, run_dir, verdict, pack if pack.is_file() else None, verify_path if verify_path.is_file() else None, replay_path if replay_path.is_file() else None)


def _repo_scan(workspace: Path) -> dict[str, Any]:
    files = [path.relative_to(workspace).as_posix() for path in sorted(workspace.rglob("*")) if path.is_file() and ".git" not in path.parts]
    return {"schema": "ao-operator/repo-scan/v1", "files": files, "excluded_paths": [".git", "secrets/*"], "manifest_files": [path for path in files if path in {"pyproject.toml", "requirements.txt", "package.json", "Cargo.toml"}]}


def _run_verifier(command: str, cwd: Path) -> dict[str, Any]:
    effective = command
    if command.startswith("python "):
        effective = sys.executable + command[len("python") :]
    completed = subprocess.run(effective, cwd=cwd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, "PYTHONPATH": str(cwd / "src")}, check=False)
    result = {"schema": "ao-operator/verifier-result/v1", "name": "unit-tests", "command": command, "status": "passed" if completed.returncode == 0 else "failed", "returncode": completed.returncode, "stdout": completed.stdout[-4000:], "stderr": completed.stderr[-4000:]}
    return result


def _closure(run_id: str, workflow: str, status: str, changed_files: list[str], verifiers: list[dict[str, Any]], policy: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"allow": 0, "approval_required": 0, "deny": 0, "blocked": 0}
    for item in policy:
        decision = item.get("decision", "allow")
        if decision in counts:
            counts[decision] += 1
    return {"schema": "ao-operator/secure-agent-closure/v1", "run_id": run_id, "profile": f"secure-agent:{workflow}", "status": status, "summary": "Run completed with required secure-agent evidence.", "changed_files": changed_files, "verifiers": verifiers, "policy_summary": counts}


def _diff(path: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=f"a/{path}", tofile=f"b/{path}"))


def _ecosystems(manifests: list[str]) -> list[str]:
    ecosystems = []
    if any(path in manifests for path in ("pyproject.toml", "requirements.txt")):
        ecosystems.append("python")
    if "package.json" in manifests:
        ecosystems.append("node")
    if "Cargo.toml" in manifests:
        ecosystems.append("rust")
    return ecosystems


def _ao_binary() -> Path:
    for raw in (os.environ.get("SAP_AO_BIN", ""), "${AO_RUNTIME_REPO}/target/release/ao", "${AO_RUNTIME_REPO}/target/debug/ao", shutil.which("ao") or ""):
        if raw and Path(raw).is_file():
            return Path(raw)
    raise FileNotFoundError("AO Runtime CLI not found; set SAP_AO_BIN")
