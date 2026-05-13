from __future__ import annotations

import math
import re
import shlex
from pathlib import Path
from typing import Any

SECRET_PATH_PATTERNS = (".env", ".pem", ".key")
SECRET_DIRS = ("secrets/",)
PROTECTED_WRITE_BLOCK = ("config/production.yaml",)
APPROVAL_PREFIXES = ("auth/", "security/", "billing/", "payments/", "migrations/", "terraform/", "k8s/", ".github/workflows/")
MANIFESTS = ("pyproject.toml", "requirements.txt", "package.json", "Cargo.toml", "Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock")
BLOCKED_COMMANDS = {"sudo", "su", "dd", "mkfs", "kubectl", "terraform", "aws", "gcloud", "az"}
APPROVAL_COMMANDS = {"curl", "wget", "gh"}


def classify_file(path: str, operation: str, *, allowed_paths: list[str], protected_paths: list[str]) -> dict[str, Any]:
    normalized = _normalize(path)
    if normalized.startswith("../") or normalized.startswith("/"):
        return _file_result(normalized, operation, "outside_workspace", "deny", ["workspace.outside"])
    if _is_secret_path(normalized):
        return _file_result(normalized, operation, "secret", "blocked", ["file_scopes.secret.block"])
    if operation == "write" and normalized in PROTECTED_WRITE_BLOCK:
        return _file_result(normalized, operation, "production_config", "blocked", ["file_scopes.production_config.block_write"])
    if any(_matches_prefix(normalized, prefix) for prefix in protected_paths):
        return _file_result(normalized, operation, "brief_protected", "approval_required", ["brief.protected_paths"])
    if operation == "write" and (normalized in MANIFESTS or any(_matches_prefix(normalized, p) for p in APPROVAL_PREFIXES)):
        return _file_result(normalized, operation, "sensitive_project_file", "approval_required", ["file_scopes.sensitive.approval"])
    if any(_matches_prefix(normalized, prefix) for prefix in allowed_paths):
        klass = "tests" if normalized.startswith("tests/") else "public_source"
        return _file_result(normalized, operation, klass, "allow", ["brief.allowed_paths"])
    if operation == "read":
        return _file_result(normalized, operation, "repo_unknown", "allow", ["file_scopes.repo_read"])
    return _file_result(normalized, operation, "repo_unknown", "approval_required", ["file_scopes.unknown.approval"])


def classify_command(command: str, *, declared_verifiers: list[str]) -> dict[str, Any]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return _command_result(command, "invalid", "high", "unknown", "blocked", "unparseable shell command")
    if not tokens:
        return _command_result(command, "empty", "low", "none", "deny", "empty command")
    if re.search(r"(`|\$\(|;|&&|\|\|)", command):
        return _command_result(command, "compound_shell", "high", "unknown", "approval_required", "compound shell requires review")
    if _contains_rm_rf(tokens) or tokens[0] in BLOCKED_COMMANDS or "chmod -R 777" in command or "chown -R /" in command:
        return _command_result(command, "dangerous", "blocked", "unknown", "blocked", "blocked command class")
    if tokens[0] in APPROVAL_COMMANDS or _is_package_install(tokens):
        return _command_result(command, "network_or_install", "high", "external", "approval_required", "network/install command requires approval")
    if tokens[:2] == ["git", "push"] or tokens[:2] == ["gh", "pr"]:
        return _command_result(command, "remote_write", "blocked", "external", "blocked", "remote write blocked in v1")
    if command in declared_verifiers:
        return _command_result(command, "test", "low", "none", "allow", "declared verifier command")
    if tokens[:2] in (["git", "status"], ["git", "diff"]) or tokens[0] in {"rg", "ls"}:
        return _command_result(command, "repo_inspection", "low", "none", "allow", "read-only repo inspection")
    return _command_result(command, "unknown", "medium", "unknown", "approval_required", "unknown command class")


def scan_secrets(root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        rel = path.relative_to(root).as_posix()
        scanned.append(rel)
        if _is_secret_path(rel):
            findings.append({"path": rel, "line": 1, "kind": "secret_path", "severity": "high", "redacted_preview": _redact(rel)})
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for idx, line in enumerate(lines, start=1):
            kind = _secret_kind(line)
            if kind:
                findings.append({"path": rel, "line": idx, "kind": kind, "severity": "high", "redacted_preview": _redact(line)})
    return {"schema": "ao-operator/secret-scan/v1", "scanned_paths": scanned, "findings": findings, "verdict": "blocked" if findings else "allow"}


def risk_from(file_decisions: list[dict[str, Any]], command_decisions: list[dict[str, Any]], secret_scan: dict[str, Any]) -> str:
    verdicts = [item["verdict"] for item in file_decisions + command_decisions]
    if secret_scan["verdict"] == "blocked" or "blocked" in verdicts or "deny" in verdicts:
        return "blocked"
    if "approval_required" in verdicts:
        return "high"
    return "low"


def _normalize(path: str) -> str:
    normalized = Path(path).as_posix()
    return normalized[2:] if normalized.startswith("./") else normalized


def _matches_prefix(path: str, prefix: str) -> bool:
    prefix = prefix.lstrip("./")
    return path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/")


def _is_secret_path(path: str) -> bool:
    lowered = path.lower()
    return any(part in lowered for part in SECRET_DIRS) or lowered.endswith(SECRET_PATH_PATTERNS) or lowered == ".env"


def _file_result(path: str, operation: str, klass: str, verdict: str, matched: list[str]) -> dict[str, Any]:
    return {"schema": "ao-operator/file-scope/v1", "path": path, "operation": operation, "class": klass, "verdict": verdict, "matched_rules": matched}


def _command_result(command: str, klass: str, risk: str, network: str, verdict: str, reason: str) -> dict[str, Any]:
    return {"schema": "ao-operator/command-risk/v1", "command": command, "command_class": klass, "risk": risk, "network": network, "verdict": verdict, "reason": reason}


def _contains_rm_rf(tokens: list[str]) -> bool:
    return bool(tokens and tokens[0] == "rm" and any("r" in token and "f" in token for token in tokens[1:] if token.startswith("-")))


def _is_package_install(tokens: list[str]) -> bool:
    return tokens[:2] in (["npm", "install"], ["pip", "install"], ["cargo", "install"], ["cargo", "fetch"])


def _secret_kind(line: str) -> str:
    if "BEGIN FAKE PRIVATE KEY" in line or "BEGIN PRIVATE KEY" in line:
        return "private_key"
    if re.search(r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY)\\s*=", line):
        return "env_secret"
    if re.search(r"AKIA[A-Z0-9]{16}", line):
        return "aws_access_key"
    if re.search(r"sk-(proj-)?[A-Za-z0-9_-]{20,}", line):
        return "provider_token"
    return "high_entropy" if _entropy(line) > 4.2 and len(line) > 40 else ""


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    return -sum((text.count(ch) / len(text)) * math.log2(text.count(ch) / len(text)) for ch in set(text))


def _redact(text: str) -> str:
    return text[:18] + "..." if len(text) > 21 else text[:4] + "..."
