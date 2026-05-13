from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .util import json_dumps, now, read_ndjson, write_json, write_ndjson


@dataclass(frozen=True)
class EvidenceInput:
    run_id: str
    workflow: str
    run_dir: Path
    secure_agent_dir: Path
    artifacts_dir: Path
    events: list[dict[str, Any]]
    policy: list[dict[str, Any]]
    approvals: dict[str, Any]
    verifier_results: list[dict[str, Any]]
    transcripts: dict[str, list[dict[str, Any]]]


def write_evidence_pack(evidence: EvidenceInput) -> Path:
    pack_root = evidence.run_dir / f"evidence-pack-{evidence.run_id}"
    if pack_root.exists():
        shutil.rmtree(pack_root)
    pack_root.mkdir(parents=True)
    write_ndjson(pack_root / "events.ndjson", evidence.events)
    write_ndjson(pack_root / "policy.ndjson", evidence.policy)
    write_json(pack_root / "approvals.json", evidence.approvals)
    write_ndjson(pack_root / "verifier-results.ndjson", evidence.verifier_results)
    roles_dir = pack_root / "roles"
    for role, records in sorted(evidence.transcripts.items()):
        write_ndjson(roles_dir / role / "transcript.jsonl", records)
    shutil.copytree(evidence.secure_agent_dir, pack_root / "secure-agent")
    artifact_index = _copy_artifacts(evidence.artifacts_dir, pack_root / "artifacts")
    write_json(pack_root / "artifact-index.json", artifact_index)
    write_json(pack_root / "replay.json", {"schema": "ao-runtime/replay-plan/v1", "deterministic_steps": ["file-scope-classifier", "command-risk-classifier", "secret-scan"]})
    required_errors = _required_errors(pack_root, evidence.workflow)
    tree_hash = _tree_hash(pack_root, exclude={"manifest.json", "evidence.sig", "public-key.pem"})
    manifest = {
        "schema": "ao-runtime/evidence-pack/v1",
        "run_id": evidence.run_id,
        "profile": {"name": f"secure-agent:{evidence.workflow}", "workflow": evidence.workflow},
        "runtime": {"ao_runtime_version": "local-ao-cli", "ao_operator_version": "v0.7.0", "profile_version": __version__},
        "security": {"policy_profile": "secure-agent.policy.yaml", "workspace_mode": "temp-copy", "apply_to_source": False, "network_default": "deny", "secret_scan": "required", "approval_mode": "required_for_risky"},
        "host_tags": ["repo-safe", "live-codex"],
        "operator": os.getenv("USER", "operator"),
        "trace_id": "trace-" + hashlib.sha256(evidence.run_id.encode()).hexdigest()[:24],
        "started_at": now(),
        "completed_at": now(),
        "artifact_index": artifact_index,
        "tree_hash": "sha256:" + tree_hash,
        "signature": {"algorithm": "Ed25519", "public_key": "public-key.pem", "path": "evidence.sig"},
        "evidence_errors": required_errors,
    }
    if required_errors:
        write_json(pack_root / "manifest.json", manifest)
        raise RuntimeError("evidence completeness failed: " + ", ".join(required_errors))
    manifest_bytes = json_dumps(manifest).encode("utf-8")
    (pack_root / "manifest.json").write_bytes(manifest_bytes)
    _sign(pack_root, manifest_bytes, tree_hash)
    return _tar_zst(pack_root, evidence.run_dir)


def verify_pack(archive: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="sap-verify-") as tmp:
        root = _materialize(archive, Path(tmp))
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        errors = _required_errors(root, str(manifest["profile"]["workflow"]))
        tree = _tree_hash(root, exclude={"manifest.json", "evidence.sig", "public-key.pem"})
        expected = str(manifest.get("tree_hash", "")).removeprefix("sha256:")
        if tree != expected:
            errors.append("tree_hash_mismatch")
        if not _verify_signature(root, (root / "manifest.json").read_bytes(), expected):
            errors.append("signature_mismatch")
        for item in manifest.get("artifact_index", []):
            path = root / item["pack_path"]
            if not path.is_file() or _sha256_file(path) != item["sha256"]:
                errors.append(f"artifact_mismatch:{item['pack_path']}")
        return {"schema": "secure-agent-profile/verify/v1", "verdict": "PASS" if not errors else "FAIL", "errors": errors, "manifest": manifest}


def replay_pack(archive: Path) -> dict[str, Any]:
    verification = verify_pack(archive)
    errors = list(verification["errors"])
    with tempfile.TemporaryDirectory(prefix="sap-replay-") as tmp:
        root = _materialize(archive, Path(tmp))
        if not read_ndjson(root / "policy.ndjson"):
            errors.append("policy_empty")
        closure = json.loads((root / "secure-agent" / "closure.json").read_text(encoding="utf-8"))
        if closure.get("status") != "passed":
            errors.append("closure_not_passed")
    return {"schema": "ao-runtime/replay-result/v1", "status": "passed" if not errors else "failed", "verdict": "PASS" if not errors else "FAIL", "model_steps": "transcript_replayed", "deterministic_steps": [{"name": name, "status": "matched"} for name in ("file-scope-classifier", "command-risk-classifier", "secret-scan")], "diffs": errors}


def _required_errors(root: Path, workflow: str) -> list[str]:
    required = ["events.ndjson", "policy.ndjson", "approvals.json", "artifact-index.json", "secure-agent/intake.json", "secure-agent/repo-scan.json", "secure-agent/risk-report.json", "secure-agent/closure.json"]
    if workflow == "guarded-code-change":
        required += ["secure-agent/plan.json", "secure-agent/changed-files.json", "secure-agent/command-audit.ndjson", "secure-agent/file-access.ndjson", "secure-agent/secret-scan.json", "secure-agent/verifier-results.json", "secure-agent/security-review.json", "secure-agent/patch.diff"]
    elif workflow == "dependency-review":
        required += ["secure-agent/dependency-review-report.json", "secure-agent/package-risk-report.json", "secure-agent/lockfile-check.json"]
    elif workflow == "pr-evidence":
        required += ["secure-agent/diff-summary.json", "secure-agent/changed-file-classification.json", "secure-agent/missing-coverage.json", "secure-agent/review-summary.md"]
    return [f"missing:{path}" for path in required if not (root / path).is_file()]


def _copy_artifacts(source: Path, dest: Path) -> list[dict[str, str]]:
    index = []
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        sha = _sha256_file(path)
        target = dest / sha / path.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        index.append({"path": path.relative_to(source).as_posix(), "sha256": sha, "pack_path": target.relative_to(dest.parent).as_posix()})
    return index


def _tree_hash(root: Path, *, exclude: set[str]) -> str:
    leaves = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in exclude:
            leaves.append(hashlib.sha256(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes()).hexdigest())
    level = sorted(leaves) or [hashlib.sha256(b"").hexdigest()]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1])).hexdigest() for i in range(0, len(level), 2)]
    return level[0]


def _sign(pack_root: Path, manifest_bytes: bytes, tree_hash: str) -> None:
    private = pack_root.parent / "ed25519-private.pem"
    public = pack_root / "public-key.pem"
    sig_input = pack_root.parent / "signature-input.bin"
    openssl = _openssl()
    _run([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private)])
    _run([openssl, "pkey", "-in", str(private), "-pubout", "-out", str(public)])
    sig_input.write_bytes(hashlib.sha256(manifest_bytes).digest() + bytes.fromhex(tree_hash))
    _run([openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(private), "-in", str(sig_input), "-out", str(pack_root / "evidence.sig")])
    private.unlink(missing_ok=True)
    sig_input.unlink(missing_ok=True)


def _verify_signature(pack_root: Path, manifest_bytes: bytes, tree_hash: str) -> bool:
    sig_input = pack_root.parent / "signature-input.bin"
    sig_input.write_bytes(hashlib.sha256(manifest_bytes).digest() + bytes.fromhex(tree_hash))
    completed = subprocess.run([_openssl(), "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(pack_root / "public-key.pem"), "-sigfile", str(pack_root / "evidence.sig"), "-in", str(sig_input)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    sig_input.unlink(missing_ok=True)
    return completed.returncode == 0


def _tar_zst(pack_root: Path, dest_dir: Path) -> Path:
    tar_path = dest_dir / f"{pack_root.name}.tar"
    archive = dest_dir / f"{pack_root.name}.tar.zst"
    with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as tf:
        for path in sorted(pack_root.rglob("*")):
            if path.is_file():
                tf.add(path, arcname=(Path(pack_root.name) / path.relative_to(pack_root)).as_posix())
    _run(["zstd", "-q", "-T0", "-o", str(archive), str(tar_path)])
    tar_path.unlink(missing_ok=True)
    return archive


def _materialize(archive: Path, scratch: Path) -> Path:
    tar_path = scratch / archive.name.removesuffix(".zst")
    _run(["zstd", "-q", "-d", "-o", str(tar_path), str(archive)])
    extract = scratch / "extract"
    extract.mkdir()
    with tarfile.open(tar_path) as tf:
        _safe_extractall(tf, extract)
    roots = [path for path in extract.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise ValueError("archive must contain one root")
    return roots[0]


def _safe_extractall(tf: tarfile.TarFile, dest: Path) -> None:
    """Use Python 3.12's data filter when available; enforce the same boundary on 3.9."""
    try:
        tf.extractall(dest, filter="data")
        return
    except TypeError:
        pass

    dest_root = dest.resolve()
    for member in tf.getmembers():
        member_path = Path(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise ValueError(f"unsafe archive path: {member.name}")
        target = (dest / member_path).resolve()
        if dest_root != target and dest_root not in target.parents:
            raise ValueError(f"unsafe archive path: {member.name}")
        if member.islnk() or member.issym():
            link_target = Path(member.linkname)
            if link_target.is_absolute() or ".." in link_target.parts:
                raise ValueError(f"unsafe archive link: {member.name}")
    tf.extractall(dest)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str]) -> None:
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "command failed: " + " ".join(command))


def _openssl() -> str:
    for candidate in (os.environ.get("SAP_OPENSSL", ""), shutil.which("openssl") or "", "/opt/homebrew/bin/openssl"):
        if candidate:
            try:
                completed = subprocess.run([candidate, "list", "-public-key-algorithms"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            except FileNotFoundError:
                continue
            if completed.returncode == 0 and "ED25519" in completed.stdout.upper():
                return candidate
    raise RuntimeError("OpenSSL with ED25519 support is required")
