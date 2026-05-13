from __future__ import annotations

import argparse
from pathlib import Path

from .workflow import _dependency_review, _guarded_code_change, _pr_evidence
from .brief import parse_brief


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AO task shim for Secure Agent Profile.")
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--brief", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--fake-adapter", action="store_true")
    args = parser.parse_args(argv)
    # The v0.1 AO shim executes the deterministic profile end-to-end when AO
    # reaches evidence-pack-export. Earlier roles are no-op markers so AO still
    # proves dependency ordering and task capture.
    if args.role != "evidence-pack-export":
        print(f"secure-agent role {args.role} marked PASS")
        return 0
    brief = parse_brief(args.brief)
    workspace = args.run_dir / "workspace"
    if args.workflow == "guarded-code-change":
        result = _guarded_code_change(args.run_dir, args.run_id, brief, workspace)
    elif args.workflow == "dependency-review":
        result = _dependency_review(args.run_dir, args.run_id, brief, workspace)
    elif args.workflow == "pr-evidence":
        result = _pr_evidence(args.run_dir, args.run_id, brief, workspace)
    else:
        raise ValueError(args.workflow)
    print(result.verdict)
    return 0 if result.verdict == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
