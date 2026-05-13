from __future__ import annotations

import argparse
import json
from pathlib import Path

from .doctor import run_doctor
from .evidence import replay_pack, verify_pack
from .workflow import run_workflow

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run or verify Secure Agent Profile workflows.")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("workflow", choices=["guarded-code-change", "dependency-review", "pr-evidence"])
    run.add_argument("--brief", type=Path, required=True)
    run.add_argument("--repo", type=Path, required=True)
    run.add_argument("--output-root", type=Path, default=ROOT / "runs")
    run.add_argument("--run-id")
    run.add_argument("--engine", choices=["local", "ao"], default="local")
    run.add_argument("--fake-adapter", action="store_true", default=True)
    verify = sub.add_parser("verify")
    verify.add_argument("archive", type=Path)
    replay = sub.add_parser("replay")
    replay.add_argument("archive", type=Path)
    doctor = sub.add_parser("doctor")
    args = parser.parse_args(argv)
    if args.command == "run":
        result = run_workflow(args.workflow, brief_path=args.brief, repo_path=args.repo, output_root=args.output_root, run_id=args.run_id, engine=args.engine, fake_adapter=args.fake_adapter)
        print(json.dumps({"workflow": result.workflow, "run_id": result.run_id, "verdict": result.verdict, "run_dir": str(result.run_dir), "pack_archive": str(result.pack_archive) if result.pack_archive else "", "verify": str(result.verify_path) if result.verify_path else "", "replay": str(result.replay_path) if result.replay_path else ""}, indent=2, sort_keys=True))
        return 0 if result.verdict == "PASS" else 2
    if args.command == "verify":
        report = verify_pack(args.archive)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["verdict"] == "PASS" else 2
    if args.command == "replay":
        report = replay_pack(args.archive)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["verdict"] == "PASS" else 2
    if args.command == "doctor":
        report = run_doctor()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["verdict"] == "PASS" else 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
