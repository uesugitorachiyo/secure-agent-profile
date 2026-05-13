from __future__ import annotations

import json
from pathlib import Path

from secure_agent_profile.workflow import run_workflow

ROOT = Path(__file__).resolve().parents[3]


def test_dependency_review_writes_report(tmp_path: Path) -> None:
    result = run_workflow("dependency-review", brief_path=ROOT / "examples/secure-agent/dependency-review/task-brief.md", repo_path=ROOT / "examples/secure-agent/fixtures/safe-python-service", output_root=tmp_path, run_id="deps-demo")

    assert result.verdict == "PASS"
    report = json.loads((result.run_dir / "secure-agent/dependency-review-report.json").read_text(encoding="utf-8"))
    assert "python" in report["ecosystems"]
