from __future__ import annotations

from pathlib import Path

from secure_agent_profile.workflow import run_workflow

ROOT = Path(__file__).resolve().parents[3]


def test_pr_evidence_writes_read_only_review_summary(tmp_path: Path) -> None:
    result = run_workflow("pr-evidence", brief_path=ROOT / "examples/secure-agent/pr-evidence/task-brief.md", repo_path=ROOT / "examples/secure-agent/fixtures/safe-python-service", output_root=tmp_path, run_id="pr-demo")

    assert result.verdict == "PASS"
    assert (result.run_dir / "secure-agent/review-summary.md").is_file()
