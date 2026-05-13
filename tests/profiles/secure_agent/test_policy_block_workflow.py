from __future__ import annotations

import json
from pathlib import Path

from secure_agent_profile.workflow import run_workflow

ROOT = Path(__file__).resolve().parents[3]


def test_policy_block_fixture_stops_before_pack_creation(tmp_path: Path) -> None:
    result = run_workflow(
        "guarded-code-change",
        brief_path=ROOT / "examples/secure-agent/policy-block/task-brief.md",
        repo_path=ROOT / "examples/secure-agent/fixtures/safe-python-service",
        output_root=tmp_path,
        run_id="policy-block-demo",
    )

    assert result.verdict == "BLOCKED"
    assert result.pack_archive is None
    risk = json.loads((result.run_dir / "secure-agent/risk-report.json").read_text(encoding="utf-8"))
    assert risk["risk"] == "blocked"
    assert any(
        item["command"] == "git push origin main" and item["verdict"] == "blocked"
        for item in risk["command_decisions"]
    )
    approvals = json.loads((result.run_dir / "approvals.json").read_text(encoding="utf-8"))
    assert approvals["verdict"] == "BLOCKED"
