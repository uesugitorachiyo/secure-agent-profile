from __future__ import annotations

from pathlib import Path

from secure_agent_profile.evidence import replay_pack
from secure_agent_profile.workflow import run_workflow

ROOT = Path(__file__).resolve().parents[3]


def test_replay_matches_deterministic_steps(tmp_path: Path) -> None:
    result = run_workflow("guarded-code-change", brief_path=ROOT / "examples/secure-agent/guarded-code-change/task-brief.md", repo_path=ROOT / "examples/secure-agent/fixtures/safe-python-service", output_root=tmp_path, run_id="replay-demo")

    report = replay_pack(result.pack_archive)
    assert report["verdict"] == "PASS"
    assert {step["name"] for step in report["deterministic_steps"]} == {"file-scope-classifier", "command-risk-classifier", "secret-scan"}
