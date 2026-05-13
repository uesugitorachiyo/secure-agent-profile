from __future__ import annotations

import json
from pathlib import Path

from secure_agent_profile.workflow import run_workflow

ROOT = Path(__file__).resolve().parents[3]


def test_guarded_code_change_generates_patch_and_pack(tmp_path: Path) -> None:
    result = run_workflow("guarded-code-change", brief_path=ROOT / "examples/secure-agent/guarded-code-change/task-brief.md", repo_path=ROOT / "examples/secure-agent/fixtures/safe-python-service", output_root=tmp_path, run_id="guarded-demo")

    assert result.verdict == "PASS"
    assert result.pack_archive is not None
    assert (result.run_dir / "secure-agent/patch.diff").is_file()
    closure = json.loads((result.run_dir / "secure-agent/closure.json").read_text(encoding="utf-8"))
    assert closure["status"] == "passed"
