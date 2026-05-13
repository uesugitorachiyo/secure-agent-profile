from __future__ import annotations

from pathlib import Path

from secure_agent_profile.runspec import materialize_runspec, render_runspec_yaml


def test_guarded_code_change_runspec_has_policy_evidence_and_dag(tmp_path: Path) -> None:
    runspec = materialize_runspec("guarded-code-change", run_id="demo", brief=Path("brief.md"), repo=Path("repo"), run_dir=tmp_path)
    body = render_runspec_yaml(runspec)

    assert runspec["apiVersion"] == "ao.dev/v1"
    assert runspec["spec"]["evidence"]["required"] is True
    assert runspec["spec"]["policy"]["default"] == "deny"
    assert "id: implementation" in body
    assert "hostTags" in body
    assert "secure_agent_profile.ao_tasks" in body
