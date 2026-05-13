from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_all_profile_json_files_have_required_contracts() -> None:
    for path in sorted((ROOT / "profiles/secure-agent").glob("*.json")):
        profile = json.loads(path.read_text(encoding="utf-8"))
        assert profile["schema"] == "ao-operator/profile/v1"
        assert profile["profile"].startswith("secure-agent:")
        assert profile["policy"] == "policy/secure-agent.policy.yaml"
        assert profile["evidence_pack"]["required"] is True
        assert profile["roles"]
        for role in profile["roles"]:
            assert role["id"]
            assert role["host_tags"]
            assert (ROOT / role["skill"]).is_file()


def test_policy_file_exists() -> None:
    assert (ROOT / "policy/secure-agent.policy.yaml").is_file()
