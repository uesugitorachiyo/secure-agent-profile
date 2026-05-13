from __future__ import annotations

from secure_agent_profile.classifiers import classify_command, classify_file


def test_policy_matrix_blocks_push_and_secret_write() -> None:
    assert classify_command("git push origin main", declared_verifiers=[])["verdict"] == "blocked"
    assert classify_file(".env", "write", allowed_paths=["."], protected_paths=[])["verdict"] == "blocked"
