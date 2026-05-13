from __future__ import annotations

from pathlib import Path

from secure_agent_profile.classifiers import scan_secrets

ROOT = Path(__file__).resolve().parents[3]


def test_unsafe_fixture_finds_only_redacted_secret_previews() -> None:
    report = scan_secrets(ROOT / "examples/secure-agent/fixtures/unsafe-secrets-repo")

    assert report["verdict"] == "blocked"
    assert report["findings"]
    assert all("example000000000000000000000000000" not in item["redacted_preview"] for item in report["findings"])
