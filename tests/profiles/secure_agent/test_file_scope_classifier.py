from __future__ import annotations

from secure_agent_profile.classifiers import classify_file


def test_allowed_source_write_is_allowed() -> None:
    report = classify_file("src/safe_service/math_utils.py", "write", allowed_paths=["src/", "tests/"], protected_paths=["secrets/"])
    assert report["verdict"] == "allow"


def test_secret_path_is_blocked() -> None:
    report = classify_file("secrets/DO_NOT_READ.key", "read", allowed_paths=["src/"], protected_paths=[])
    assert report["verdict"] == "blocked"


def test_production_config_write_is_blocked() -> None:
    report = classify_file("config/production.yaml", "write", allowed_paths=["config/"], protected_paths=[])
    assert report["verdict"] == "blocked"
