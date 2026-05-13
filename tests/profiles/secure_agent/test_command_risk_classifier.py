from __future__ import annotations

from secure_agent_profile.classifiers import classify_command


def test_declared_pytest_verifier_is_allowed() -> None:
    report = classify_command("python -m pytest tests/test_math_utils.py", declared_verifiers=["python -m pytest tests/test_math_utils.py"])
    assert report["verdict"] == "allow"
    assert report["command_class"] == "test"


def test_destructive_command_is_blocked() -> None:
    report = classify_command("rm -rf /tmp/demo", declared_verifiers=[])
    assert report["verdict"] == "blocked"


def test_network_install_requires_approval() -> None:
    report = classify_command("pip install requests", declared_verifiers=[])
    assert report["verdict"] == "approval_required"
