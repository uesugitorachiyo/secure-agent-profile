from __future__ import annotations

import tarfile
import tempfile
from pathlib import Path

import pytest

from secure_agent_profile.evidence import _materialize, verify_pack
from secure_agent_profile.workflow import run_workflow

ROOT = Path(__file__).resolve().parents[3]


def test_evidence_pack_verifies_with_secure_agent_artifacts(tmp_path: Path) -> None:
    result = run_workflow("guarded-code-change", brief_path=ROOT / "examples/secure-agent/guarded-code-change/task-brief.md", repo_path=ROOT / "examples/secure-agent/fixtures/safe-python-service", output_root=tmp_path, run_id="verify-demo")

    report = verify_pack(result.pack_archive)
    assert report["verdict"] == "PASS"
    assert report["manifest"]["profile"]["name"] == "secure-agent:guarded-code-change"


def test_evidence_materialize_supports_python39_tarfile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = run_workflow(
        "guarded-code-change",
        brief_path=ROOT / "examples/secure-agent/guarded-code-change/task-brief.md",
        repo_path=ROOT / "examples/secure-agent/fixtures/safe-python-service",
        output_root=tmp_path,
        run_id="python39-materialize-demo",
    )
    original_extractall = tarfile.TarFile.extractall

    def python39_extractall(
        self: tarfile.TarFile,
        path: object = ".",
        members: object = None,
        *,
        numeric_owner: bool = False,
        filter: object = None,
    ) -> None:
        if filter is not None:
            raise TypeError("extractall() got an unexpected keyword argument 'filter'")
        return original_extractall(self, path, members, numeric_owner=numeric_owner)

    monkeypatch.setattr(tarfile.TarFile, "extractall", python39_extractall)

    with tempfile.TemporaryDirectory(prefix="sap-python39-materialize-") as scratch:
        root = _materialize(result.pack_archive, Path(scratch))

    assert root.name == "evidence-pack-python39-materialize-demo"
