from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def run_doctor() -> dict[str, Any]:
    checks = {
        "python": {"verdict": "PASS", "path": sys.executable, "version": sys.version.split()[0]},
        "pytest": _tool("pytest"),
        "zstd": _tool("zstd"),
        "openssl_ed25519": _openssl(),
        "ao_runtime": _ao(),
    }
    required = ["python", "zstd", "openssl_ed25519"]
    return {"schema": "secure-agent-profile/doctor/v1", "verdict": "PASS" if all(checks[name]["verdict"] == "PASS" for name in required) else "FAIL", "checks": checks}


def _tool(name: str) -> dict[str, str]:
    path = shutil.which(name)
    return {"verdict": "PASS", "path": path} if path else {"verdict": "WARN", "reason": f"{name} not found"}


def _openssl() -> dict[str, str]:
    for candidate in ("/opt/homebrew/bin/openssl", shutil.which("openssl") or ""):
        if candidate:
            completed = subprocess.run([candidate, "list", "-public-key-algorithms"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if completed.returncode == 0 and "ED25519" in completed.stdout.upper():
                return {"verdict": "PASS", "path": candidate}
    return {"verdict": "FAIL", "reason": "OpenSSL Ed25519 support not found"}


def _ao() -> dict[str, str]:
    for raw in ("${AO_RUNTIME_REPO}/target/release/ao", "${AO_RUNTIME_REPO}/target/debug/ao", shutil.which("ao") or ""):
        if raw and Path(raw).is_file():
            completed = subprocess.run([raw, "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            return {"verdict": "PASS" if completed.returncode == 0 else "FAIL", "path": raw, "version": (completed.stdout or completed.stderr).strip()}
    return {"verdict": "WARN", "reason": "AO Runtime CLI not found; local engine still works"}
