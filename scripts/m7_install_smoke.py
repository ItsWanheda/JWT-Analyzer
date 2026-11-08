"""Cross-platform smoke validation for editable, wheel, and sdist installs."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


def _run(command: Sequence[str], *, cwd: Path) -> str:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _console_script(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise RuntimeError(f"installed console script is not on PATH: {name}")
    return resolved


def _smoke_installed_commands(workdir: Path) -> None:
    _run([_console_script("jwt-analyzer"), "--version"], cwd=workdir)
    _run([_console_script("jwt-analyzer-v2"), "--version"], cwd=workdir)
    _run(
        [
            sys.executable,
            "-c",
            (
                "from jwt_analyzer import Assessment, Finding, PluginManager, "
                "PluginManifest, inspect_token; "
                "assert callable(inspect_token); "
                "assert Assessment and Finding and PluginManager and PluginManifest"
            ),
        ],
        cwd=workdir,
    )

    import jwt

    token = jwt.encode(
        {"sub": "m7-install-smoke", "exp": 4102444800},
        "m7-install-smoke-secret-32-bytes-minimum",
        algorithm="HS256",
    )
    token_path = workdir / "smoke.jwt"
    token_path.write_text(token, encoding="utf-8")
    inspected = _run(
        [_console_script("jwt-analyzer-v2"), "inspect", "--token-file", str(token_path)],
        cwd=workdir,
    )
    envelope = json.loads(inspected)
    assert envelope["status"] == "ok"
    assert envelope["assessment"]["verification_status"] == "not_attempted"
    assessment_path = workdir / "assessment.json"
    assessment_path.write_text(inspected, encoding="utf-8")

    batch_path = workdir / "batch.txt"
    batch_path.write_text(token + "\n", encoding="utf-8")
    batch_output = _run(
        [_console_script("jwt-analyzer-v2"), "batch", "--input-file", str(batch_path)],
        cwd=workdir,
    )
    batch_lines = [json.loads(line) for line in batch_output.splitlines() if line.strip()]
    assert len(batch_lines) == 2
    assert batch_lines[-1]["status"] == "complete"
    assert batch_lines[-1]["summary"]["succeeded"] == 1

    report_path = workdir / "smoke-report.json"
    _run(
        [
            _console_script("jwt-analyzer-v2"),
            "report",
            "--assessment-file",
            str(assessment_path),
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
        cwd=workdir,
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["report_schema_version"] == "1.0"
    assert report["redaction_applied"] is True


def _install_and_smoke(package_path: Path, workdir: Path, *, sdist: bool = False) -> None:
    _run(
        [sys.executable, "-m", "pip", "uninstall", "-y", "jwt-analyzer"],
        cwd=workdir,
    )
    install = [sys.executable, "-m", "pip", "install", "--no-deps"]
    if sdist:
        install.append("--no-build-isolation")
    install.append(str(package_path))
    _run(install, cwd=workdir)
    _smoke_installed_commands(workdir)


def main() -> int:
    repository_root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="jwt-analyzer-m7-") as temporary:
        temporary_root = Path(temporary)
        smoke_directory = temporary_root / "outside-source-tree"
        smoke_directory.mkdir()
        distribution_directory = temporary_root / "dist"
        distribution_directory.mkdir()

        # First verify the editable install supplied by the matrix job.
        _smoke_installed_commands(smoke_directory)

        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--no-isolation",
                "--outdir",
                str(distribution_directory),
            ],
            cwd=repository_root,
        )
        distributions = sorted(distribution_directory.iterdir())
        wheels = [path for path in distributions if path.suffix == ".whl"]
        sdists = [path for path in distributions if path.name.endswith(".tar.gz")]
        if len(wheels) != 1 or len(sdists) != 1:
            raise RuntimeError("expected exactly one wheel and one source distribution")

        _run(
            [sys.executable, "-m", "twine", "check", str(wheels[0]), str(sdists[0])],
            cwd=smoke_directory,
        )
        _install_and_smoke(wheels[0], smoke_directory)
        _install_and_smoke(sdists[0], smoke_directory, sdist=True)

    print("M7 editable, wheel, sdist, API, CLI, batch, and report smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
