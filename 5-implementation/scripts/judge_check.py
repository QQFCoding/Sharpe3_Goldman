"""Fast implementation checks. Real-model quality gates are a separate, longer command."""
import subprocess
import sys
import tempfile
from pathlib import Path

from bootstrap import install_opa

ROOT = Path(__file__).resolve().parents[1]


def main():
    opa = install_opa()
    with tempfile.TemporaryDirectory(prefix="judge-check-", dir=ROOT / ".tools") as temporary:
        commands = [
            [str(opa), "test", str(ROOT / "opa")],
            [sys.executable, "-m", "ruff", "check", "."],
            [sys.executable, "-m", "pytest", "-q", "--basetemp=" + temporary + "/cases",
             "-o", "cache_dir=" + temporary + "/cache", "--junitxml=artifacts/judge-check.xml"],
        ]
        for command in commands:
            subprocess.run(command, cwd=ROOT, check=True)
    print("Implementation checks passed. Semantic accuracy is not measured by this command.")
    print("Full quality gates: python -m scripts.self_test --robustness")


if __name__ == "__main__":
    main()
