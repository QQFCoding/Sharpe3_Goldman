"""The same checks on Windows, macOS, Linux, and in make test."""

import subprocess
import sys
from pathlib import Path

from bootstrap import install_opa

ROOT = Path(__file__).resolve().parents[1]


def main():
    opa = install_opa()
    for command in [
        [str(opa), "test", "./opa", "-v"],
        [sys.executable, "-m", "ruff", "check", "."],
        [sys.executable, "-m", "pytest", "-q", *sys.argv[1:]],
    ]:
        subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
