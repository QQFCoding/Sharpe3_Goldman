"""Portable bootstrap. OPA is pinned and its published checksum is verified."""

import argparse
import hashlib
import os
import platform
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPA_VERSION = "1.4.2"


def install_opa() -> Path:
    target = ROOT / ".tools" / ("opa.exe" if os.name == "nt" else "opa")
    if target.exists():
        return target
    machine = "arm64" if platform.machine().lower() in {"aarch64", "arm64"} else "amd64"
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}[platform.system()]
    name = f"opa_{system}_{machine}" + (".exe" if system == "windows" else "")
    url = f"https://github.com/open-policy-agent/opa/releases/download/v{OPA_VERSION}/{name}"
    target.parent.mkdir(parents=True, exist_ok=True)
    checksum = urllib.request.urlopen(url + ".sha256", timeout=60).read().decode().split()[0]
    blob = urllib.request.urlopen(url, timeout=120).read()
    if hashlib.sha256(blob).hexdigest() != checksum:
        raise RuntimeError("OPA checksum mismatch")
    target.write_bytes(blob)
    target.chmod(0o755)
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--opa-only", action="store_true")
    args = parser.parse_args()
    if not args.opa_only:
        subprocess.run([sys.executable, "-m", "venv", str(ROOT / ".venv")], check=True)
        python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        subprocess.run([str(python), "-m", "pip", "install", "-e", ".[test]"], cwd=ROOT, check=True)
    print(f"OPA: {install_opa()}")


if __name__ == "__main__":
    main()
