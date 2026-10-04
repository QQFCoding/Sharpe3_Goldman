"""Content binding for evaluation/dashboard freshness, inspired by reference evidence checks."""
import hashlib
import json
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from app.settings import ROOT


@lru_cache(maxsize=32)
def artifact_digest(path, size, modified, changed):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_fingerprint():
    digest = hashlib.sha256()
    files = [*sorted((ROOT / "app").rglob("*.py")),
        *sorted((ROOT / "app").glob("dashboard.*")),
        *sorted((ROOT / "config").glob("*.yaml")), *sorted((ROOT / "config").glob("*.json")),
        *sorted((ROOT / "opa").rglob("*.rego")),
        *sorted((ROOT / "tests").rglob("*.py")),
        *sorted((ROOT / "scripts").glob("*.py")), ROOT / "requirements.lock", ROOT / "pyproject.toml"]
    for path in files:
        if path.is_file() and path.name not in {"mcp-credentials.json"}:
            digest.update(Path(path).relative_to(ROOT).as_posix().encode())
            digest.update(path.read_bytes())
    for path in sorted((ROOT / "docs/baseline").glob("*.py")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    lock = ROOT / "config/deberta.lock.json"
    if lock.is_file():
        for name in sorted(json.loads(lock.read_text())["files"]):
            artifact = ROOT / "models/deberta" / name
            digest.update(name.encode())
            if artifact.is_file():
                stat = artifact.stat()
                digest.update(artifact_digest(str(artifact), stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns).encode())
            else:
                digest.update(b"missing")
    for package in ("torch", "transformers", "tokenizers", "pydantic", "fastapi"):
        try:
            digest.update((package + ":" + version(package)).encode())
        except PackageNotFoundError:
            digest.update((package + ":missing").encode())
    return digest.hexdigest()
