"""Offline provenance inventory from installed package metadata and pinned local model cards.

Run in the environment being delivered. This records declarations and file digests;
it is neither a legal conclusion nor a replacement for the bundled license texts.
"""
import argparse
import hashlib
import json
import platform
import re
import sys
import tomllib
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def package_inventory():
    packages = []
    for distribution in metadata.distributions():
        fields = distribution.metadata
        declared = fields.get("License", "")
        files = []
        for item in distribution.files or ():
            if not any(part.lower().startswith(("license", "licence", "copying", "notice")) for part in item.parts):
                continue
            path = Path(distribution.locate_file(item)).resolve()
            if not path.is_file() or not path.is_relative_to(Path(sys.prefix).resolve()):
                continue
            files.append({"file": item.as_posix(), "sha256": digest(path), "bytes": path.stat().st_size})
        packages.append({"name": fields.get("Name", "unknown"), "version": distribution.version,
            "license_expression": fields.get("License-Expression"),
            "license_declaration": " ".join(declared.split())[:500] or None,
            "license_declaration_truncated": len(" ".join(declared.split())) > 500,
            "license_metadata_sha256": hashlib.sha256(declared.encode()).hexdigest() if declared else None,
            "license_classifiers": [value for value in fields.get_all("Classifier", []) if value.startswith("License ::")],
            "bundled_license_files": sorted(files, key=lambda file: file["file"]),
            "files_manifest_available": distribution.files is not None})
    return sorted(packages, key=lambda package: package["name"].lower())


def model_inventory():
    models = []
    for path in sorted((ROOT / "config").glob("*.lock.json")):
        lock = json.loads(path.read_text(encoding="utf-8"))
        identifier = lock.get("model") or lock.get("repo")
        if not identifier or not lock.get("revision"):
            continue
        name = path.name.removesuffix(".lock.json")
        card = ROOT / "models" / name / "README.md"
        declaration = None
        if card.is_file():
            match = re.search(r"(?m)^license:\s*([^\r\n]+)", card.read_text(encoding="utf-8"))
            declaration = match.group(1).strip() if match else None
        expected = lock.get("files", {}).get("README.md")
        card_digest = digest(card) if card.is_file() else None
        models.append({"name": name, "model_id": identifier, "revision": lock["revision"],
            "lock_file": path.relative_to(ROOT).as_posix(), "lock_sha256": digest(path),
            "lock_license_declaration": lock.get("license"), "card_license_declaration": declaration,
            "card_present": card.is_file(), "card_sha256": card_digest,
            "card_pinned_by_lock": expected is not None,
            "card_matches_lock": card_digest == expected if expected else None,
            "primary_card_url": f"https://huggingface.co/{identifier}/blob/{lock['revision']}/README.md",
            "artifacts": [{"file": name, "expected_sha256": sha} for name, sha in sorted(lock.get("files", {}).items())]})
    return models


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/final/licenses.json")
    args = parser.parse_args()
    packages = package_inventory()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    primary = ROOT / "docs/final/license-sources.json"
    body = {"schema_version": "license-inventory-v1", "generated_at": datetime.now(UTC).isoformat(),
        "environment": {"python": platform.python_version(), "platform": platform.system(),
            "scope": "all distributions installed in the interpreter used for this command; optional/dev packages may be included"},
        "repository": {"name": project["name"], "version": project["version"], "license": "MIT",
            "license_file": "LICENSE", "license_sha256": digest(ROOT / "LICENSE"),
            "direct_requirements": project.get("dependencies", []),
            "optional_requirements": project.get("optional-dependencies", {})},
        "package_count": len(packages),
        "packages_without_machine_readable_declaration": [p["name"] for p in packages if not p["license_expression"]
            and not p["license_declaration"] and not p["license_classifiers"]],
        "packages_without_bundled_license_files": [p["name"] for p in packages if not p["bundled_license_files"]],
        "packages": packages, "models": model_inventory(),
        "primary_source_verification": json.loads(primary.read_text(encoding="utf-8")) if primary.is_file() else None,
        "limitations": ["Package metadata is publisher-declared and may be incomplete or ambiguous.",
            "This is an installed-environment inventory, not a complete SBOM of Docker images, Python runtime, browsers or system libraries.",
            "Model license tags do not establish rights to every underlying training dataset or base model.",
            "Optional gated Prompt Guard is not installed/pinned by this checkout; review its model terms before opting in.",
            "Ollama tags in sample policy are not immutable model locks; evaluated service-model provenance is recorded separately.",
            "Redis/PostgreSQL and observability container redistribution licenses are not exhaustively inventoried here.",
            "Missing license fields/files require source review; no license is inferred from absence."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(body, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "packages": len(packages), "models": len(body["models"]),
        "missing_declarations": body["packages_without_machine_readable_declaration"],
        "missing_bundled_license_files": len(body["packages_without_bundled_license_files"])}))


if __name__ == "__main__":
    main()
