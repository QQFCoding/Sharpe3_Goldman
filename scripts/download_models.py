"""Explicit opt-in model download, never part of startup or basic tests."""

import argparse
import hashlib
import os
from pathlib import Path


def main():
    os.environ.setdefault("HF_HUB_DISABLE_XET", "1")
    from huggingface_hub import snapshot_download

    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=["deberta", "prompt_guard"], default="deberta")
    parser.add_argument("--revision", help="Pin a reviewed Hugging Face commit SHA")
    parser.add_argument(
        "--destination"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.model == "prompt_guard" and not args.revision:
        parser.error("Prompt Guard requires an explicitly reviewed --revision and gated model access")
    repo = "protectai/deberta-v3-base-prompt-injection-v2" if args.model == "deberta" else "meta-llama/Llama-Prompt-Guard-2-86M"
    revision = args.revision or "e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5"
    destination = Path(args.destination or str(root / "models" / args.model.replace("_", "-")))
    patterns = ["config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json",
                "special_tokens_map.json", "spm.model", "tokenizer.model", "README.md"]
    if args.model == "deberta" and revision == "e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5":
        import httpx
        expected = "6521cb8d0ac08148c81464899c424e6148fcc62befa371089fa4061d8b6e0424"
        destination.mkdir(parents=True, exist_ok=True)
        weights = destination / "model.safetensors"
        if not weights.is_file() or hashlib.file_digest(weights.open("rb"), "sha256").hexdigest() != expected:
            temporary = destination / "model.safetensors.download"
            url = f"https://huggingface.co/{repo}/resolve/{revision}/model.safetensors?download=true"
            digest, total = hashlib.sha256(), 0
            with httpx.stream("GET", url, follow_redirects=True, timeout=60) as response, temporary.open("wb") as out:
                response.raise_for_status()
                for chunk in response.iter_bytes(1024 * 1024):
                    out.write(chunk)
                    digest.update(chunk)
                    total += len(chunk)
                    if total % (64 * 1024 * 1024) == 0:
                        print(f"Weights downloaded: {total // (1024 * 1024)} MiB", flush=True)
            if digest.hexdigest() != expected:
                raise ValueError("Pinned weight SHA-256 mismatch")
            temporary.replace(weights)
        patterns.remove("model.safetensors")
    snapshot_download(
        repo, revision=revision,
        cache_dir=str(root / ".tools/hf-cache"),
        local_dir=str(destination), allow_patterns=patterns,
    )
    print(f"Installed {repo} at immutable revision {revision}")


if __name__ == "__main__":
    main()
