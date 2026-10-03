"""Explicit opt-in model download, never part of startup or basic tests."""

import argparse
from pathlib import Path


def main():
    from huggingface_hub import snapshot_download

    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True, help="Pin a reviewed Hugging Face commit SHA")
    parser.add_argument(
        "--destination", default=str(Path(__file__).resolve().parents[1] / "models/prompt-guard")
    )
    args = parser.parse_args()
    snapshot_download(
        "meta-llama/Llama-Prompt-Guard-2-86M",
        revision=args.revision,
        local_dir=args.destination,
        allow_patterns=["*.json", "*.safetensors", "*.model", "tokenizer*", "special_tokens_map.json"],
    )


if __name__ == "__main__":
    main()
