from app.semantic.prompt_guard import PromptGuardProvider


class DebertaProvider(PromptGuardProvider):
    """Public ProtectAI v2 classifier. Shared bounded/windowed inference implementation."""
    provider_id = "deberta"
    def _load(self):
        self.model = self.tokenizer = None
        import hashlib
        import json
        from pathlib import Path

        from app.semantic.base import SemanticUnavailable
        from app.settings import ROOT

        lock = json.loads((ROOT / "config/deberta.lock.json").read_text())
        for name, expected in lock["files"].items():
            artifact = Path(self.path) / name
            if not artifact.is_file() or artifact.is_symlink():
                raise SemanticUnavailable("Pinned DeBERTa artifact missing")
            with artifact.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                    raise SemanticUnavailable("Pinned DeBERTa artifact changed")
        self.model_revision = lock["revision"]
        self.model_artifact_sha256=lock["files"]["model.safetensors"]
        super()._load()
        labels = {int(k): str(v).upper() for k, v in self.model.config.id2label.items()}
        if labels != {0: "SAFE", 1: "INJECTION"} or self.model.config.num_labels != 2:
            self.model = self.tokenizer = None
            raise SemanticUnavailable("Expected ProtectAI binary injection classifier")
