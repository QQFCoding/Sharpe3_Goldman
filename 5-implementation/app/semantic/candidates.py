"""Pinned exploratory models. Runtime defaults never select candidates implicitly."""
import hashlib
import json

from app.semantic.base import SemanticUnavailable
from app.semantic.prompt_guard import PromptGuardProvider
from app.settings import ROOT

LABELS={"deepset":{0:"LEGIT",1:"INJECTION"},"distilbert":{0:"LABEL_0",1:"LABEL_1"}}


class CandidateProvider(PromptGuardProvider):
    def __init__(self,name,cpu_threads=2):
        if name not in LABELS:
            raise ValueError("Unknown pinned candidate")
        self.provider_id=name
        super().__init__(str(ROOT/"models"/name),cpu_threads)

    def _load(self):
        self.model=self.tokenizer=None
        try:
            lock=json.loads((ROOT/f"config/{self.provider_id}.lock.json").read_text())
            for filename,expected in lock["files"].items():
                path=ROOT/"models"/self.provider_id/filename
                if not path.is_file() or path.is_symlink():
                    raise SemanticUnavailable("Candidate artifact missing")
                with path.open("rb") as stream:
                    if hashlib.file_digest(stream,"sha256").hexdigest()!=expected:
                        raise SemanticUnavailable("Candidate artifact changed")
            super()._load()
            if self.model.config.id2label!=LABELS[self.provider_id] or self.model.config.num_labels!=2:
                raise SemanticUnavailable("Candidate labels incompatible")
            self.model_revision=lock["revision"]
            self.model_artifact_sha256=lock["files"]["model.safetensors"]
        except Exception:
            self.model=self.tokenizer=None
            raise
