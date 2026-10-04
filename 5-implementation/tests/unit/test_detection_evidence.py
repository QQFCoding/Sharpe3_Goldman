import json
from types import SimpleNamespace

import pytest

from app.evaluation import evidence
from app.semantic.base import SemanticUnavailable
from app.semantic.deberta import DebertaProvider
from app.semantic.prompt_guard import PromptGuardProvider
from app.settings import ROOT


def test_report_binding_changes_for_code_and_actual_model_bytes(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    source = tmp_path / "app/detector.py"
    source.write_text("version = 1")
    (tmp_path / "config").mkdir()
    (tmp_path / "config/deberta.lock.json").write_text(json.dumps({"files": {"weights": "expected"}}))
    (tmp_path / "models/deberta").mkdir(parents=True)
    weights = tmp_path / "models/deberta/weights"
    weights.write_bytes(b"first model")
    monkeypatch.setattr(evidence, "ROOT", tmp_path)
    first = evidence.source_fingerprint()
    assert first == evidence.source_fingerprint()
    source.write_text("version = 2")
    second = evidence.source_fingerprint()
    assert second != first
    weights.write_bytes(b"changed model artifact")
    assert evidence.source_fingerprint() != second
    weights.unlink()
    assert evidence.source_fingerprint() != second


def test_invalid_model_labels_do_not_leave_a_usable_failed_model(tmp_path, monkeypatch):
    import hashlib
    from pathlib import Path

    lock = json.loads((ROOT / "config/deberta.lock.json").read_text())
    for name in lock["files"]:
        (tmp_path / name).write_bytes(b"test-only artifact")
    monkeypatch.setattr(hashlib, "file_digest", lambda stream, algorithm:
        SimpleNamespace(hexdigest=lambda: lock["files"][Path(stream.name).name]))
    def incompatible(provider):
        provider.model = SimpleNamespace(config=SimpleNamespace(id2label={0: "INJECTION", 1: "SAFE"}, num_labels=2))
        provider.tokenizer = object()
    monkeypatch.setattr(PromptGuardProvider, "_load", incompatible)
    provider = DebertaProvider(str(tmp_path))
    for _ in range(2):
        with pytest.raises(SemanticUnavailable, match="binary injection classifier"):
            provider._load()
        assert provider.model is None and provider.tokenizer is None
