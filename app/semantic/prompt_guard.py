import asyncio
from pathlib import Path

from app.core.transaction import text_leaves
from app.semantic.base import SemanticRisk, SemanticUnavailable


class PromptGuardProvider:
    """Prompt Guard 2 binary classifier with overlapping windows; local weights only."""
    provider_id = "prompt_guard"

    def __init__(self, path: str):
        self.path = path
        self.tokenizer = self.model = None
        self._inflight = None

    def _load(self):
        if not Path(self.path).is_dir():
            raise SemanticUnavailable("Prompt Guard weights are not installed")
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.tokenizer = AutoTokenizer.from_pretrained(self.path, local_files_only=True)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.path, local_files_only=True)
        self.model.eval()

    def _analyze(self, texts):
        import torch

        if self.model is None:
            self._load()
        score = 0.0
        # Scan leaves separately to avoid merging attacker content into a trusted instruction stream.
        for text in texts:
            tokens = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                stride=64,
                return_overflowing_tokens=True,
                padding=True,
            )
            tokens.pop("overflow_to_sample_mapping", None)
            for offset in range(0, len(tokens["input_ids"]), 8):
                with torch.inference_mode():
                    logits = self.model(**{k: v[offset : offset + 8] for k, v in tokens.items()}).logits
                    # Prompt Guard 2's malicious class is index 1; reject incompatible model weights.
                    if logits.shape[-1] != 2:
                        raise SemanticUnavailable("Expected Prompt Guard 2 binary classifier")
                    score = max(score, float(torch.softmax(logits, dim=-1)[:, 1].max()))
        return SemanticRisk(prompt_injection=score)

    async def analyze(self, transaction):
        if self._inflight is not None and not self._inflight.done():
            raise SemanticUnavailable("Prompt Guard is busy")
        self._inflight = asyncio.create_task(
            asyncio.to_thread(self._analyze, [t for _, t in text_leaves(transaction.payload)])
        )
        self._inflight.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
        try:
            # A timeout does not create unlimited background inference jobs.
            return await asyncio.shield(self._inflight)
        except Exception as exc:
            raise SemanticUnavailable("Prompt Guard inference unavailable") from exc
