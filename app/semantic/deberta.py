from app.semantic.prompt_guard import PromptGuardProvider


class DebertaProvider(PromptGuardProvider):
    """Public ProtectAI v2 classifier. Shared bounded/windowed inference implementation."""
    provider_id = "deberta"
    def _load(self):
        super()._load()
        labels = {int(k): str(v).upper() for k, v in self.model.config.id2label.items()}
        if labels.get(1) not in {"INJECTION", "LABEL_1"} or self.model.config.num_labels != 2:
            from app.semantic.base import SemanticUnavailable
            raise SemanticUnavailable("Expected ProtectAI binary injection classifier")
