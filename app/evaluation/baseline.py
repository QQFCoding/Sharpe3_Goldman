"""Load the archived pre-change detector implementations only for explicit offline evaluation."""
import importlib.util

from app.settings import ROOT


def module(name):
    path = ROOT / "docs/baseline" / (name + ".py")
    spec = importlib.util.spec_from_file_location("aicl_baseline_" + name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def detectors():
    patterns = module("prompt_patterns")
    patterns.security_discussion = module("discussion").security_discussion
    legacy = module("prompt_guard")

    class BaselineDeberta(legacy.PromptGuardProvider):
        provider_id = "deberta"

        def _load(self):
            super()._load()
            labels = {int(k): str(v).upper() for k, v in self.model.config.id2label.items()}
            if labels.get(1) not in {"INJECTION", "LABEL_1"} or self.model.config.num_labels != 2:
                from app.semantic.base import SemanticUnavailable
                raise SemanticUnavailable("Expected ProtectAI binary injection classifier")

    return patterns.inspect, BaselineDeberta
