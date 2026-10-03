import ast
import json

from app.settings import ROOT


def test_regression_metadata_maps_to_executed_assertions():
    names = {node.name for path in (ROOT / "tests").rglob("test_*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    required = {"attack_category", "source", "expected_decision", "expected_sink_behavior", "reason_code",
        "semantic_detection_expected", "deterministic_enforcement_alone", "test"}
    cases = []
    for path in (ROOT / "tests/corpus/regressions").glob("*.json"):
        cases += json.loads(path.read_text(encoding="utf-8"))
    assert len(cases) >= 13
    for case in cases:
        assert required <= set(case)
        assert case["test"] in names
