"""Schema validity and field projection are separate from instruction safety."""
import copy

from jsonschema import Draft202012Validator

from app.core.transaction import Finding


def input_minimize(tool, arguments, field_labels):
    if not Draft202012Validator(tool.schema).is_valid(arguments):
        return arguments, [Finding(code="SCHEMA_INVALID", control="tool-input-minimizer")]
    declared = tool.schema.get("properties", {})
    if set(arguments) - set(declared):
        return arguments, [Finding(code="UNDECLARED_TOOL_FIELD", control="tool-input-minimizer")]
    selected = set(tool.input_fields if tool.input_fields is not None else declared)
    if not set(tool.schema.get("required", [])) <= selected:
        return arguments, [Finding(code="TOOL_PROJECTION_INVALID", control="tool-input-minimizer")]
    minimized = {k: copy.deepcopy(v) for k, v in arguments.items() if k in selected}
    findings = []
    for path, rule in tool.argument_rules.items():
        if path not in minimized:
            continue
        label = field_labels.get(path)
        if label is None:
            findings.append(Finding(code="TOOL_FIELD_PROVENANCE_MISSING", control="tool-input-minimizer"))
        elif (not label.confidentiality <= set(rule.get("confidentiality", ["public", "internal", "private", "secret"]))
            or label.integrity not in rule.get("integrity", ["trusted", "derived", "untrusted"])):
            findings.append(Finding(code="TOOL_FIELD_FLOW_VIOLATION", control="tool-input-minimizer"))
    return minimized, findings


def output_sanitize(tool, output, limit, requested=None):
    from app.controls.base import encoded
    if len(encoded(output)) > limit:
        return None, [Finding(code="RESPONSE_TOO_LARGE", control="tool-output-sanitizer")]
    if not Draft202012Validator(tool.output_schema).is_valid(output):
        return None, [Finding(code="OUTPUT_SCHEMA_INVALID", control="tool-output-sanitizer")]
    if not isinstance(output, dict):
        return None, [Finding(code="OUTPUT_SCHEMA_INVALID", control="tool-output-sanitizer")]
    approved = set(tool.output_fields if tool.output_fields is not None else
        tool.output_schema.get("properties", {}))
    fields = set(requested) if requested is not None else approved
    if not fields <= approved:
        return None, [Finding(code="OUTPUT_FIELD_NOT_APPROVED", control="tool-output-sanitizer")]
    return {k: copy.deepcopy(v) for k, v in output.items() if k in fields}, []
