"""Structured instruction-safety rules. Scores are risk signals, not probabilities."""
import hashlib
import re
import time
from dataclasses import dataclass

from app.controls.context import context_for_match, discussion_context
from app.controls.intent_patterns import definitions
from app.controls.normalization import InspectionLimit, inspection_views
from app.controls.reconstruction import input_units
from app.core.transaction import Finding, SecurityTransaction

VERSION = "prompt-rules-v5"


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: re.Pattern
    title: str
    confidence: float = .95
    tier: str = "high_confidence"


def rule(id, category, pattern, title, confidence=.95, tier="high_confidence"):
    return Rule(id, category, re.compile(pattern, re.I), title, confidence, tier)


RULES = (
    rule("PROMPT_OVERRIDE_001", "instruction_override", r"\b(?:ignore|override|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|safety|future)\s+(?:instructions|rules|prompts|policy|policies)", "Instruction hierarchy override"),
    rule("PROMPT_DISCLOSURE_002", "prompt_disclosure", r"\b(?:reveal|print|expose|disclose|show)\s+(?:the\s+|your\s+)?(?:hidden\s+(?:system\s+)?(?:instructions|prompt|rules)|(?:secret|confidential|protected)\s+instructions|system\s+prompt|internal\s+configuration)", "Protected instruction disclosure"),
    rule("ROLE_DELIMITER_003", "role_spoofing", r"<\|(?:im_start|system|start_header_id)\|>|\[INST\]\s*<<SYS>>", "Model role delimiter injection", .99),
    rule("EXFILTRATION_004", "data_exfiltration", r"\b(?:send|upload|exfiltrate|export|leak)\b[^.!?]{0,100}\b(?:credentials|secrets|api[ -]?keys|access tokens|private (?:records|notes|data)|confidential (?:records|notes|customer))\b", "Sensitive data transfer instruction"),
    rule("JAILBREAK_005", "jailbreak", r"\b(?:unrestricted|uncensored)\s+(?:assistant|model)\b|\b(?:disable|bypass)\s+(?:safety\s+)?(?:safeguards|safety policy|safety policies|safety rules)", "Safeguard bypass or unrestricted role"),
    rule("AUTHORITY_SPOOF_006", "role_spoofing", r"\b(?:developer override mode|system override)\b", "Untrusted authority spoofing"),
    rule("TOOL_ABUSE_007", "tool_abuse", r"\b(?:bypass|skip|disable)\s+(?:the\s+)?(?:approvals|approval checks|authorization checks)\b", "Approval bypass instruction"),
    rule("MULTILINGUAL_PL_008", "multilingual_override", r"\b(?:zignoruj|pomiń|pomijaj)\s+(?:poprzednie\s+instrukcje|zasady(?:\s+bezpieczeństwa)?)|\b(?:ujawnij|wyślij)\s+(?:tajne|prywatne|ukryte)\s+(?:dane|instrukcje|prompt)", "Polish override or disclosure instruction"),
    rule("MULTILINGUAL_ES_009", "multilingual_override", r"\bignora\s+las\s+instrucciones\s+anteriores|\brevela\s+el\s+prompt\s+del\s+sistema", "Spanish override instruction"),
    rule("MULTILINGUAL_DE_010", "multilingual_override", r"\bignoriere\s+(?:vorherige|alle)\s+anweisungen|\bzeige\s+geheime\s+systemanweisungen", "German override instruction"),
    rule("MULTILINGUAL_FR_011", "multilingual_override", r"\bignore\s+(?:les\s+)?instructions\s+précédentes|\brévèle\s+(?:le\s+)?prompt\s+système|\bcontourne\s+les\s+autorisations", "French override or authorization bypass"),
    rule("MULTILINGUAL_IT_012", "multilingual_override", r"\bignora\s+le\s+istruzioni\s+precedenti|\brivela\s+il\s+prompt\s+di\s+sistema|\bsalta\s+le\s+autorizzazioni", "Italian override or authorization bypass"),
    rule("MULTILINGUAL_PT_013", "multilingual_override", r"\bignore\s+as\s+instruções\s+anteriores|\brevele\s+o\s+prompt\s+do\s+sistema|\bignore\s+a\s+aprovação", "Portuguese override or approval bypass"),
    rule("MULTILINGUAL_UK_014", "multilingual_override", r"ігноруй\s+попередні\s+інструкції|розкрий\s+системний\s+промпт|обійди\s+погодження", "Ukrainian override or approval bypass"),
    rule("MULTILINGUAL_RU_015", "multilingual_override", r"игнорируй\s+предыдущие\s+инструкции|раскрой\s+системный\s+промпт|обойди\s+согласование", "Russian override or approval bypass"),
    rule("MULTILINGUAL_CS_016", "multilingual_override", r"\bignoruj\s+předchozí\s+pokyny|\bodhal\s+systémový\s+prompt|\bobejdi\s+schválení", "Czech override or approval bypass"),
    rule("TASK_HIJACK_017", "task_hijacking", r"\b(?:abandon|stop obeying|disregard)\s+the\s+user(?:'s)?\s+(?:task|query|request|objective)|\b(?:grant|delegate)\b[^.!?]{0,80}\b(?:administrator privileges|administrator capability|administrative control)", "Task or privilege manipulation"),
    rule("DATA_FLOW_018", "data_exfiltration", r"\b(?:copy|put|take|attach|transfer)\b[^.!?]{0,100}\b(?:confidential dossier|restricted spreadsheet|internal personnel archive|payroll addresses)\b[^.!?]{0,140}\b(?:outside|stranger|outsider|beyond the company|external)", "Unauthorized sensitive data movement"),
    rule("CONTEXT_AUTHORITY_019", "role_spoofing", r"\b(?:sole authority|rules of the developer|rules from your creators|constraints from your creators)\b", "Contextual authority claim", .55, "weak_signal"),
    rule("TOOL_SEQUENCE_020", "tool_abuse", r"\b(?:payment tool|administrator deletion tool|shell execution)\b", "Sensitive tool selection context", .65, "contextual_heuristic"),
)
RULES += tuple(rule(*definition) for definition in definitions())

# Compatibility for consumers that inspect the historical pattern list.
PATTERNS = [item.pattern.pattern for item in RULES]


def inspect(tx: SecurityTransaction) -> list[Finding]:
    started = time.perf_counter()
    findings = []
    preprocessing = set()
    contextual = []
    try:
            units=input_units(tx)
            discussion_origins=set()
            if tx.context.source_trust=="trusted":
                for group in (u for u in units if u.reconstructed and u.role in {"user","data"}):
                    if discussion_context(inspection_views(group.text)[-1].text):
                        discussion_origins.update(group.origins)
            for unit in units:
                path,text = unit.path,unit.text
                seen = set()
                for view in inspection_views(text):
                    preprocessing.update(view.transformations)
                    for item in RULES:
                        trusted = tx.context.source_trust == "trusted" and unit.role in {"user", "data"}
                        match = None
                        for candidate in item.pattern.finditer(view.text):
                            context = context_for_match(view.text,candidate.start(),candidate.end(),trusted)
                            if trusted and unit.path in discussion_origins and context=="instruction":
                                context="explanatory_mention"
                            if context in {"negated","quoted_discussion"}:
                                contextual.append({"rule_id":item.id,"context":context})
                                continue
                            match = candidate
                            break
                        if match and item.id not in seen:
                            seen.add(item.id)
                            tier="contextual_heuristic" if context=="explanatory_mention" else item.tier
                            confidence=min(item.confidence,.55) if context=="explanatory_mention" else item.confidence
                            findings.append(Finding(code="PROMPT_INJECTION_PATTERN", control="prompt-patterns",
                                path=list(path), rule_id=item.id, category=item.category,
                                confidence=confidence, title=item.title, version=VERSION,
                                action="BLOCK" if tier=="high_confidence" else "WARN",
                                severity="high" if tier=="high_confidence" else "medium",
                                description="An instruction-safety pattern matched an inspection view.",
                                remediation="Treat retrieved content as data; remove overrides and require authorized data flows.",
                                evidence={"sha256": hashlib.sha256(text.encode()).hexdigest(),
                                    "matched_pattern": item.id, "view_transformations": list(view.transformations),
                                    "tier": tier,"context":context, "reconstructed": unit.reconstructed,
                                    "origin_count": len(unit.origins), "normalized_start": match.start(), "normalized_end": match.end(),
                                    "location": "normalized view; offsets do not address executable arguments"}))
                            if len(findings)>=64:
                                break
                    if len(findings)>=64:
                        break
                if len(findings) >= 64:
                    break
    except (InspectionLimit, UnicodeError):
        findings.append(Finding(code="INSPECTION_LIMIT_EXCEEDED", control="preprocessing", rule_id="INPUT_LIMIT_001",
            severity="critical",evidence={"tier":"hard_invariant"}))
    blocking_score=max((f.confidence for f in findings if f.action=="BLOCK"), default=0)
    tx.risk.prompt_injection = max(tx.risk.prompt_injection, blocking_score)
    tx.metadata["deterministic_detection"] = {"detector": "prompt-patterns", "type": "deterministic",
        "version": VERSION, "status": "ok", "score": blocking_score,
        "weak_score":max((f.confidence for f in findings if f.action!="BLOCK"),default=0),
        "verdict": "malicious" if blocking_score else "review" if findings else "benign", "latency_ms": (time.perf_counter() - started) * 1000,
        "contextual_matches": contextual[:32],
        "rule_ids": sorted({f.rule_id for f in findings if f.rule_id}),
        "preprocessing": sorted(preprocessing)}
    return findings
