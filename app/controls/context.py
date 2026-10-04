"""Local quote/negation evidence, never a whole-request allowlist.

Only a matched span fully inside a quoted/code discussion is downgraded. Other
instructions and hard invariants remain independently actionable.
"""
import re

from app.controls.intent_patterns import ACTION, NATIVE_OVERRIDE, NATIVE_TRANSFER

QUOTES = re.compile(r"```[\s\S]*?```|`[^`\n]+`|\"[^\"\n]+\"|(?<!\w)'(?:[^'\n]|(?<=\w)'(?=\w))+'(?!\w)|[«“„][^»”\n]+[»”“]|‘[^’\n]+’")
DISCUSS = re.compile(r"\b(?:explain|analy[sz]e|document|describe|discuss|review|classify|compare|teach|why)\b|"
    r"\b(?:write|create|build|test|improve|debug|maintain|refactor)\s+(?:a\s+|the\s+)?(?:regex|regular expression|detector|detection rule|unit test|rule|scanner)\b|"
    r"\b(?:paper|study|incident|log|example|pattern|regex|test|report)\b[^.!?]{0,60}\b(?:describes|documents|contains|matches|discusses|quotes|illustrates|analy[sz]es|detects|reports|explores)\b|"
    r"\b(?:wyjaśnij|opisz|przeanalizuj|omów|erkläre|erläutere|beschreibe|analysiere|explica|explicar|analiza|describe|explique|expliquer|analyse|décris|spiega|descrivi|analizza|descreva|explique|analise|поясни|поясніть|опиши|проаналізуй|объясни|объясните|опиши|проанализируй|vysvětli|popiš|analyzuj)\b", re.I)
EXECUTE = re.compile(r"\b(?:then|now|actually|instead|before answering|after explaining|must obey|must follow|carry out|execute|follow that|follow it)\b|\b(?:send|upload|export|copy|put|grant|delegate|disclose|reveal|disable|bypass|ignore|disregard|teraz|następnie|wyślij|ujawnij|zignoruj|dann|jetzt|sende|umgehe|ignoriere|ahora|envía|ignora|revela|ensuite|envoie|révèle|ignora|invia|rivela|agora|envie|revele|надішли|розкрий|ігноруй|отправь|раскрой|игнорируй|pošli|odhal|ignoruj)\b", re.I)
EXECUTE = re.compile(EXECUTE.pattern+rf"|\b{ACTION}\b|"+"|".join(rf"\b{item[0]}\b" for item in (*NATIVE_OVERRIDE,*NATIVE_TRANSFER)),re.I)
EXECUTE = re.compile(EXECUTE.pattern+r"|\b(?:return|output|recite|dump|extract|reproduce|serialize|invoke|call|choose|replace|overwrite|persist|override|forget|abandon|stop|reveal|print|expose|disclose|show|disable|bypass|skip|grant|delegate|exfiltrate|leak|repeat|list|translate|use|run|switch|substitute|store|insert|remember|mark|update|perform|implement|apply|adopt)\b|(?<![-\w])mail\b",re.I)
NEGATION = re.compile(r"\b(?:never|do not|don't|must not|should not|cannot|prevent|refuse to|without|nie|nigdy|nicht|niemals|no|sin|non|sans|não|sem|ne|не|ніколи)\s+(?:\w+\s+){0,2}$", re.I)
MENTION = re.compile(r"\b(?:phrase|sentence|string|literal|pattern|fixture|quoted|attacker|attack|known technique|paper|incident|log|why|regex|example|detector|test|research|training|technique|documentation)\b|"
    r"\b(?:benchmark|adversarial|security|email|e-mail|correos?|courriels?|malicioso|malveillant|detection|quoting|quotation)\b|"
    r"\b(?:atak\w*|fraz\w*|zdani\w*|przykład\w*|wzorc\w*|dokumentacj\w*|angriff\w*|satz|zeichenfolge|beispiel\w*|muster|ataque\w*|frase\w*|ejemplo\w*|patrón|attaque\w*|phrase\w*|exemple\w*|motif|attacco|attacchi|esempio|modello|exemplo\w*|padrão|атак\w*|фраз\w*|приклад\w*|пример\w*|шаблон\w*|útok\w*|fráz\w*|příklad\w*|vzor\w*)\b",re.I)
FOLLOW_THROUGH = re.compile(r"\b(?:(?:perform|implement|apply|enact|adopt|follow)(?:\s+the)?\s+(?:it|that|this|(?:quoted|above|given)\s+(?:instruction|directive|command|action)s?)|do\s+(?:it|that)|act on\s+(?:it|that|this))\b",re.I)
FOLLOW_THROUGH = re.compile(FOLLOW_THROUGH.pattern + r"|\b(?:wykonaj|zastosuj|befolge|führe|ejecuta|aplica|exécute|applique|esegui|applica|execute|aplique|виконай|застосуй|выполни|примени|proveď|použij)\b",re.I)
EXECUTION_FRAME = re.compile(r"\b(?:then|now|actually|instead|obey me|obey this|must obey|execute|carry out|must follow|you must|follow that|follow it|teraz|następnie|jetzt|ahora|ensuite|agora)\b",re.I)
DEFENSIVE = re.compile(r"\b(?:prevent|prevention|defend|protect|impedire|prevenir|prévenir|impedir|zapobiegać|verhindern|zabránit)\b",re.I)
COMPARISON = re.compile(r"\b(?:difference|distinction)\s+between\s+(?:quoting|mentioning|describing|discussing)\b[^;.!?]{0,180}\band\s+(?:asking|requesting|executing|execution)\b[^;.!?]{0,100}$",re.I)
ROLE_FRAME = re.compile(r"<\|(?:im_start|system|start_header_id)\|>|\[INST\]\s*<<SYS>>",re.I)
POLITE_PREFIX = re.compile(r"\s*(?:(?:please|can you|could you|the|a|an|this)\s+)?",re.I)
CLAUSE_JOIN = re.compile(r"[,;:]|\s+(?:and|then|y|et|und|i|e|a|та|и|а)\s+",re.I)


def explanatory_mention(text):
    # Each risky sentence needs its own discussion frame. An adjacent imperative
    # cannot inherit an exemption from an earlier educational sentence.
    meaningful=False
    for sentence in re.split(r"[.!?\n]",text):
        frame=DISCUSS.search(sentence[:180])
        spans=quote_spans(sentence)
        if any(not any(a<=m.start() and m.end()<=b for a,b in spans) for m in ROLE_FRAME.finditer(sentence)):
            return False
        risky=list(EXECUTE.finditer(sentence)) or list(re.finditer(r"\b(?:uncensored|unrestricted|system prompt|hidden instructions)\b",sentence,re.I))
        if not risky:
            if (frame and POLITE_PREFIX.fullmatch(sentence[:frame.start()]) and not CLAUSE_JOIN.search(sentence)
                and (MENTION.search(sentence) or DEFENSIVE.search(sentence)) and not FOLLOW_THROUGH.search(sentence)):
                meaningful=True
            continue
        if all(NEGATION.search(sentence[max(0,m.start()-45):m.start()]) for m in risky):
            continue
        comparison_match=COMPARISON.search(sentence) if frame else None
        comparison=bool(comparison_match)
        follow=[m for m in FOLLOW_THROUGH.finditer(sentence)
            if not NEGATION.search(sentence[max(0,m.start()-45):m.start()])
            and not (comparison and m[0].lower()=="execute" and m.start()>=comparison_match.start())]
        execution_frames=[m for m in EXECUTION_FRAME.finditer(sentence)
            if not NEGATION.search(sentence[max(0,m.start()-45):m.start()])
            and not (comparison and m[0].lower()=="execute")]
        if not frame or frame.start()>risky[0].start() or not MENTION.search(sentence) or execution_frames or follow:
            return False
        for cue in risky:
            if NEGATION.search(sentence[max(0,cue.start()-45):cue.start()]):
                continue
            if any(a<=cue.start() and cue.end()<=b for a,b in spans):
                continue
            if comparison and cue[0].lower()=="execute":
                continue
            # A later clause cannot inherit an earlier educational frame.
            prefix=re.split(r"[,;:]|\band\b",sentence[:cue.start()],flags=re.I)[-1]
            if not MENTION.search(prefix) and not re.search(r"\b(?:why|what|whether)\b",prefix,re.I):
                return False
        meaningful=True
    return meaningful


def quote_spans(text):
    return [(m.start(), m.end()) for m in QUOTES.finditer(text)]


def context_for_match(text, start, end, trusted=True):
    prefix = text[max(0, start-45):start]
    if NEGATION.search(prefix):
        return "negated"
    if trusted and DISCUSS.search(text[max(0,start-180):start]) and quoted_discussion(text,trusted):
        if any(a <= start and end <= b for a,b in quote_spans(text)):
            return "quoted_discussion"
    if trusted and explanatory_mention(text):
        return "explanatory_mention"
    return "instruction"


def quoted_discussion(text, trusted=True):
    """A structural, conservative context adjustment for real model scores."""
    if not trusted:
        return False
    spans = quote_spans(text)
    if not spans:
        return False
    if not any(DISCUSS.search(text[max(0,a-180):a]) for a,b in spans):
        return False
    outside = text
    for a,b in reversed(spans):
        outside = outside[:a] + " [QUOTED DATA] " + outside[b:]
    if ROLE_FRAME.search(outside):
        return False
    # Any execution cue outside the data disables the adjustment.
    cues=[*EXECUTE.finditer(outside),*FOLLOW_THROUGH.finditer(outside)]
    return not any(not NEGATION.search(outside[max(0,m.start()-45):m.start()]) for m in cues)


def discussion_context(text,trusted=True):
    return trusted and (quoted_discussion(text,trusted) or explanatory_mention(text))


def observational_question(text):
    return bool(re.fullmatch(r"\s*(?:why\s+(?:is|are|does)|what\s+(?:is|does))\b[^?\n]{1,300}\?\s*",text,re.I)
        and not EXECUTION_FRAME.search(text))
