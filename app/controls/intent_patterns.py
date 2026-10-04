"""Action plus protected object evidence. Bounded spans, shared context handling.

Lexicons generalize action/object combinations; they are not whole-input bypass
lists. Ordinary tool use and public data movement are not blocking evidence.
"""

DATA = r"(?:credentials|secrets|api[ -]?keys|access tokens|private (?:records|notes|data|files)|confidential \w+|restricted \w+|internal (?:personnel|customer|financial|payroll)\w*|payroll addresses|employee medical|customer database|staff (?:records|directory))"
EXTERNAL = r"(?:outside|outsider|stranger|external|public (?:site|endpoint|bucket)|personal (?:email|account)|attacker|unapproved|beyond the company|off[- ]site)"
ACTION = r"(?:send|upload|export|copy|put|take|attach|transfer|forward|publish|post|deliver|transmit|serialize|bundle|move)"

# Imperative families, protected objects and optional grammatical intervening
# words. Native language scripts are kept intact by inspection normalization.
NATIVE_OVERRIDE = (
    (r"(?:zignoruj|ignoruj|pomiń|pomijaj|odrzuć|porzuć)",r"(?:instrukcj\w*|zasad\w*|reguł\w*|ogranicze\w*|poleceni\w*)"),
    (r"(?:ignoriere|umgehe|verwirf|überspringe|missachte)",r"(?:anweisung\w*|regel\w*|richtlinie\w*|genehmigung\w*|freigabe\w*|beschränkung\w*)"),
    (r"(?:ignora|omite|elude|descarta|abandona)",r"(?:instruccion\w*|instrucción\w*|reglas|políticas|aprobación|restricciones)"),
    (r"(?:ignore|contourne|écarte|abandonne|saute)",r"(?:instructions|règles|consignes|restrictions|autorisations|approbation)"),
    (r"(?:ignora|salta|aggira|scarta|abbandona)",r"(?:istruzioni|regole|vincoli|autorizzazioni|approvazione)"),
    (r"(?:ignore|ignora|omita|contorne|descarte)",r"(?:instruções|regras|restrições|aprovação|autorizações)"),
    (r"(?:ігноруй|ігноруйте|обійди|відкинь|знехтуй|пропусти)",r"(?:інструкці\w*|правил\w*|обмеженн\w*|погоджен\w*|дозвол\w*)"),
    (r"(?:игнорируй|игнорируйте|обойди|отбрось|отмени|пропусти)",r"(?:инструкци\w*|правил\w*|ограничени\w*|согласовани\w*|разрешени\w*)"),
    (r"(?:ignoruj|obejdi|vynech|zahoď|odmítni)",r"(?:pokyn\w*|instrukc\w*|pravid\w*|omezen\w*|schválen\w*|povolen\w*)"),
)
NATIVE_TRANSFER = (
    (r"(?:wyślij|prześlij|przekaż|przenieś|skopiuj)",r"(?:poufne|prywatne|chronione|wewnętrzne)",r"(?:obc\w*|zewnętrzn\w*|nieuprawnion\w*|osobist\w*|prywatn\w* konto)"),
    (r"(?:sende|übertrage|verschiebe|kopiere|exportiere)",r"(?:vertrauliche|private|geschützte|interne)",r"(?:fremd\w*|extern\w*|unbefugt\w*|persönlich\w*)"),
    (r"(?:envía|transfiere|traslada|copia|exporta)",r"(?:confidenciales|privados|protegidos|interna)",r"(?:desconocid\w*|extern\w*|no autorizado|personal|ajen\w*)"),
    (r"(?:envoie|transfère|déplace|copie|exporte)",r"(?:confidentiels|privés|protégés|interne)",r"(?:étrang\w*|externe|non autorisé|personnel)"),
    (r"(?:invia|trasferisci|sposta|copia|esporta)",r"(?:riservati|privati|protetti|interna)",r"(?:estrane\w*|estern\w*|non autorizzato|personale)"),
    (r"(?:envie|transfira|mova|copie|exporte)",r"(?:confidenciais|privados|protegidos|interna)",r"(?:estranh\w*|extern\w*|não autorizado|pessoal)"),
    (r"(?:надішли|передай|перемісти|скопіюй)",r"(?:конфіденційн\w*|приватн\w*|захищен\w*|внутрішн\w*)",r"(?:сторонн\w*|зовнішн\w*|неуповноважен\w*|особист\w*)"),
    (r"(?:отправь|передай|перемести|скопируй)",r"(?:конфиденциальн\w*|приватн\w*|защищ\w*|внутренн\w*)",r"(?:посторонн\w*|внешн\w*|неуполномоченн\w*|личн\w*)"),
    (r"(?:pošli|přenes|přesuň|zkopíruj)",r"(?:důvěrné|soukromé|chráněné|interní)",r"(?:ciz\w*|extern\w*|neoprávněn\w*|osobní)"),
)


def definitions():
    yield ("DATA_TRANSFER_021","data_exfiltration",
        rf"\b{ACTION}\b[^.!?]{{0,100}}\b{DATA}\b[^.!?]{{0,160}}\b{EXTERNAL}\b",
        "Protected data moved beyond its authorized boundary")
    yield ("PROTECTED_EXTRACT_022","prompt_disclosure",
        r"\b(?:repeat|return|output|recite|dump|extract|list|reproduce|serialize|translate)\b[^.!?]{0,60}\b(?:system prompt|developer instructions|hidden (?:rules|policy|instructions)|internal (?:configuration|policy)|protected instructions)\b",
        "Protected instruction extraction")
    yield ("TOOL_REDIRECT_023","tool_abuse",
        r"\b(?:call|invoke|choose|run|use|replace|substitute|switch)\b[^.!?]{0,90}\b(?:payment|deletion|delete|shell|administrator|write|transfer)\b[^.!?]{0,100}\b(?:instead of|rather than|even though|without (?:approval|authorization)|against the user|not requested)\b",
        "Tool action conflicts with the authorized task")
    yield ("TRUST_POISON_024","data_poisoning",
        r"\b(?:overwrite|replace|update|store|persist|insert|remember|mark)\b[^.!?]{0,100}\b(?:trusted|memory|safety record|policy|approval|allowlist)\b[^.!?]{0,140}\b(?:unnecessary|not required|always approved|automatically approve|trusted forever|disable|bypass|never check|skip)\b",
        "Persistent trust or approval manipulation")
    yield ("TASK_DIVERSION_025","task_hijacking",
        r"\b(?:ignore|replace|abandon|stop|forget|discard)\b[^.!?]{0,45}\b(?:user|original|requested|assigned)\b[^.!?]{0,50}\b(?:task|objective|request|goal|query)\b|\b(?:real|new|only) objective\b[^.!?]{0,100}\b(?:conceal|hide|advertise|promote|attacker)\b",
        "User task replaced by an unauthorized objective")
    for i,(action,target) in enumerate(NATIVE_OVERRIDE):
        yield (f"NATIVE_INTENT_{26+i:03}","multilingual_override",
            rf"\b{action}\b(?:\s+[\w'-]+){{0,4}}\s+{target}\b",
            "Native-language instruction or approval override")
    for i,(action,protected,external) in enumerate(NATIVE_TRANSFER):
        yield (f"NATIVE_TRANSFER_{35+i:03}","data_exfiltration",
            rf"\b{action}\b[^.!?]{{0,80}}\b{protected}\b[^.!?]{{0,120}}\b{external}\b",
            "Native-language protected data boundary violation")
