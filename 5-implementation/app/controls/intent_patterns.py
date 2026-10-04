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

# Authority cancellation must be coupled to an exclusive instruction from a
# competing principal. A mention of changed rules alone is not enough. Keep
# language families together, rather than mixing verbs from different scripts.
AUTHORITY_REPLACEMENT = (
    (r"(?:developer|system|initial|original)\s+(?:rules|instructions|policy)", r"(?:revoked|cancelled|canceled|void|no longer (?:apply|valid)|superseded)", r"(?:obey|follow|execute|heed)", r"(?:only|solely|exclusively)", r"(?:my|our|me)"),
    (r"(?:zasad\w*|instrukcj\w*|reguł\w*)\s+(?:twórc\w*|programist\w*|system\w*|początkow\w*)", r"(?:odwołan\w*|anulowan\w*|nie obowiązują|nieważn\w*)", r"(?:słuchaj|wykonuj|wykonaj|przestrzegaj|stosuj)", r"(?:tylko|wyłącznie|jedynie)", r"(?:moj\w*|mnie|nasz\w*)"),
    (r"(?:entwickler\w*|system\w*|ursprünglich\w*|anfänglich\w*|intern\w*)\s*(?:regel\w*|anweisung\w*|richtlini\w*)", r"(?:aufgehoben|widerrufen|ungültig|gelten nicht mehr|außer kraft)", r"(?:befolge|gehorche|folge|führe|hör\w*)", r"(?:nur|ausschließlich|allein)", r"(?:mein\w*|mir|uns\w*)"),
    (r"(?:reglas|instrucciones|políticas)\s+(?:(?:del|de los?)\s+)?(?:desarrollador\w*|sistema|iniciales|originales)", r"(?:anuladas|revocadas|canceladas|sin efecto|ya no (?:valen|rigen|se aplican))", r"(?:obedece|sigue|ejecuta|cumple|acata)", r"(?:solo|sólo|solamente|únicamente|exclusivamente)", r"(?:mis|mi|mí|nuestras)"),
    (r"(?:règles|instructions|consignes)\s+(?:(?:du|des|de la)\s+)?(?:développeur\w*|système|initiales|originales)", r"(?:annulées|révoquées|abrogées|ne s.appliquent plus|sans effet|invalides)", r"(?:obéis|suis|exécute|applique|respecte)", r"(?:uniquement|seulement|exclusivement)", r"(?:mes|mon|moi|nos)"),
    (r"(?:regole|istruzioni|direttive)\s+(?:(?:del|dello)\s+)?(?:sviluppatore|sistema|iniziali|originali)", r"(?:revocate|annullate|non valgono più|non si applicano più|invalide)", r"(?:obbedisci|segui|esegui|applica|rispetta)", r"(?:solo|soltanto|unicamente|esclusivamente)", r"(?:mie|miei|mio|me|nostre)"),
    (r"(?:regras|instruções|diretrizes)\s+(?:(?:do|dos|da)\s+)?(?:criador\w*|desenvolvedor\w*|sistema|iniciais|originais)", r"(?:revogadas|anuladas|canceladas|não (?:valem|se aplicam) mais|inválidas)", r"(?:obedeça|obedece|siga|segue|cumpra|execute)", r"(?:apenas|somente|só|exclusivamente)", r"(?:minhas|meus|minha|mim|nossas)"),
    (r"(?:правил\w*|інструкці\w*|настанов\w*)\s+(?:розробник\w*|творц\w*|систем\w*|початков\w*)", r"(?:скасован\w*|відкликан\w*|недійсн\w*|більше не діють)", r"(?:виконуй|виконай|слухай|дотримуйся|підкоряйся)", r"(?:лише|тільки|виключно)", r"(?:мої\w*|мого|мене|наші\w*)"),
    (r"(?:правил\w*|инструкци\w*|указани\w*)\s+(?:разработчик\w*|создател\w*|систем\w*|изначальн\w*)", r"(?:отменен\w*|отменён\w*|отозван\w*|недействительн\w*|больше не действуют)", r"(?:выполняй|выполни|слушай|следуй|подчиняйся)", r"(?:только|лишь|исключительно)", r"(?:мои\w*|моим|моего|меня|наши\w*)"),
    (r"(?:pravid\w*|pokyn\w*|instrukc\w*)\s+(?:vývojář\w*|tvůrc\w*|systém\w*|původní\w*)", r"(?:zrušen\w*|odvolan\w*|neplat\w*|už neplatí)", r"(?:poslouchej|uposlechni|vykonej|prováděj|řiď se|dodržuj)", r"(?:pouze|jen|výhradně)", r"(?:moj\w*|mé|mých|mně|naš\w*)"),
)

# Also covers future-exclusive obedience without a preceding cancellation claim.
EXCLUSIVE_CONTROL = (
    (r"(?:from now on|starting now|henceforth)", r"(?:listen|obey|follow)", r"(?:only|solely|exclusively)", r"(?:me|my (?:orders|commands|instructions))"),
    (r"(?:od teraz|od tej chwili)", r"(?:słuchaj|wykonuj|przestrzegaj)", r"(?:tylko|wyłącznie|jedynie)", r"(?:mnie|moj\w* (?:polecen\w*|rozkaz\w*|instrukcj\w*))"),
    (r"(?:ab jetzt|von nun an)", r"(?:befolge|gehorche|folge|höre|hör)", r"(?:nur|ausschließlich|allein)", r"(?:mir|mein\w* (?:befehle|anweisungen))"),
    (r"(?:a partir de ahora|desde ahora)", r"(?:obedece|sigue|cumple|acata)", r"(?:solo|sólo|únicamente|exclusivamente)", r"(?:mis (?:órdenes|instrucciones)|a mí)"),
    (r"(?:désormais|à partir de maintenant)", r"(?:obéis|suis|respecte)", r"(?:uniquement|seulement|exclusivement)", r"(?:mes (?:ordres|instructions)|moi)"),
    (r"(?:da ora|d.ora in poi)", r"(?:obbedisci|segui|esegui)", r"(?:solo|soltanto|unicamente)", r"(?:i miei (?:comandi|ordini)|le mie istruzioni|me)"),
    (r"(?:a partir de agora|de agora em diante)", r"(?:obedeça|obedece|siga|cumpra)", r"(?:apenas|somente|só)", r"(?:minhas (?:ordens|instruções)|a mim)"),
    (r"(?:відтепер|від цього моменту)", r"(?:слухай|виконуй|дотримуйся)", r"(?:лише|тільки|виключно)", r"(?:мене|мої\w* (?:наказ\w*|інструкці\w*))"),
    (r"(?:отныне|с этого момента)", r"(?:слушай|выполняй|следуй)", r"(?:только|лишь|исключительно)", r"(?:меня|мои\w* (?:приказ\w*|инструкци\w*))"),
    (r"(?:od teď|od této chvíle)", r"(?:poslouchej|uposlechni|prováděj|řiď se)", r"(?:pouze|jen|výhradně)", r"(?:mě|moj\w* (?:příkaz\w*|pokyn\w*))"),
)

PROTECTED_DISCLOSURE = (
    (r"(?:pokaż|ujawnij|wypisz|zwróć|odtwórz)", r"(?:ukryt\w*|tajn\w*|chronion\w*|systemow\w*|wewnętrzn\w*)", r"(?:instrukcj\w*|reguł\w*|prompt\w*|konfiguracj\w*)"),
    (r"(?:zeige|enthülle|offenbare|gib|reproduziere)", r"(?:geheim\w*|versteckt\w*|intern\w*|geschützt\w*|system\w*)", r"(?:(?:system)?anweisung\w*|regel\w*|prompt\w*|konfiguration\w*)"),
    (r"(?:muestra|revela|divulga|devuelve|reproduce)", r"(?:ocult\w*|secret\w*|protegid\w*|intern\w*|sistema)", r"(?:instruccion\w*|instrucción\w*|reglas|prompt|configuración)"),
    (r"(?:montre|révèle|divulgue|reproduis|affiche)", r"(?:caché\w*|secret\w*|protégé\w*|interne\w*|système)", r"(?:instructions|consignes|règles|prompt|configuration)"),
    (r"(?:mostra|rivela|divulga|restituisci|riproduci)", r"(?:nascost\w*|segret\w*|protett\w*|intern\w*|sistema)", r"(?:istruzioni|regole|prompt|configurazione)"),
    (r"(?:mostre|revele|divulgue|devolva|reproduza)", r"(?:ocult\w*|secret\w*|protegid\w*|intern\w*|sistema)", r"(?:instruções|regras|prompt|configuração)"),
    (r"(?:покажи|розкрий|виведи|поверни|відтвори)", r"(?:прихован\w*|таємн\w*|захищен\w*|внутрішн\w*|системн\w*)", r"(?:інструкці\w*|правил\w*|промпт\w*|конфігураці\w*)"),
    (r"(?:покажи|раскрой|выведи|верни|воспроизведи)", r"(?:скрыт\w*|секретн\w*|защищен\w*|защищён\w*|внутренн\w*|системн\w*)", r"(?:инструкци\w*|правил\w*|промпт\w*|конфигураци\w*)"),
    (r"(?:ukaž|odhal|vypiš|vrať|reprodukuj)", r"(?:skryt\w*|tajn\w*|chráněn\w*|intern\w*|systémov\w*)", r"(?:instrukc\w*|pokyn\w*|pravid\w*|prompt\w*|konfigurac\w*)"),
)

OWNED_AUTHORITY_SWAP = (
    (r"(?:my|our)\s+(?:orders|commands|instructions)", r"(?:replace|supersede|override)", r"(?:developer|system)\s+(?:rules|instructions|policy)"),
    (r"(?:moj\w*|nasz\w*)\s+(?:polecen\w*|rozkaz\w*|instrukcj\w*)", r"(?:zastępują|unieważniają|nadpisują)", r"(?:zasad\w*|instrukcj\w*|reguł\w*)\s+(?:twórc\w*|programist\w*|system\w*)"),
    (r"(?:mein\w*|uns\w*)\s+(?:befehle|anweisungen)", r"(?:ersetzen|überschreiben)", r"(?:entwickler\w*|system\w*)\s*(?:regel\w*|anweisung\w*)"),
    (r"(?:mis|nuestras)\s+(?:órdenes|instrucciones)", r"(?:sustituyen|reemplazan|anulan)", r"(?:reglas|instrucciones)\s+(?:del\s+)?(?:desarrollador|sistema)"),
    (r"(?:mes|nos)\s+(?:ordres|instructions)", r"(?:remplacent|annulent)", r"(?:règles|instructions)\s+(?:du\s+)?(?:développeur|système)"),
    (r"(?:i miei|le mie|le nostre)\s+(?:ordini|istruzioni|direttive)", r"(?:sostituiscono|annullano)", r"(?:regole|istruzioni)\s+(?:del\s+)?(?:sviluppatore|sistema)"),
    (r"(?:minhas|nossas)\s+(?:ordens|instruções)", r"(?:substituem|anulam)", r"(?:regras|instruções)\s+(?:do\s+)?(?:criador|sistema)"),
    (r"(?:мої\w*|наші\w*)\s+(?:наказ\w*|інструкці\w*)", r"(?:замінюють|скасовують)", r"(?:правил\w*|інструкці\w*)\s+(?:розробник\w*|систем\w*)"),
    (r"(?:мои\w*|наши\w*)\s+(?:приказ\w*|инструкци\w*)", r"(?:заменяют|отменяют)", r"(?:правил\w*|инструкци\w*)\s+(?:разработчик\w*|систем\w*)"),
    (r"(?:moj\w*|naš\w*)\s+(?:příkaz\w*|pokyn\w*)", r"(?:nahrazují|ruší)", r"(?:pravid\w*|pokyn\w*)\s+(?:vývojář\w*|systém\w*)"),
)


def definitions():
    yield ("DATA_TRANSFER_021","data_exfiltration",
        rf"\b{ACTION}\b[^.!?]{{0,100}}\b{DATA}\b[^.!?]{{0,160}}\b{EXTERNAL}\b",
        "Protected data moved beyond its authorized boundary")
    yield ("PROTECTED_EXTRACT_022","prompt_disclosure",
        r"\b(?:repeat|return|output|recite|dump|extract|list|reproduce|serialize|translate)\b[^.!?]{0,60}\b(?:system prompt|developer instructions|hidden (?:system )?(?:rules|policy|instructions)|internal (?:configuration|policy)|protected instructions)\b",
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
    for i,(target,cancel,obey,exclusive,owner) in enumerate(AUTHORITY_REPLACEMENT):
        yield (f"AUTHORITY_REPLACEMENT_{44+i:03}","instruction_override",
            rf"\b{target}\b[^.!?]{{0,75}}\b{cancel}\b[^.!?]{{0,110}}\b{obey}\b[^.!?]{{0,45}}\b{exclusive}\b[^.!?]{{0,45}}\b{owner}\b",
            "Trusted instruction authority replaced with exclusive personal control")
    for i,(future,obey,exclusive,owner) in enumerate(EXCLUSIVE_CONTROL):
        yield (f"EXCLUSIVE_CONTROL_{54+i:03}","instruction_override",
            rf"\b{future}\b[^.!?]{{0,45}}\b{obey}\b[^.!?]{{0,35}}\b{exclusive}\b[^.!?]{{0,40}}\b{owner}\b",
            "Exclusive future obedience to a competing principal")
    for i,(action,protected,target) in enumerate(PROTECTED_DISCLOSURE):
        # Romance languages place an adjective after the protected noun;
        # Slavic/German examples normally use adjective-before-noun order.
        yield (f"NATIVE_DISCLOSURE_{64+i:03}","prompt_disclosure",
            rf"\b{action}\b[^.!?]{{0,65}}(?:\b{protected}\b[^.!?]{{0,35}}\b{target}\b|\b{target}\b[^.!?]{{0,35}}\b{protected}\b)",
            "Native-language protected instruction disclosure")
    for i,(owned,replace,target) in enumerate(OWNED_AUTHORITY_SWAP):
        yield (f"OWNED_AUTHORITY_SWAP_{73+i:03}","instruction_override",
            rf"\b{owned}\b[^.!?]{{0,45}}\b{replace}\b[^.!?]{{0,65}}\b{target}\b",
            "Personal orders claim precedence over protected instruction authority")
