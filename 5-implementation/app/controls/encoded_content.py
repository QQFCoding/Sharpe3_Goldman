"""Decoded privacy controls cannot redact source offsets safely; reject instead."""
from app.controls import pii, secrets
from app.controls.normalization import InspectionLimit, inspection_views
from app.controls.reconstruction import InputUnit, input_units
from app.core.transaction import Finding, text_leaves
from app.detection.trace import active_trace


def inspect(tx, secrets_enabled=True, pii_enabled=True):
    findings = []
    try:
        leaves=list(text_leaves(tx.payload))
        originals=dict(leaves)
        units=[InputUnit(text,path,(path,)) for path,text in leaves]
        units += [u for u in input_units(tx) if u.reconstructed or "[key]" in u.path]
        for unit in units:
            path,text=unit.path,unit.text
            for view in inspection_views(text):
                if view.text == text and not unit.reconstructed and "[key]" not in path:
                    continue
                scan = tx.model_copy(update={"payload": view.text})
                secret=bool(secrets_enabled and secrets.inspect(scan,"BLOCK"))
                private=bool(pii_enabled and (unit.reconstructed or any(method.endswith("decode") for method in view.transformations)) and pii.inspect(scan,"BLOCK"))
                if secret:
                    findings.append(Finding(code="SECRET_DETECTED", control="reconstructed-secrets" if unit.reconstructed else "decoded-secrets", path=list(path),
                        rule_id="ENCODED_SECRET_001", category="secret_exposure", severity="critical",
                        title="Secret found in reconstructed or decoded content", remediation="Remove the secret and rotate it if exposed.",
                        evidence={"view_transformations": list(view.transformations),"reconstructed":unit.reconstructed,"origin_count":len(unit.origins)}))
                if private:
                    findings.append(Finding(code="ENCODED_PII_DETECTED", control="reconstructed-privacy" if unit.reconstructed else "decoded-privacy", path=list(path),
                        rule_id="ENCODED_PII_002", category="privacy", title="Personal data found in encoded content",
                        remediation="Remove encoded personal data; source spans cannot be safely redacted."))
                trace=active_trace.get()
                if (secret or private) and trace is not None:
                    trace.withheld_text.update([text,view.text,*[originals[p] for p in unit.origins if p in originals]])
                    trace.withheld_text.update(v.text for p in unit.origins if p in originals
                        for v in inspection_views(originals[p]))
    except (InspectionLimit, UnicodeError):
        findings.append(Finding(code="INSPECTION_LIMIT_EXCEEDED", control="preprocessing"))
    return findings[:64]
