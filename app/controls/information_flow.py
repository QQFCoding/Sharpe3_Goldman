from app.core.labels import DataSecurityLabel

EXTERNAL_SINKS = {"email.send", "network.fetch", "http.post", "github.create_issue", "github.search",
                  "github.read_issue", "filesystem.write"}


def facts(tx, label: DataSecurityLabel, policy):
    name = tx.resource.name if tx.resource else ""
    external = name in EXTERNAL_SINKS or tx.effect == "external_side_effect"
    declassified = set()
    for grant in policy.information_flow.declassification:
        if name in grant.sinks and grant.required_scope in tx.principal.scopes:
            declassified.update(grant.classifications)
    return {
        "enabled": policy.information_flow.enabled,
        "integrity": label.integrity,
        "untrusted": label.integrity == "untrusted" or "untrusted_origin" in label.taints,
        "confidentiality": sorted(label.confidentiality),
        "external_sink": external,
        "declassified": sorted(declassified),
        "source_category": tx.metadata.get("source_category", "direct_user_injection"),
    }
