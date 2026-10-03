import json

from app.adapters.manifests import manifest
from app.adapters.tools import TOOLS
from app.settings import ROOT


def test_pinned_manifest_matches_reviewed_registry():
    pins = json.loads((ROOT / "config/tool-manifests.json").read_text())
    assert pins == {name: manifest(tool) for name, tool in TOOLS.items()}
    jwks = json.loads((ROOT / "config/demo-jwks.json").read_text())
    assert all(key["alg"] == "RS256" and "d" not in key for key in jwks["keys"])


def test_dependency_feed_is_distinct_from_runtime_signatures():
    feed = json.loads((ROOT / "config/advisories.sample.json").read_text())
    assert feed["advisories"] and feed["advisories"][0]["affected_versions"]
    assert "regex" not in feed["advisories"][0]
