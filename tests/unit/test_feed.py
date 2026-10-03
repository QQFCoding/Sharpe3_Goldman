import pytest

from app.core.transaction import Operation, Principal, Resource, SecurityTransaction
from app.threatintel.loader import ThreatFeed, ThreatRule


@pytest.mark.parametrize(
    "indicator, metadata, resource",
    [
        ({"tools": ["github.search"]}, {}, Resource(name="github.search")),
        ({"hashes": ["synthetic-hash"]}, {"artifact_hash": "synthetic-hash"}, Resource(name="demo")),
        ({"packages": {"mock-sdk": ["0.0.1"]}}, {"packages": {"mock-sdk": "0.0.1"}}, Resource(name="demo")),
        (
            {"mcp_servers": ["blocked-demo-server"]},
            {},
            Resource(name="demo", mcp_server="blocked-demo-server"),
        ),
    ],
)
def test_metadata_indicators(indicator, metadata, resource):
    feed = ThreatFeed(revision=1, rules=[ThreatRule(id="TEST-1", category="test", **indicator)])
    tx = SecurityTransaction(
        principal=Principal(subject="a", tenant_id="a"),
        operation=Operation.MCP_TOOL_CALL,
        resource=resource,
        payload={},
        metadata=metadata,
    )
    assert feed.match(tx)[0].rule_id == "TEST-1"
    assert feed.revision == "1"
