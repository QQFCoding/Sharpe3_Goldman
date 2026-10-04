"""The hosted frontend must not leak credentials through redirects or shared state."""
import json
from pathlib import Path

import httpx
import pytest

from cloud.gateway import Gateway, GatewayError, configured_url


@pytest.mark.parametrize("url", ["http://public.example", "https://user:secret@example.com",
    "https://example.com/route", "https://example.com?key=secret", "file:///tmp", "https://example.com#x"])
def test_configuration_rejects_credentialed_or_unsafe_origins(url):
    with pytest.raises(ValueError):
        configured_url(url)


def test_https_and_loopback_are_supported():
    assert configured_url("https://gateway.example/") == "https://gateway.example"
    assert configured_url("http://127.0.0.1:8012") == "http://127.0.0.1:8012"


def client_factory(monkeypatch, handler):
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real(transport=httpx.MockTransport(handler), **kwargs))


def test_redirect_never_forwards_operator_token(monkeypatch):
    destinations = []
    def handler(request):
        destinations.append(str(request.url))
        assert request.headers["Authorization"] == "Bearer operator-test"
        return httpx.Response(302, headers={"Location": "https://other.example/steal"})
    client_factory(monkeypatch, handler)
    with pytest.raises(GatewayError, match="302"):
        Gateway("https://gateway.example", "operator-test").request("/admin/governance")
    assert destinations == ["https://gateway.example/admin/governance"]


def test_gateway_failure_body_is_not_echoed(monkeypatch):
    client_factory(monkeypatch, lambda request: httpx.Response(503, text="private-token-and-debug-path"))
    with pytest.raises(GatewayError) as error:
        Gateway("https://gateway.example", "operator-test").request("/admin/governance")
    assert "private-token" not in str(error.value)
    assert error.value.status == 503


def test_stream_preserves_actual_stages_and_terminal_errors(monkeypatch):
    events = [{"sequence": 0, "stage": "received", "data": {}}, {"error": "INSPECTION_UNAVAILABLE"}]
    body = "".join("event: stage\ndata: " + json.dumps(e) + "\n\n" for e in events)
    client_factory(monkeypatch, lambda request: httpx.Response(200, text=body))
    stream = Gateway("https://gateway.example", "operator-test").events({"text": "Public request"})
    assert next(stream) == events[0]
    with pytest.raises(GatewayError, match="INSPECTION_UNAVAILABLE"):
        next(stream)


def test_anonymous_page_requires_connection(monkeypatch):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest
    monkeypatch.delenv("AICL_CLOUD_STANDALONE", raising=False)
    app = AppTest.from_file(Path(__file__).resolve().parents[2] / "cloud/streamlit_app.py").run(timeout=15)
    assert not app.exception
    assert any("Connect with the gateway operator token" in item.value for item in app.info)
    with pytest.raises(KeyError):
        app.session_state["operator_token"]
