import socket

import httpx
import pytest

from app.controls import pii, secrets
from app.controls.base import canonicalize, transform
from app.controls.ssrf import NetworkGuard, PinnedNetworkTransport, UnsafeURL
from app.core.transaction import Operation, Principal, SecurityTransaction
from app.policy.loader import NetworkPolicy


def tx(text):
    return SecurityTransaction(
        principal=Principal(subject="a", tenant_id="a"),
        operation=Operation.LLM_REQUEST,
        payload={"text": text},
    )


@pytest.mark.parametrize(
    "text",
    [
        "api_key=FAKE_SYNTHETIC_KEY_123456",
        "Bearer FAKE_SYNTHETIC_TOKEN_123456",
        "ghp_FAKE_SYNTHETIC_TOKEN_123456789012345678",
        "AKIAABCDEFGHIJKLMNOP",
        "password=FAKE_PASSWORD_123",
        "postgresql://user:FAKE_PASSWORD@database/test",
        "-----BEGIN PRIVATE KEY-----\nFAKE_KEY\n-----END PRIVATE KEY-----",
        "key=7Tg0yRHsQWx83bc19Aa62zZ4pLm5NnVq",
    ],
)
def test_synthetic_secret_detection(text):
    assert secrets.inspect(tx(text), "BLOCK")


def test_benign_prose_is_not_secret():
    assert not secrets.inspect(tx("Explain how API keys work. A strong password is useful."), "BLOCK")


def test_secret_json_keys_and_quoted_assignments():
    transaction = tx('{"password": "FAKE_SYNTHETIC_PASSWORD"}')
    assert secrets.inspect(transaction, "BLOCK")
    transaction.payload = {"nested": {"api_key": "FAKE_SYNTHETIC_API_KEY"}}
    findings = secrets.inspect(transaction, "REDACT")
    result, _ = transform(transaction.payload, findings)
    assert result["nested"]["api_key"] == "<SECRET_REDACTED>"


@pytest.mark.parametrize(
    "text, label",
    [
        ("john@example.com", "EMAIL"),
        ("+48 555 123 456", "PHONE"),
        ("4111 1111 1111 1111", "CREDIT_CARD"),
        ("44051401458", "PESEL"),
        ("PL61109010140000071219812874", "IBAN"),
        ("192.0.2.10", "IP"),
        ("2001:db8::1", "IP"),
    ],
)
def test_pii_redaction(text, label):
    transaction = tx(text)
    findings = pii.inspect(transaction, "REDACT")
    output, changes = transform(transaction.payload, findings)
    assert f"<{label}_REDACTED>" in output["text"]
    assert text not in output["text"]
    assert changes


def test_checksum_rejections():
    assert not pii.luhn("4111 1111 1111 1112")
    assert not pii.pesel("44051401459")
    assert not pii.iban("PL62109010140000071219812874")
    assert not pii.valid_ip("999.0.0.1")


def test_normalization_obfuscation_and_key_collision():
    assert canonicalize("ｉｇｎｏｒｅ\u200b previous rules") == "ignore previous rules"
    with pytest.raises(ValueError):
        canonicalize({"a": 1, "ａ": 2})


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/test",
        "http://127.0.0.2",
        "http://[::1]",
        "http://10.1.2.3",
        "http://169.254.169.254/latest",
        "http://[::ffff:127.0.0.1]",
        "file:///etc/passwd",
        "gopher://example.com",
        "http://2130706433",
        "http://0177.0.0.1",
        "http://0x7f000001",
        "http://user:pass@public.example",
        "http://[fe80::1%25eth0]",
        "http://127%2e0%2e0%2e1",
    ],
)
async def test_ssrf_prohibited_targets(url):
    with pytest.raises(UnsafeURL):
        await NetworkGuard(NetworkPolicy(resolve_dns=False)).validate(url)


async def test_dns_mixed_public_private_is_denied(monkeypatch):
    def addresses(*_, **__):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80)) for ip in ["93.184.216.34", "10.0.0.5"]]

    monkeypatch.setattr(socket, "getaddrinfo", addresses)
    with pytest.raises(UnsafeURL):
        await NetworkGuard(NetworkPolicy()).validate("http://public.example")


async def test_redirect_checked_and_connection_pinned(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    sent = []

    async def handler(request):
        sent.append(request)
        assert request.url.host == "93.184.216.34"
        assert request.headers["Host"] == "public.example"
        assert request.extensions["sni_hostname"] == "public.example"
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/private"})

    transport = PinnedNetworkTransport(NetworkGuard(NetworkPolicy()))
    transport.transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
        with pytest.raises(UnsafeURL):
            await client.get("https://public.example")
    assert len(sent) == 1
