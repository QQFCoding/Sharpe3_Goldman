import asyncio
import ipaddress
import re
import socket
from urllib.parse import unquote, urlsplit

import httpx

from app.core.transaction import Finding, SecurityTransaction, text_leaves
from app.policy.loader import NetworkPolicy


class UnsafeURL(ValueError):
    pass


class NetworkGuard:
    def __init__(self, policy: NetworkPolicy):
        self.policy = policy

    def check_ip(self, address: str):
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise UnsafeURL("Invalid IP address") from exc
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if (
            (self.policy.block_loopback and ip.is_loopback)
            or (self.policy.block_private_ips and ip.is_private)
            or (self.policy.block_link_local and ip.is_link_local)
            or (self.policy.block_reserved and (ip.is_reserved or ip.is_unspecified or ip.is_multicast))
        ):
            raise UnsafeURL("Address is prohibited by network policy")

    async def validate(self, url: str) -> tuple[str, list[str]]:
        try:
            parts = urlsplit(url)
            host = parts.hostname
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError as exc:
            raise UnsafeURL("Malformed URL") from exc
        if parts.scheme not in {"http", "https"} or not host or parts.username or parts.password:
            raise UnsafeURL("Only HTTP(S) URLs without credentials are accepted")
        host = unquote(host).rstrip(".").lower()
        if (
            "%" in host
            or "\\" in host
            or host in {"localhost", "localhost.localdomain"}
            or host.endswith(".localhost")
        ):
            raise UnsafeURL("Invalid or local hostname")
        try:
            ip = ipaddress.ip_address(host)
            self.check_ip(str(ip))
            return host, [str(ip)]
        except ValueError as exc:
            if isinstance(exc, UnsafeURL):
                raise
        # Reject ambiguous numeric forms such as 2130706433, 0177.0.0.1, and 0x7f000001.
        if re.fullmatch(r"[0-9.]+", host) or host.startswith("0x"):
            raise UnsafeURL("Ambiguous numeric host")
        if not self.policy.resolve_dns:
            return host, []
        try:
            entries = await asyncio.wait_for(
                asyncio.to_thread(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM), timeout=2
            )
        except (OSError, TimeoutError) as exc:
            raise UnsafeURL("DNS resolution unavailable") from exc
        addresses = sorted({entry[4][0] for entry in entries})
        if not addresses:
            raise UnsafeURL("DNS returned no addresses")
        for address in addresses:
            self.check_ip(address)
        return host, addresses

    async def inspect(self, tx: SecurityTransaction) -> list[Finding]:
        findings = []
        urls = set()
        for path, text in text_leaves(tx.payload):
            if path and str(path[-1]).lower() in {"url", "uri", "endpoint", "redirect_url"}:
                urls.add(text)
            urls.update(re.findall(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>\"']+", text))
        for url in urls:
            try:
                await self.validate(url.rstrip(".,;)"))
            except UnsafeURL:
                findings.append(Finding(code="UNSAFE_URL", control="ssrf"))
        return findings


class PinnedNetworkTransport(httpx.AsyncBaseTransport):
    """Validate DNS on every hop, then connect to the validated IP with the original TLS SNI."""

    def __init__(self, guard: NetworkGuard):
        self.guard = guard
        self.transport = httpx.AsyncHTTPTransport(retries=0)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host, addresses = await self.guard.validate(str(request.url))
        if not addresses:
            raise UnsafeURL("Actual network execution requires DNS validation")
        headers = httpx.Headers(request.headers)
        headers["Host"] = request.url.netloc.decode()
        pinned = httpx.Request(
            request.method,
            request.url.copy_with(host=addresses[0]),
            headers=headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": host},
        )
        return await self.transport.handle_async_request(pinned)

    async def aclose(self):
        await self.transport.aclose()
