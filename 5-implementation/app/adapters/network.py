import httpx

from app.adapters.base import UpstreamResult
from app.adapters.openai_compatible import UpstreamFailure
from app.controls.ssrf import NetworkGuard, PinnedNetworkTransport
from app.policy.loader import NetworkPolicy


class NetworkAdapter:
    """Read-only API adapter with pinned DNS and redirect validation at every connection."""

    async def execute(self, transaction):
        guard = NetworkGuard(NetworkPolicy.model_validate(transaction.metadata["network_policy"]))
        async with httpx.AsyncClient(
            transport=PinnedNetworkTransport(guard),
            follow_redirects=True,
            max_redirects=5,
            trust_env=False,
            timeout=10,
        ) as client:
            async with client.stream("GET", transaction.payload["url"]) as response:
                response.raise_for_status()
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > transaction.metadata["response_limit"]:
                        raise UpstreamFailure("Network response size limit exceeded")
                return UpstreamResult(output={"result": content.decode("utf-8", errors="replace")})
