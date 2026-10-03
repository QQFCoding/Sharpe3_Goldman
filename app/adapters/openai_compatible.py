
import httpx

from app.adapters.base import UpstreamResult
from app.adapters.spotlighting import spotlight


class UpstreamFailure(RuntimeError):
    pass


async def bounded_get_json(client, url, limit, timeout):
    from app.adapters.mcp_protocol import strict_json
    async with client.stream("GET", url, timeout=timeout) as response:
        response.raise_for_status()
        data = bytearray()
        async for chunk in response.aiter_bytes():
            data.extend(chunk)
            if len(data) > limit:
                raise UpstreamFailure("Metadata size limit exceeded")
        return strict_json(data)


async def bounded_json(client: httpx.AsyncClient, url: str, body: dict, limit: int, timeout: float, headers=None):
    async with client.stream("POST", url, json=body, timeout=timeout, headers=headers) as response:
        response.raise_for_status()
        data = bytearray()
        async for chunk in response.aiter_bytes():
            data.extend(chunk)
            if len(data) > limit:
                raise UpstreamFailure("Upstream response limit exceeded")
        from app.adapters.mcp_protocol import strict_json
        return strict_json(data)


class OpenAICompatibleAdapter:
    def __init__(self, client: httpx.AsyncClient, url: str, timeout=15):
        self.client, self.url, self.timeout = client, url, timeout

    async def execute(self, transaction):
        payload = {**transaction.payload, "model": transaction.resource.model, "stream": False}
        payload["messages"] = spotlight(transaction.payload["messages"])
        result = await bounded_json(
            self.client,
            f"{self.url}/v1/chat/completions",
            payload,
            transaction.metadata["response_limit"] + 4096,
            self.timeout,
        )
        usage = result.get("usage", {})
        return UpstreamResult(
            output={"content": result["choices"][0]["message"]["content"]},
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )
