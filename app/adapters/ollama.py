from app.adapters.base import UpstreamResult
from app.adapters.openai_compatible import bounded_json


class OllamaAdapter:
    def __init__(self, client, url, timeout=15):
        self.client, self.url, self.timeout = client, url, timeout

    async def execute(self, transaction):
        result = await bounded_json(
            self.client,
            f"{self.url}/api/chat",
            {
                "model": transaction.resource.model,
                "messages": transaction.payload["messages"],
                "stream": False,
                "options": {"num_predict": transaction.budget.max_output_tokens},
            },
            transaction.metadata["response_limit"] + 4096,
            self.timeout,
        )
        return UpstreamResult(
            output={"content": result["message"]["content"]},
            input_tokens=result.get("prompt_eval_count", 0),
            output_tokens=result.get("eval_count", 0),
        )
