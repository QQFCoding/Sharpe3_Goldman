from app.adapters.base import UpstreamResult
from app.adapters.manifests import definition
from app.adapters.tools import TOOLS


class SafeAdapter:
    """Inert evaluation endpoint; records attempts but never has dangerous capabilities."""
    def __init__(self, tool=False):
        self.tool, self.calls = tool, []
        self.output = None

    async def list_tools(self):
        return [definition(tool) for tool in TOOLS.values()]

    async def execute(self, tx):
        self.calls.append(tx.model_copy(deep=True))
        return UpstreamResult(output=self.output or ({"result": "Public fixture result"} if self.tool else
            {"content": "Public fixture answer"}), output_tokens=0)
