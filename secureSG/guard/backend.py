"""The injectable MCP backend seam: where approved calls are forwarded.

The proxy never talks to the MCP server directly; it forwards an *approved*
call through a :class:`McpBackend`. A real deployment uses :class:`HttpMcpBackend`
(an async HTTP JSON-RPC client); tests and the self-contained demo use
:class:`MockMcpBackend` with canned per-tool responses. Both return the raw
JSON-RPC response dict — extraction and screening happen downstream in the
interceptor and enforcer, never here.

Failures are surfaced as :class:`~secureSG.exceptions.BackendError` (an unknown
mock tool, a transport failure, a non-2xx status, or a non-object body) so the
proxy can fail closed instead of delivering an untrustworthy result.
"""

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

import httpx

from secureSG.exceptions import BackendError
from secureSG.schemas.tool_call import JsonValue, ToolCallSchema

_JSONRPC_VERSION = "2.0"


class McpBackend(ABC):
    """An injectable transport that forwards approved calls to the MCP server."""

    @abstractmethod
    async def forward(self, call: ToolCallSchema) -> dict[str, Any]:
        """Forward an approved call and return the raw JSON-RPC response dict."""

    @abstractmethod
    async def aclose(self) -> None:
        """Release any held resources (idempotent)."""


class MockMcpBackend(McpBackend):
    """In-process backend returning canned per-tool results for tests and demo."""

    def __init__(self, responses: Mapping[str, JsonValue]) -> None:
        self._responses = dict(responses)

    async def forward(self, call: ToolCallSchema) -> dict[str, Any]:
        """Return the canned JSON-RPC response for a tool, else fail closed. O(1)."""
        if call.tool_name not in self._responses:
            raise BackendError(
                f"mock backend has no canned response for tool '{call.tool_name}'"
            )
        return {
            "jsonrpc": _JSONRPC_VERSION,
            "id": call.id,
            "result": self._responses[call.tool_name],
        }

    async def aclose(self) -> None:
        return None


class HttpMcpBackend(McpBackend):
    """Async HTTP JSON-RPC backend forwarding to a real MCP server."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = url
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport)

    async def forward(self, call: ToolCallSchema) -> dict[str, Any]:
        """POST the call and return the parsed JSON-RPC response.

        Raises:
            BackendError: on any transport failure, non-2xx status, or a
                response body that is not a JSON object.

        Time complexity: O(payload size) plus network. Space complexity: O(same).
        """
        try:
            response = await self._client.post(self._url, json=call.model_dump())
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError as exc:
            raise BackendError(f"MCP backend request failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise BackendError("MCP backend returned a non-object JSON-RPC response")
        return payload

    async def aclose(self) -> None:
        await self._client.aclose()
