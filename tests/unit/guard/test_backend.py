"""Tests for the MCP backend interface (mock + http via MockTransport)."""

import json
from typing import Any

import httpx
import pytest

from secureSG.exceptions import BackendError
from secureSG.guard.backend import HttpMcpBackend, MockMcpBackend
from secureSG.schemas.tool_call import ToolCallSchema


def _call(name: str, arguments: dict[str, Any] | None = None) -> ToolCallSchema:
    return ToolCallSchema.model_validate(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )


async def test_mock_backend_returns_canned_response() -> None:
    backend = MockMcpBackend({"read_secret": "s3cr3t"})
    response = await backend.forward(_call("read_secret"))
    assert response["result"] == "s3cr3t"
    assert response["id"] == 7
    await backend.aclose()


async def test_mock_backend_unknown_tool_fails_closed() -> None:
    backend = MockMcpBackend({})
    with pytest.raises(BackendError):
        await backend.forward(_call("unknown_tool"))
    await backend.aclose()


async def test_http_backend_posts_call_and_parses_response() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 7, "result": "ok"})

    backend = HttpMcpBackend(
        "http://mcp.local/rpc",
        timeout=5.0,
        transport=httpx.MockTransport(handler),
    )
    response = await backend.forward(_call("send_email", {"to": "a@b.c"}))
    assert response["result"] == "ok"
    assert captured["url"] == "http://mcp.local/rpc"
    assert captured["body"]["params"]["name"] == "send_email"
    await backend.aclose()


async def test_http_backend_raises_backend_error_on_transport_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    backend = HttpMcpBackend(
        "http://mcp.local/rpc",
        timeout=5.0,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(BackendError):
        await backend.forward(_call("send_email"))
    await backend.aclose()


async def test_http_backend_raises_backend_error_on_error_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "server"})

    backend = HttpMcpBackend(
        "http://mcp.local/rpc",
        timeout=5.0,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(BackendError):
        await backend.forward(_call("send_email"))
    await backend.aclose()


async def test_http_backend_raises_on_non_object_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"])

    backend = HttpMcpBackend(
        "http://mcp.local/rpc",
        timeout=5.0,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(BackendError):
        await backend.forward(_call("send_email"))
    await backend.aclose()
