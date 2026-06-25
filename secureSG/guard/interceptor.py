"""JSON-RPC interception: parse inbound calls, extract results, derive txn ids.

These are pure functions over the raw JSON-RPC envelope. Field names here
(``result``, ``error``) are JSON-RPC / MCP protocol constants, not configurable
values. Parsing is fail-closed: an unparseable inbound call or a malformed
result yields ``None`` so the caller can apply a fail-closed verdict rather than
trusting unvalidated input (CLAUDE.md section 6).
"""

import json
from typing import Any, Final
from uuid import NAMESPACE_DNS, UUID, uuid5

from pydantic import ValidationError

from secureSG.schemas.tool_call import JsonValue, ToolCallSchema, ToolResult

_TXN_NAMESPACE: Final[UUID] = uuid5(NAMESPACE_DNS, "securesg.guard.transaction")
"""Fixed namespace for deterministic uuid5 transaction ids (idempotent replay)."""


def parse_call(raw: dict[str, Any]) -> ToolCallSchema | None:
    """Validate a raw JSON-RPC request into a ToolCallSchema; None if invalid.

    Time complexity: O(payload size). Space complexity: O(payload size).
    """
    try:
        return ToolCallSchema.model_validate(raw)
    except ValidationError:
        return None


def extract_result(raw_response: dict[str, Any], tool_name: str) -> ToolResult | None:
    """Extract a ToolResult from a raw JSON-RPC response; None on error/malformed.

    A response carrying a JSON-RPC ``error`` (the tool's own failure), or one
    with neither ``result`` nor ``error``, yields None — there is no trustworthy
    result payload to screen or taint.

    Time complexity: O(payload size). Space complexity: O(payload size).
    """
    if "error" in raw_response or "result" not in raw_response:
        return None
    try:
        return ToolResult.model_validate(
            {"tool_name": tool_name, "result": raw_response["result"]}
        )
    except ValidationError:
        return None


def derive_transaction_id(
    session_id: str, rpc_id: int | str, arguments: dict[str, JsonValue]
) -> UUID:
    """Derive a stable transaction id from session, request id, and arguments.

    A genuine replay (same session, request id, and arguments) maps to the same
    id, so the audit layer dedupes it; a reused request id with different
    arguments gets a distinct id.

    Time complexity: O(arguments size). Space complexity: O(arguments size).
    """
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    return uuid5(_TXN_NAMESPACE, f"{session_id}|{rpc_id}|{canonical}")


def derive_result_transaction_id(call_transaction_id: UUID) -> UUID:
    """Derive the result-screening transaction id from the call's id. O(1)."""
    return uuid5(_TXN_NAMESPACE, f"{call_transaction_id}:result")
