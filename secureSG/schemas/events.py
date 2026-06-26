"""DTOs for the live dashboard event stream.

These live in ``schemas`` (the base layer) so the proxy can emit them without
depending on the ``dashboard`` package. One flat, frozen :class:`DashboardEvent`
carries every event kind; typed constructors keep the emit sites readable and
ensure each kind only sets the fields that belong to it. The dashboard service
enriches an event with its ``category`` via :meth:`model_copy` before fan-out.
"""

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict


class DashboardEventKind(StrEnum):
    """The kind of live dashboard event."""

    VERDICT = "VERDICT"
    CONTENT = "CONTENT"
    MODEL_STATE = "MODEL_STATE"


class DashboardEvent(BaseModel):
    """One event on the live dashboard feed (verdict, content, or model state)."""

    model_config = ConfigDict(frozen=True)

    kind: DashboardEventKind
    created_at: datetime
    session_id: str
    tool_name: str | None = None
    verdict: str | None = None
    rule_id: str | None = None
    category: str | None = None
    content: str | None = None
    reason: str | None = None
    model_state: str | None = None
    transaction_id: str | None = None

    @classmethod
    def verdict_event(
        cls,
        *,
        created_at: datetime,
        session_id: str,
        tool_name: str | None,
        verdict: str,
        rule_id: str,
    ) -> Self:
        """Build a per-call verdict event."""
        return cls(
            kind=DashboardEventKind.VERDICT,
            created_at=created_at,
            session_id=session_id,
            tool_name=tool_name,
            verdict=verdict,
            rule_id=rule_id,
        )

    @classmethod
    def content_event(
        cls,
        *,
        created_at: datetime,
        session_id: str,
        tool_name: str,
        content: str,
        verdict: str,
        rule_id: str,
        reason: str,
        transaction_id: str,
    ) -> Self:
        """Build a screened-result content event (content is already redacted)."""
        return cls(
            kind=DashboardEventKind.CONTENT,
            created_at=created_at,
            session_id=session_id,
            tool_name=tool_name,
            content=content,
            verdict=verdict,
            rule_id=rule_id,
            reason=reason,
            transaction_id=transaction_id,
        )

    @classmethod
    def model_state_event(
        cls, *, created_at: datetime, session_id: str, model_state: str
    ) -> Self:
        """Build a model-state-transition event for the status bar."""
        return cls(
            kind=DashboardEventKind.MODEL_STATE,
            created_at=created_at,
            session_id=session_id,
            model_state=model_state,
        )
