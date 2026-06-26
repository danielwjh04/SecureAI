"""DTOs returned by the dashboard REST endpoints."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CategoryCount(BaseModel):
    """Verdict tallies for one attack category over a window."""

    model_config = ConfigDict(frozen=True)

    category: str
    allow: int = 0
    human_approval_required: int = 0
    block: int = 0
    total: int = 0


class SummaryReport(BaseModel):
    """Monthly Summary panel: verdict counts grouped by attack category."""

    model_config = ConfigDict(frozen=True)

    window_days: int
    generated_at: datetime
    categories: list[CategoryCount] = Field(default_factory=list)


class AlertView(BaseModel):
    """Alert Feed panel entry: one blocked-injection incident."""

    model_config = ConfigDict(frozen=True)

    id: str
    created_at: datetime
    session_id: str
    tool_name: str | None
    rule_id: str
    category: str
    reason: str
    redacted_payload: str


class RegistryEntry(BaseModel):
    """Safe Content Registry panel entry: verified-clean, redacted content."""

    model_config = ConfigDict(frozen=True)

    id: str
    created_at: datetime
    session_id: str
    tool_name: str
    redacted_content: str


class IncidentReport(BaseModel):
    """A flagged alert plus a fresh proof the audit chain is intact."""

    model_config = ConfigDict(frozen=True)

    alert: AlertView
    chain_status: str
    first_invalid_seq: int | None
    generated_at: datetime
