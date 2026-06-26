"""Tests for the live dashboard event DTO and its constructors."""

from datetime import UTC, datetime

from secureSG.schemas.events import DashboardEvent, DashboardEventKind


def _now() -> datetime:
    return datetime(2026, 6, 26, tzinfo=UTC)


def test_verdict_event() -> None:
    event = DashboardEvent.verdict_event(
        created_at=_now(),
        session_id="s",
        tool_name="read_file",
        verdict="ALLOW",
        rule_id="policy.read_file",
    )
    assert event.kind is DashboardEventKind.VERDICT
    assert event.verdict == "ALLOW"
    assert event.rule_id == "policy.read_file"
    assert event.content is None


def test_content_event() -> None:
    event = DashboardEvent.content_event(
        created_at=_now(),
        session_id="s",
        tool_name="scrape_page",
        content="masked content",
        verdict="BLOCK",
        rule_id="injection.signature",
        reason="matched signature",
        transaction_id="txn-1",
    )
    assert event.kind is DashboardEventKind.CONTENT
    assert event.content == "masked content"
    assert event.transaction_id == "txn-1"


def test_model_state_event() -> None:
    event = DashboardEvent.model_state_event(
        created_at=_now(), session_id="s", model_state="screening"
    )
    assert event.kind is DashboardEventKind.MODEL_STATE
    assert event.model_state == "screening"


def test_category_enrichment_via_model_copy() -> None:
    event = DashboardEvent.verdict_event(
        created_at=_now(),
        session_id="s",
        tool_name=None,
        verdict="BLOCK",
        rule_id="denylist",
    )
    enriched = event.model_copy(update={"category": "Forbidden Tool"})
    assert enriched.category == "Forbidden Tool"
    assert event.category is None
