"""Tests for the dashboard REST response DTOs."""

from datetime import UTC, datetime

from secureSG.schemas.dashboard import (
    AlertView,
    CategoryCount,
    IncidentReport,
    RegistryEntry,
    SummaryReport,
)


def _now() -> datetime:
    return datetime(2026, 6, 26, tzinfo=UTC)


def test_summary_report_holds_category_counts() -> None:
    report = SummaryReport(
        window_days=30,
        generated_at=_now(),
        categories=[CategoryCount(category="Prompt Injection", block=2, total=2)],
    )
    assert report.window_days == 30
    assert report.categories[0].block == 2
    assert report.categories[0].allow == 0


def test_alert_view_fields() -> None:
    alert = AlertView(
        id="a1",
        created_at=_now(),
        session_id="s",
        tool_name="scrape_page",
        rule_id="injection.signature",
        category="Prompt Injection",
        reason="matched signature",
        redacted_payload="... [REDACTED] ...",
    )
    assert alert.id == "a1"
    assert alert.category == "Prompt Injection"


def test_registry_entry_fields() -> None:
    entry = RegistryEntry(
        id="r1",
        created_at=_now(),
        session_id="s",
        tool_name="read_file",
        redacted_content="clean content",
    )
    assert entry.tool_name == "read_file"


def test_incident_report_wraps_alert_and_chain_status() -> None:
    alert = AlertView(
        id="a1",
        created_at=_now(),
        session_id="s",
        tool_name=None,
        rule_id="injection.signature",
        category="Prompt Injection",
        reason="r",
        redacted_payload="p",
    )
    report = IncidentReport(
        alert=alert,
        chain_status="CHAIN_OK",
        first_invalid_seq=None,
        generated_at=_now(),
    )
    assert report.chain_status == "CHAIN_OK"
    assert report.alert.id == "a1"
