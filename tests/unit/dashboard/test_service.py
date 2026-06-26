"""Tests for the dashboard service: event routing, redaction, reports."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.dashboard.hub import EventHub
from secureSG.dashboard.service import DashboardService
from secureSG.dashboard.store import DashboardStore
from secureSG.schemas.audit import AuditRecord
from secureSG.schemas.events import DashboardEvent
from secureSG.schemas.verdict import Verdict

GENESIS = derive_genesis_hash("dashboard-service-test")


def _now() -> datetime:
    return datetime(2026, 6, 26, tzinfo=UTC)


def _build(tmp_path: Path) -> tuple[DashboardService, EventHub, DashboardStore]:
    hub = EventHub(queue_size=10)
    store = DashboardStore(max_alerts=5, max_registry=5)
    service = DashboardService(
        hub=hub, store=store, db_path=tmp_path / "audit.db", genesis_hash=GENESIS
    )
    return service, hub, store


def _content(verdict: str, *, content: str, rule_id: str) -> DashboardEvent:
    return DashboardEvent.content_event(
        created_at=_now(),
        session_id="s",
        tool_name="scrape_page",
        content=content,
        verdict=verdict,
        rule_id=rule_id,
        reason="reason",
        transaction_id="t",
    )


async def test_handle_publishes_enriched_verdict(tmp_path: Path) -> None:
    service, hub, _store = _build(tmp_path)
    async with hub.subscribe() as queue:
        service.handle(
            DashboardEvent.verdict_event(
                created_at=_now(),
                session_id="s",
                tool_name="send_email",
                verdict="BLOCK",
                rule_id="taint.high_to_external",
            )
        )
        event = await queue.get()
    assert event.category == "Data Exfiltration"


async def test_content_block_records_redacted_alert(tmp_path: Path) -> None:
    service, _hub, store = _build(tmp_path)
    service.handle(
        _content(
            "BLOCK",
            content="leak sk-abcdefghijklmnop1234 now",
            rule_id="injection.signature",
        )
    )
    alerts = store.alerts()
    assert len(alerts) == 1
    assert alerts[0].category == "Prompt Injection"
    assert "[REDACTED]" in alerts[0].redacted_payload  # PII masked downstream


async def test_content_clean_records_registry(tmp_path: Path) -> None:
    service, _hub, store = _build(tmp_path)
    service.handle(
        _content("ALLOW", content="ordinary text", rule_id="injection.clean")
    )
    registry = store.registry()
    assert len(registry) == 1
    assert registry[0].redacted_content == "ordinary text"


async def test_model_state_event_is_published_not_stored(tmp_path: Path) -> None:
    service, hub, store = _build(tmp_path)
    async with hub.subscribe() as queue:
        service.handle(
            DashboardEvent.model_state_event(
                created_at=_now(), session_id="s", model_state="screening"
            )
        )
        event = await queue.get()
    assert event.model_state == "screening"
    assert store.alerts() == []
    assert store.registry() == []


async def test_report_bundles_alert_with_chain_proof(tmp_path: Path) -> None:
    logger = AuditLogger(db_path=tmp_path / "audit.db", genesis_hash=GENESIS)
    await logger.initialize()
    await logger.append(
        AuditRecord(
            transaction_id=uuid4(),
            created_at=_now(),
            verdict=Verdict.BLOCK,
            tool_name="scrape_page",
            details={"reason": "r", "rule_id": "injection.signature"},
        )
    )
    await logger.close()
    service, _hub, store = _build(tmp_path)
    service.handle(
        _content("BLOCK", content="bad", rule_id="injection.signature")
    )
    alert_id = store.alerts()[0].id
    report = await service.report(alert_id)
    assert report is not None
    assert report.chain_status == "CHAIN_OK"
    assert report.alert.id == alert_id


async def test_report_unknown_alert_returns_none(tmp_path: Path) -> None:
    service, _hub, _store = _build(tmp_path)
    assert await service.report("missing") is None
