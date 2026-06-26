"""Tests for the dashboard REST endpoints."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
from fastapi import FastAPI

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.config.settings import Settings
from secureSG.dashboard import api
from secureSG.dashboard.hub import EventHub
from secureSG.dashboard.reader import AuditReader
from secureSG.dashboard.service import DashboardService
from secureSG.dashboard.store import DashboardStore
from secureSG.schemas.audit import AuditRecord
from secureSG.schemas.events import DashboardEvent
from secureSG.schemas.verdict import Verdict

GENESIS = derive_genesis_hash("dashboard-api-test")


def _now() -> datetime:
    return datetime(2026, 6, 26, tzinfo=UTC)


@asynccontextmanager
async def _client(
    tmp_path: Path, *, with_alert: bool = False
) -> AsyncIterator[tuple[httpx.AsyncClient, DashboardService]]:
    db_path = tmp_path / "audit.db"
    logger = AuditLogger(db_path=db_path, genesis_hash=GENESIS)
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
    hub = EventHub(queue_size=10)
    store = DashboardStore(max_alerts=5, max_registry=5)
    service = DashboardService(
        hub=hub, store=store, db_path=db_path, genesis_hash=GENESIS
    )
    if with_alert:
        service.handle(
            DashboardEvent.content_event(
                created_at=_now(),
                session_id="s",
                tool_name="scrape_page",
                content="bad payload",
                verdict="BLOCK",
                rule_id="injection.signature",
                reason="matched signature",
                transaction_id="t",
            )
        )
        service.handle(
            DashboardEvent.content_event(
                created_at=_now(),
                session_id="s",
                tool_name="read_file",
                content="clean file",
                verdict="ALLOW",
                rule_id="injection.clean",
                reason="clean",
                transaction_id="t2",
            )
        )
    app = FastAPI()
    app.state.dashboard = service
    app.state.audit_reader = AuditReader(db_path)
    app.state.settings = Settings(_env_file=None)
    app.include_router(api.router)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, service


async def test_summary_endpoint(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, _service):
        response = await client.get("/dashboard/summary")
    assert response.status_code == 200
    categories = {c["category"]: c for c in response.json()["categories"]}
    assert categories["Prompt Injection"]["block"] == 1


async def test_summary_rejects_zero_window(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, _service):
        response = await client.get("/dashboard/summary", params={"window_days": 0})
    assert response.status_code == 422


async def test_alerts_endpoint(tmp_path: Path) -> None:
    async with _client(tmp_path, with_alert=True) as (client, _service):
        response = await client.get("/dashboard/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) == 1
    assert alerts[0]["category"] == "Prompt Injection"


async def test_registry_endpoint(tmp_path: Path) -> None:
    async with _client(tmp_path, with_alert=True) as (client, _service):
        response = await client.get("/dashboard/registry")
    assert response.status_code == 200
    assert response.json()[0]["redacted_content"] == "clean file"


async def test_report_endpoint_returns_chain_proof(tmp_path: Path) -> None:
    async with _client(tmp_path, with_alert=True) as (client, service):
        alert_id = service.alerts()[0].id
        response = await client.post(f"/dashboard/alerts/{alert_id}/report")
    assert response.status_code == 200
    assert response.json()["chain_status"] == "CHAIN_OK"


async def test_report_unknown_alert_is_404(tmp_path: Path) -> None:
    async with _client(tmp_path) as (client, _service):
        response = await client.post("/dashboard/alerts/missing/report")
    assert response.status_code == 404
