"""Tests for the dashboard WebSocket live feed (sync TestClient)."""

from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secureSG.dashboard import ws
from secureSG.dashboard.hub import EventHub
from secureSG.dashboard.service import DashboardService
from secureSG.dashboard.store import DashboardStore
from secureSG.schemas.events import DashboardEvent


def _app(tmp_path: Path) -> FastAPI:
    hub = EventHub(queue_size=10)
    store = DashboardStore(max_alerts=5, max_registry=5)
    service = DashboardService(
        hub=hub, store=store, db_path=tmp_path / "audit.db", genesis_hash="g"
    )
    app = FastAPI()
    app.state.dashboard = service
    app.include_router(ws.router)

    @app.post("/_emit/{state}")
    async def _emit(state: str) -> dict[str, bool]:
        service.handle(
            DashboardEvent.model_state_event(
                created_at=datetime(2026, 6, 26, tzinfo=UTC),
                session_id="s",
                model_state=state,
            )
        )
        return {"ok": True}

    return app


def test_ws_streams_published_events(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client, client.websocket_connect(
        "/dashboard/ws"
    ) as socket:
        client.post("/_emit/screening")
        first = socket.receive_json()
        client.post("/_emit/idle")
        second = socket.receive_json()
    assert first["kind"] == "MODEL_STATE"
    assert first["model_state"] == "screening"
    assert second["model_state"] == "idle"
