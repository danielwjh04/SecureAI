"""WebSocket endpoint streaming live dashboard events to the browser.

The endpoint subscribes to the event hub *before* accepting the socket, so an
event published immediately after the handshake cannot race ahead of the
subscription. It then forwards each event as JSON until the client disconnects.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from secureSG.dashboard.service import DashboardService

router = APIRouter()


@router.websocket("/dashboard/ws")
async def dashboard_ws(websocket: WebSocket) -> None:
    """Stream live dashboard events to one subscriber until it disconnects."""
    service: DashboardService = websocket.app.state.dashboard
    async with service.subscribe() as queue:
        await websocket.accept()
        try:
            while True:
                event = await queue.get()
                await websocket.send_json(event.model_dump(mode="json"))
        except WebSocketDisconnect:  # pragma: no cover - client-initiated close
            return
