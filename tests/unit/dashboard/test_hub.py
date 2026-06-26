"""Tests for the in-process event broadcaster."""

from datetime import UTC, datetime

from secureSG.dashboard.hub import EventHub
from secureSG.schemas.events import DashboardEvent


def _event(state: str = "idle") -> DashboardEvent:
    return DashboardEvent.model_state_event(
        created_at=datetime(2026, 6, 26, tzinfo=UTC),
        session_id="s",
        model_state=state,
    )


async def test_subscriber_receives_published_event() -> None:
    hub = EventHub(queue_size=10)
    async with hub.subscribe() as queue:
        hub.publish(_event("screening"))
        event = await queue.get()
    assert event.model_state == "screening"


async def test_publish_without_subscribers_is_noop() -> None:
    hub = EventHub(queue_size=10)
    hub.publish(_event())
    assert hub.subscriber_count == 0


async def test_subscriber_is_unregistered_on_exit() -> None:
    hub = EventHub(queue_size=10)
    async with hub.subscribe():
        assert hub.subscriber_count == 1
    assert hub.subscriber_count == 0


async def test_full_queue_drops_oldest_event() -> None:
    hub = EventHub(queue_size=2)
    async with hub.subscribe() as queue:
        hub.publish(_event("a"))
        hub.publish(_event("b"))
        hub.publish(_event("c"))  # full at 2 -> drops "a", enqueues "c"
        first = await queue.get()
        second = await queue.get()
        assert queue.empty()
    assert first.model_state == "b"
    assert second.model_state == "c"


async def test_every_subscriber_receives_event() -> None:
    hub = EventHub(queue_size=10)
    async with hub.subscribe() as q1, hub.subscribe() as q2:
        hub.publish(_event("x"))
        assert (await q1.get()).model_state == "x"
        assert (await q2.get()).model_state == "x"
