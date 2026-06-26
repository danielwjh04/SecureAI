"""In-process fan-out of dashboard events to live WebSocket subscribers.

The proxy publishes events on its hot path, so :meth:`EventHub.publish` must
never block: each subscriber has a bounded queue, and a slow consumer simply
loses its oldest events rather than stalling the guard. Everything runs on the
single asyncio event loop, so no locking is needed beyond cooperative
scheduling — there is no ``await`` between the ``full()`` check and the drop, so
the queue cannot change underneath us.
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from secureSG.schemas.events import DashboardEvent


class EventHub:
    """Bounded-queue pub/sub broadcaster for the live dashboard feed."""

    def __init__(self, *, queue_size: int) -> None:
        self._queue_size = queue_size
        self._subscribers: set[asyncio.Queue[DashboardEvent]] = set()

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[DashboardEvent]]:
        """Register a bounded queue for one subscriber; unregister on exit."""
        queue: asyncio.Queue[DashboardEvent] = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers.add(queue)
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)

    def publish(self, event: DashboardEvent) -> None:
        """Fan an event out to every subscriber without blocking.

        A full subscriber queue drops its oldest event to make room, so a slow
        WebSocket client never stalls the proxy.

        Time complexity: O(subscribers). Space complexity: O(1).
        """
        for queue in self._subscribers:
            if queue.full():
                queue.get_nowait()  # drop oldest; safe right after full() on one loop
            queue.put_nowait(event)

    @property
    def subscriber_count(self) -> int:
        """Number of currently-registered subscribers. O(1)."""
        return len(self._subscribers)
