"""Routes proxy events to the live feed, the projections, and incident reports.

The proxy emits neutral :class:`DashboardEvent`s to :meth:`DashboardService.handle`.
The service enriches each with its attack category, applies pattern-based PII
redaction on top of the proxy's taint masking, fans it out to live subscribers,
and records content events into the alert ring (blocked) or registry ring
(clean). Incident reports bundle a flagged alert with a fresh chain-integrity
proof, so a report is self-verifying evidence rather than a bare claim.
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from secureSG.audit.verifier import ChainVerifier
from secureSG.dashboard.categories import category_for
from secureSG.dashboard.hub import EventHub
from secureSG.dashboard.redaction import redact_pii
from secureSG.dashboard.store import DashboardStore
from secureSG.schemas.dashboard import AlertView, IncidentReport, RegistryEntry
from secureSG.schemas.events import DashboardEvent, DashboardEventKind
from secureSG.schemas.verdict import Verdict


class DashboardService:
    """Fan-out + projection + report layer behind the dashboard endpoints."""

    def __init__(
        self,
        *,
        hub: EventHub,
        store: DashboardStore,
        db_path: Path,
        genesis_hash: str,
    ) -> None:
        self._hub = hub
        self._store = store
        self._db_path = db_path
        self._genesis_hash = genesis_hash

    def handle(self, event: DashboardEvent) -> None:
        """Enrich, broadcast, and (for content) project one proxy event. O(subs)."""
        enriched = self._enrich(event)
        self._hub.publish(enriched)
        if enriched.kind is DashboardEventKind.CONTENT:
            self._record_content(enriched)

    @staticmethod
    def _enrich(event: DashboardEvent) -> DashboardEvent:
        updates: dict[str, str] = {}
        if event.rule_id is not None:
            updates["category"] = category_for(event.rule_id)
        if event.content is not None:
            updates["content"] = redact_pii(event.content)
        return event.model_copy(update=updates) if updates else event

    def _record_content(self, event: DashboardEvent) -> None:
        category = category_for(event.rule_id or "")
        if event.verdict == Verdict.BLOCK.value:
            self._store.record_alert(
                created_at=event.created_at,
                session_id=event.session_id,
                tool_name=event.tool_name,
                rule_id=event.rule_id or "",
                category=category,
                reason=event.reason or "",
                redacted_payload=event.content or "",
            )
        else:
            self._store.record_registry(
                created_at=event.created_at,
                session_id=event.session_id,
                tool_name=event.tool_name or "",
                redacted_content=event.content or "",
            )

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[DashboardEvent]]:
        """Yield a live-feed queue for one WebSocket subscriber."""
        async with self._hub.subscribe() as queue:
            yield queue

    def alerts(self) -> list[AlertView]:
        """Recent alerts, newest first."""
        return self._store.alerts()

    def registry(self) -> list[RegistryEntry]:
        """Recent verified-clean entries, newest first."""
        return self._store.registry()

    async def report(self, alert_id: str) -> IncidentReport | None:
        """Bundle a flagged alert with a fresh audit-chain integrity proof.

        Returns None if the alert id is unknown. Time complexity: O(alerts) +
        O(chain length) for the verification pass.
        """
        alert = self._store.find_alert(alert_id)
        if alert is None:
            return None
        result = await ChainVerifier(
            db_path=self._db_path, genesis_hash=self._genesis_hash
        ).verify()
        return IncidentReport(
            alert=alert,
            chain_status=result.status.value,
            first_invalid_seq=result.first_invalid_seq,
            generated_at=datetime.now(UTC),
        )
