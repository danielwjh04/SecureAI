"""Bounded in-memory projections for the dashboard's content panels.

The audit chain is the durable record of *verdicts* but deliberately stores no
content. The Alert Feed and Safe Content Registry need the (redacted) content
itself, so they are kept here as bounded rings — ephemeral UX aids the live feed
and recent-history views read. The durable Monthly Summary reads the chain.
"""

from collections import deque
from datetime import datetime
from uuid import uuid4

from secureSG.schemas.dashboard import AlertView, RegistryEntry


class DashboardStore:
    """Bounded rings of recent alerts and verified-clean content entries."""

    def __init__(self, *, max_alerts: int, max_registry: int) -> None:
        self._alerts: deque[AlertView] = deque(maxlen=max_alerts)
        self._registry: deque[RegistryEntry] = deque(maxlen=max_registry)

    def record_alert(
        self,
        *,
        created_at: datetime,
        session_id: str,
        tool_name: str | None,
        rule_id: str,
        category: str,
        reason: str,
        redacted_payload: str,
    ) -> AlertView:
        """Append a blocked-injection alert, evicting the oldest. O(1)."""
        alert = AlertView(
            id=uuid4().hex,
            created_at=created_at,
            session_id=session_id,
            tool_name=tool_name,
            rule_id=rule_id,
            category=category,
            reason=reason,
            redacted_payload=redacted_payload,
        )
        self._alerts.append(alert)
        return alert

    def record_registry(
        self,
        *,
        created_at: datetime,
        session_id: str,
        tool_name: str,
        redacted_content: str,
    ) -> RegistryEntry:
        """Append a verified-clean content entry, evicting the oldest. O(1)."""
        entry = RegistryEntry(
            id=uuid4().hex,
            created_at=created_at,
            session_id=session_id,
            tool_name=tool_name,
            redacted_content=redacted_content,
        )
        self._registry.append(entry)
        return entry

    def alerts(self) -> list[AlertView]:
        """Recent alerts, newest first. O(n)."""
        return list(reversed(self._alerts))

    def registry(self) -> list[RegistryEntry]:
        """Recent verified-clean entries, newest first. O(n)."""
        return list(reversed(self._registry))

    def find_alert(self, alert_id: str) -> AlertView | None:
        """Look up an alert by id, newest first. O(n) over the bounded ring."""
        for alert in reversed(self._alerts):
            if alert.id == alert_id:
                return alert
        return None
