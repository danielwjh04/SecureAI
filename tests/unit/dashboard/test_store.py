"""Tests for the bounded alert + registry projection rings."""

from datetime import UTC, datetime

from secureSG.dashboard.store import DashboardStore


def _now() -> datetime:
    return datetime(2026, 6, 26, tzinfo=UTC)


def _alert(store: DashboardStore, reason: str) -> str:
    return store.record_alert(
        created_at=_now(),
        session_id="s",
        tool_name="scrape_page",
        rule_id="injection.signature",
        category="Prompt Injection",
        reason=reason,
        redacted_payload="payload",
    ).id


def test_alerts_listed_newest_first() -> None:
    store = DashboardStore(max_alerts=5, max_registry=5)
    first = _alert(store, "r1")
    second = _alert(store, "r2")
    assert [a.id for a in store.alerts()] == [second, first]


def test_find_alert_by_id() -> None:
    store = DashboardStore(max_alerts=5, max_registry=5)
    alert_id = _alert(store, "r")
    found = store.find_alert(alert_id)
    assert found is not None
    assert found.id == alert_id
    assert store.find_alert("missing") is None


def test_alert_ring_evicts_oldest() -> None:
    store = DashboardStore(max_alerts=2, max_registry=2)
    oldest = _alert(store, "r1")
    _alert(store, "r2")
    _alert(store, "r3")  # evicts the oldest
    ids = [a.id for a in store.alerts()]
    assert oldest not in ids
    assert len(ids) == 2


def test_registry_records_and_lists_newest_first() -> None:
    store = DashboardStore(max_alerts=5, max_registry=5)
    store.record_registry(
        created_at=_now(), session_id="s", tool_name="read_file", redacted_content="a"
    )
    entry = store.record_registry(
        created_at=_now(), session_id="s", tool_name="read_file", redacted_content="b"
    )
    assert store.registry()[0].id == entry.id
