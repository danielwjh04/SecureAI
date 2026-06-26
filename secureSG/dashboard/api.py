"""REST endpoints for the dashboard panels: summary, alerts, registry, report.

Dependencies (the dashboard service, the audit reader, and settings) are read
from ``app.state``, where ``create_app`` places them when the dashboard is
enabled. The summary reads the durable audit chain; alerts and registry read the
in-memory projection rings; a report bundles an alert with a fresh chain proof.
"""

from fastapi import APIRouter, HTTPException, Query, Request

from secureSG.config.settings import Settings
from secureSG.dashboard.reader import AuditReader
from secureSG.dashboard.service import DashboardService
from secureSG.schemas.dashboard import (
    AlertView,
    IncidentReport,
    RegistryEntry,
    SummaryReport,
)

router = APIRouter(prefix="/dashboard")


def _service(request: Request) -> DashboardService:
    service: DashboardService = request.app.state.dashboard
    return service


@router.get("/summary", response_model=SummaryReport)
async def get_summary(
    request: Request, window_days: int | None = Query(default=None, ge=1)
) -> SummaryReport:
    settings: Settings = request.app.state.settings
    reader: AuditReader = request.app.state.audit_reader
    window = (
        window_days
        if window_days is not None
        else settings.dashboard_summary_window_days
    )
    return await reader.summary(window)


@router.get("/alerts", response_model=list[AlertView])
async def get_alerts(request: Request) -> list[AlertView]:
    return _service(request).alerts()


@router.get("/registry", response_model=list[RegistryEntry])
async def get_registry(request: Request) -> list[RegistryEntry]:
    return _service(request).registry()


@router.post("/alerts/{alert_id}/report", response_model=IncidentReport)
async def post_report(request: Request, alert_id: str) -> IncidentReport:
    report = await _service(request).report(alert_id)
    if report is None:
        raise HTTPException(status_code=404, detail="unknown alert id")
    return report
