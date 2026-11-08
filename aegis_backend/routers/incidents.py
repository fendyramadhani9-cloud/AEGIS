"""
AEGIS Incidents & AI Security Analysis REST Endpoints.
Coordinates multi-alert incident correlation, timeline reconstruction,
risk assessments, and AI-powered security investigations.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body, status as http_status
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import logging

from aegis_backend.repository import BaseAegisRepository, get_repository
from aegis_backend.tenancy import get_scoped_repository, AuthUser, get_request_user, DEV_USER
from aegis_backend.incident_service import IncidentService
from aegis_backend.ai_provider import get_ai_provider
from aegis_backend.schemas import (
    IncidentItem,
    PaginatedIncidentsResponse,
    IncidentDetailResponse,
    IncidentStatusUpdateRequest,
    IncidentTimelineItem,
    AIAnalysisItem,
    IncidentSummaryResponse,
    AnalyzeIncidentRequest,
    AIHealthResponse,
    AlertEvidenceItem,
    ErrorResponse,
)

logger = logging.getLogger("aegis_backend.routers.incidents")

router = APIRouter(prefix="/api", tags=["Incidents & AI Analysis"])


def get_incident_service(repo: BaseAegisRepository = Depends(get_scoped_repository)) -> IncidentService:
    return IncidentService(repository=repo, ai_provider=get_ai_provider())


# ==========================================
# 1. AI HEALTH & SUMMARY ENDPOINTS
# ==========================================

@router.get(
    "/analysis/health",
    response_model=AIHealthResponse,
    summary="Check AI Provider Health",
)
def get_ai_health(service: IncidentService = Depends(get_incident_service)):
    """Reports status, configured model, and connectivity of the AI analysis provider."""
    health_data = service.ai_provider.health_check()
    return AIHealthResponse.model_validate(health_data)


@router.get(
    "/incidents/summary",
    response_model=IncidentSummaryResponse,
    summary="Get Incident Metrics Summary",
)
@router.get(
    "/analysis/summary",
    response_model=IncidentSummaryResponse,
    summary="Get Analysis Metrics Summary (Alias)",
    include_in_schema=False,
)
def get_incidents_summary(
    host_id: Optional[str] = Query(default=None, description="Filter summary by host ID"),
    service: IncidentService = Depends(get_incident_service),
):
    """Returns aggregated incident lifecycle status counts and risk distribution."""
    return service.get_incidents_summary(host_id=host_id)


# ==========================================
# 2. INCIDENT LIFECYCLE & LISTING
# ==========================================

@router.get(
    "/incidents",
    response_model=PaginatedIncidentsResponse,
    summary="List Security Incidents",
)
def list_incidents(
    limit: Optional[int] = Query(default=None, ge=1, le=100),
    offset: Optional[int] = Query(default=None, ge=0),
    page: Optional[int] = Query(default=None, ge=1),
    page_size: Optional[int] = Query(default=None, ge=1, le=100),
    host_id: Optional[str] = Query(default=None, description="Filter by target host ID"),
    status: Optional[str] = Query(default=None, description="Filter by status (new, investigating, confirmed, etc.)"),
    severity: Optional[str] = Query(default=None, description="Filter by severity"),
    search: Optional[str] = Query(default=None, description="Search keyword in incident title or ID"),
    repo: BaseAegisRepository = Depends(get_scoped_repository),
):
    """Retrieves paginated, filtered list of correlated security incidents."""
    eff_limit = limit or page_size or 20
    eff_offset = offset if offset is not None else (((page or 1) - 1) * eff_limit)
    try:
        items, total = repo.list_incidents(
            limit=eff_limit,
            offset=eff_offset,
            host_id=host_id,
            status=status,
            severity=severity,
            search=search,
        )
        return PaginatedIncidentsResponse(
            items=[IncidentItem.model_validate(i) for i in items],
            total=total,
            limit=eff_limit,
            offset=eff_offset,
        )
    except Exception as e:
        logger.error(f"Failed to list incidents: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error while querying incidents: {type(e).__name__}",
        )


@router.post(
    "/incidents",
    response_model=List[IncidentItem],
    status_code=http_status.HTTP_200_OK,
    summary="Trigger Automated Alert Correlation into Incidents",
)
def correlate_incidents(
    payload: Optional[Dict[str, Any]] = Body(default=None),
    host_id: Optional[str] = Query(default=None, description="Optional target host to correlate"),
    service: IncidentService = Depends(get_incident_service),
):
    """
    Scans alerts on a host (or all hosts) and correlates unlinked alerts
    into multi-stage security incidents based on entity and temporal proximity.
    """
    target_host = host_id or (payload.get("host_id") if payload else None)
    try:
        correlated = service.correlate_alerts(host_id=target_host)
        return correlated
    except Exception as e:
        logger.error(f"Correlation error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to correlate alerts: {type(e).__name__}",
        )


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentDetailResponse,
    summary="Get Incident Detail",
)
def get_incident(
    incident_id: str,
    service: IncidentService = Depends(get_incident_service),
):
    """Retrieves full incident view with correlated alerts, evidence metrics, and AI analysis."""
    detail = service.get_incident_detail(incident_id)
    if not detail:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )
    return detail


@router.patch(
    "/incidents/{incident_id}/status",
    response_model=IncidentItem,
    summary="Update Incident Status",
)
def update_incident_status(
    incident_id: str,
    req: IncidentStatusUpdateRequest,
    service: IncidentService = Depends(get_incident_service),
    user: AuthUser = Depends(get_request_user),
):
    """Updates incident lifecycle status and appends transition to audit history."""
    # Enforce identity integrity: in authenticated mode, operator must reflect the authenticated user (preventing spoofing)
    if user and user != DEV_USER:
        operator_name = user.username
    else:
        operator_name = req.operator or (user.username if user else "admin")
    updated = service.update_incident_status(
        incident_id=incident_id,
        new_status=req.status,
        note=req.note,
        operator=operator_name,
    )
    if not updated:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )
    return updated


# ==========================================
# 3. TIMELINE & EVIDENCE
# ==========================================

@router.get(
    "/incidents/{incident_id}/timeline",
    response_model=List[IncidentTimelineItem],
    summary="Get Incident Unified Timeline",
)
def get_incident_timeline(
    incident_id: str,
    service: IncidentService = Depends(get_incident_service),
):
    """Reconstructs end-to-end chronological timeline merging telemetry, alerts, and investigations."""
    return service.get_incident_timeline(incident_id)


@router.get(
    "/incidents/{incident_id}/evidence",
    response_model=List[AlertEvidenceItem],
    summary="Get All Supporting Evidence for Incident",
)
def get_incident_evidence(
    incident_id: str,
    service: IncidentService = Depends(get_incident_service),
):
    """Retrieves all concrete telemetry evidence events across all correlated alerts in the incident."""
    alerts = service.repo.get_incident_alerts(incident_id)
    if not alerts and not service.repo.get_incident_by_id(incident_id):
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )

    all_evidence = []
    seen_events = set()
    for a in alerts:
        aid = a.get("id")
        if aid:
            evs = service.repo.get_alert_evidence(aid) or []
            for ev in evs:
                ev_id = ev.get("event_id") or ev.get("id")
                if ev_id not in seen_events:
                    seen_events.add(ev_id)
                    all_evidence.append(AlertEvidenceItem.model_validate(ev))

    return all_evidence


# ==========================================
# 4. AI INVESTIGATION TRIGGER & RESULTS
# ==========================================

@router.post(
    "/incidents/{incident_id}/analyze",
    response_model=AIAnalysisItem,
    summary="Run AI Security Investigation on Incident",
)
def analyze_incident(
    incident_id: str,
    req: AnalyzeIncidentRequest = AnalyzeIncidentRequest(),
    service: IncidentService = Depends(get_incident_service),
):
    """
    Executes AI security analysis on the incident.
    Constructs sanitized forensic context, invokes configured provider, validates output,
    and returns grounded investigation findings.
    """
    analysis = service.analyze_incident(incident_id=incident_id, force=req.force)
    if not analysis:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )
    return analysis


@router.get(
    "/incidents/{incident_id}/analysis",
    response_model=AIAnalysisItem,
    summary="Get Latest AI Analysis for Incident",
)
def get_incident_analysis(
    incident_id: str,
    service: IncidentService = Depends(get_incident_service),
):
    """Retrieves the latest AI analysis result for an incident."""
    analysis = service.repo.get_latest_ai_analysis(incident_id)
    if not analysis:
        # Check incident existence
        inc = service.repo.get_incident_by_id(incident_id)
        if not inc:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Incident with ID '{incident_id}' not found.",
            )
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"No AI analysis has been run for incident '{incident_id}'. Use POST /analyze to trigger.",
        )
    return AIAnalysisItem.model_validate(analysis)


# ==========================================
# 5. SINGLE ALERT ANALYSIS (BACKWARD COMPATIBILITY)
# ==========================================

@router.get(
    "/alerts/{alert_id}/analysis",
    response_model=AIAnalysisItem,
    summary="Get AI Analysis for Alert",
)
def get_alert_analysis(
    alert_id: str,
    service: IncidentService = Depends(get_incident_service),
):
    """Retrieves AI analysis for an alert, checking if it belongs to a correlated incident."""
    alert = service.repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found.",
        )

    # Check if part of an incident
    incidents, _ = service.repo.list_incidents(host_id=alert.get("host_id"), limit=50)
    for inc in incidents:
        linked_alerts = service.repo.get_incident_alerts(inc["id"])
        if any(a.get("id") == alert_id for a in linked_alerts):
            analysis = service.repo.get_latest_ai_analysis(inc["id"])
            if analysis:
                return AIAnalysisItem.model_validate(analysis)

    # If unanalyzed, trigger or return unavailable
    return service.analyze_incident(incidents[0]["id"] if incidents else alert_id, force=False)


@router.post(
    "/alerts/{alert_id}/analyze",
    response_model=AIAnalysisItem,
    summary="Trigger AI Analysis for Alert",
)
def analyze_alert(
    alert_id: str,
    req: AnalyzeIncidentRequest = AnalyzeIncidentRequest(),
    service: IncidentService = Depends(get_incident_service),
):
    """Triggers AI analysis on a single alert (auto-creating an incident if needed)."""
    alert = service.repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found.",
        )

    # Correlate alerts on this host first
    service.correlate_alerts(host_id=alert.get("host_id"))

    # Find the incident containing this alert
    incidents, _ = service.repo.list_incidents(host_id=alert.get("host_id"), limit=20)
    target_inc_id = None
    for inc in incidents:
        linked_alerts = service.repo.get_incident_alerts(inc["id"])
        if any(a.get("id") == alert_id for a in linked_alerts):
            target_inc_id = inc["id"]
            break

    if not target_inc_id and incidents:
        target_inc_id = incidents[0]["id"]

    if not target_inc_id:
        # Fallback create single-alert incident
        inc_dict = {
            "id": f"INC-{alert.get('host_id')}-{alert_id[:8]}",
            "host_id": alert.get("host_id"),
            "title": alert.get("title"),
            "severity": alert.get("severity"),
            "risk_level": alert.get("severity"),
            "risk_score": 60,
            "status": "new",
            "primary_alert_id": alert_id,
            "alert_count": 1,
            "first_seen_at": alert.get("detected_at"),
            "last_seen_at": alert.get("detected_at"),
            "attack_scenario": alert.get("reason"),
        }
        service.repo.upsert_incident(inc_dict, alert_ids=[alert_id])
        target_inc_id = inc_dict["id"]

    analysis = service.analyze_incident(target_inc_id, force=req.force)
    return analysis
