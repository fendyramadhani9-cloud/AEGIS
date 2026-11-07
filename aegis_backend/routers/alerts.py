"""
Security Alerts Endpoints for AEGIS Backend.
Provides read-only access to Rules Engine alerts without modifying severity.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from typing import Optional
from aegis_backend.schemas import AlertItem, PaginatedAlertsResponse, AlertEvidenceItem, AlertEvidenceResponse, ErrorResponse
from aegis_backend.repository import BaseAegisRepository, get_repository

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get(
    "",
    response_model=PaginatedAlertsResponse,
    responses={500: {"model": ErrorResponse}},
    summary="List Security Alerts",
)
def list_alerts(
    limit: int = Query(default=20, ge=1, le=100, description="Number of records to return (1-100)"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    host_id: Optional[str] = Query(default=None, description="Filter by target host ID"),
    severity: Optional[str] = Query(
        default=None,
        pattern="^(critical|high|medium|low|info)$",
        description="Filter by severity level",
    ),
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Retrieves paginated list of deterministic security alerts."""
    try:
        data, total = repo.list_alerts(
            limit=limit,
            offset=offset,
            host_id=host_id,
            severity=severity,
        )
        items = [AlertItem.model_validate(a) for a in data]
        return PaginatedAlertsResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query alerts: {type(e).__name__}",
        )


@router.get(
    "/{alert_id}",
    response_model=AlertItem,
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Get Single Alert Detail",
)
def get_alert(
    alert_id: str,
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Retrieves details of a specific alert by its ID."""
    try:
        alert = repo.get_alert_by_id(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert with ID '{alert_id}' not found.",
            )
        return AlertItem.model_validate(alert)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve alert: {type(e).__name__}",
        )


@router.get(
    "/{alert_id}/evidence",
    response_model=AlertEvidenceResponse,
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Get Alert Supporting Evidence",
)
def get_alert_evidence(
    alert_id: str,
    repo: BaseAegisRepository = Depends(get_repository),
):
    """
    Retrieves supporting telemetry evidence events bound to a specific alert.
    Guarantees:
      - Validates parent alert existence (404 on missing alert).
      - Joins evidence directly with telemetry_events.
      - Enforces strict cross-host isolation (host_id match).
      - Enforces defense-in-depth secret sanitization.
      - Zero fallback to mock data in live mode.
    """
    try:
        items = repo.get_alert_evidence(alert_id)
        if items is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert with ID '{alert_id}' not found.",
            )
        evidence_items = [AlertEvidenceItem.model_validate(ev) for ev in items]
        return AlertEvidenceResponse(
            alert_id=alert_id,
            items=evidence_items,
            total=len(evidence_items),
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve alert evidence: {type(e).__name__}",
        )

