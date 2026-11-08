"""
Security Alerts Endpoints for AEGIS Backend.
Provides read-only access to Rules Engine alerts without modifying severity.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from datetime import datetime, timezone
from typing import Optional
from aegis_backend.schemas import (
    AlertItem,
    PaginatedAlertsResponse,
    AlertEvidenceItem,
    AlertEvidenceResponse,
    AiAnalysisResponse,
    HandoffDocumentResponse,
    RecoveryVerificationResponse,
    InvestigationUpdateRequest,
    InvestigationStateResponse,
    IncidentReplayResponse,
    AlertContextResponse,
    SignedEvidenceBundleResponse,
    ErrorResponse,
)
from aegis_backend.repository import BaseAegisRepository, get_repository
from aegis_backend.tenancy import get_scoped_repository, AuthUser, get_request_user, DEV_USER
from aegis_backend.incident_service import (
    op_store,
    run_alert_ai_analysis,
    generate_handoff_document,
    verify_alert_recovery,
    build_incident_replay,
    build_alert_context,
    build_signed_evidence_bundle,
    detect_collection_gaps,
)

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
    repo: BaseAegisRepository = Depends(get_scoped_repository),
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
    repo: BaseAegisRepository = Depends(get_scoped_repository),
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
    repo: BaseAegisRepository = Depends(get_scoped_repository),
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


@router.post(
    "/{alert_id}/analyze",
    response_model=AiAnalysisResponse,
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Run AI RM Analysis on Alert",
)
def analyze_alert(
    alert_id: str,
    force: bool = Query(default=False, description="Bypass per-alert cooldown cache"),
    cooldown_sec: int = Query(default=10, ge=0, le=300, description="Cooldown window in seconds"),
    repo: BaseAegisRepository = Depends(get_scoped_repository),
):
    """
    Runs AI-assisted Runtime Monitor (RM) analysis on a deterministic alert and its supporting evidence.
    Severity remains strictly immutable. Includes per-alert cooldown to prevent accidental quota exhaustion.
    """
    try:
        alert = repo.get_alert_by_id(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert with ID '{alert_id}' not found.",
            )
        if not force and cooldown_sec > 0:
            cached = op_store.ai_analyses.get(alert_id)
            if cached and cached.state == "ready" and cached.generated_at:
                try:
                    gen_dt = datetime.fromisoformat(cached.generated_at.replace("Z", "+00:00"))
                    if (datetime.now(timezone.utc) - gen_dt).total_seconds() < cooldown_sec:
                        return cached
                except Exception:
                    pass
        evidence_items = repo.get_alert_evidence(alert_id) or []
        return run_alert_ai_analysis(alert, evidence_items, repo=repo)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute AI analysis: {type(e).__name__}",
        )


@router.get(
    "/{alert_id}/handoff",
    response_model=HandoffDocumentResponse,
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Generate Portable AI Investigation & Remediation Handoff Markdown",
)
def get_alert_handoff(
    alert_id: str,
    repo: BaseAegisRepository = Depends(get_scoped_repository),
):
    """
    Generates a context-rich, portable Markdown (.md) investigation and remediation prompt
    separating confirmed facts from hypotheses and providing safe rollback instructions.
    """
    try:
        alert = repo.get_alert_by_id(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert with ID '{alert_id}' not found.",
            )
        host_id = alert.get("host_id", "")
        host = repo.get_host_by_id(host_id)
        evidence_items = repo.get_alert_evidence(alert_id) or []
        gaps = detect_collection_gaps([host] if host else [], host_id=host_id)
        return generate_handoff_document(alert, host, evidence_items, gaps=gaps)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate handoff document: {type(e).__name__}",
        )


@router.post(
    "/{alert_id}/verify",
    response_model=RecoveryVerificationResponse,
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Run Automatic Recovery Verification on Alert",
)
def verify_alert(
    alert_id: str,
    window_min: int = Query(default=15, ge=0, le=1440),
    repo: BaseAegisRepository = Depends(get_scoped_repository),
):
    """
    Evaluates whether the triggering conditions of an alert have recovered.
    Missing telemetry or an offline agent never counts as proof of recovery.
    """
    try:
        alert = repo.get_alert_by_id(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert with ID '{alert_id}' not found.",
            )
        host_id = alert.get("host_id", "")
        host = repo.get_host_by_id(host_id)
        recent_alerts, _ = repo.list_alerts(limit=100, offset=0, host_id=host_id)
        open_gaps = detect_collection_gaps([host] if host else [], host_id=host_id, open_only=True)
        return verify_alert_recovery(
            alert=alert,
            host=host,
            recent_alerts=recent_alerts,
            open_gaps=open_gaps,
            observation_window_min=window_min,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to verify alert recovery: {type(e).__name__}",
        )


@router.get(
    "/{alert_id}/replay",
    response_model=IncidentReplayResponse,
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Get Chronological Incident Replay Reconstruction",
)
def get_alert_replay(
    alert_id: str,
    repo: BaseAegisRepository = Depends(get_scoped_repository),
):
    """Reconstructs an evidence-based chronological replay of the incident."""
    try:
        alert = repo.get_alert_by_id(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert with ID '{alert_id}' not found.",
            )
        host = repo.get_host_by_id(alert.get("host_id", ""))
        evidence_items = repo.get_alert_evidence(alert_id) or []
        return build_incident_replay(alert, host, evidence_items)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to build incident replay: {type(e).__name__}",
        )


@router.get(
    "/{alert_id}/investigation",
    response_model=InvestigationStateResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Get Operator Investigation Workflow State",
)
def get_alert_investigation(
    alert_id: str,
    repo: BaseAegisRepository = Depends(get_scoped_repository),
):
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found.",
        )
    return op_store.get_investigation(alert_id)


@router.post(
    "/{alert_id}/investigation",
    response_model=InvestigationStateResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Update Operator Investigation Status and Notes",
)
def update_alert_investigation(
    alert_id: str,
    req: InvestigationUpdateRequest,
    repo: BaseAegisRepository = Depends(get_scoped_repository),
    user: AuthUser = Depends(get_request_user),
):
    """
    Updates the manual investigation lifecycle status and appends operator notes.
    Never modifies the immutable alert severity.
    """
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found.",
        )
    # Enforce identity integrity: in authenticated mode, author must reflect the authenticated user (preventing spoofing)
    if user and user != DEV_USER:
        author_name = user.username
    else:
        author_name = req.author or (user.username if user else "ops-admin")
    return op_store.update_investigation(
        alert_id=alert_id,
        status=req.status,
        note=req.note,
        author=author_name,
        alert=alert,
        repo=repo,
    )


@router.get(
    "/{alert_id}/context",
    response_model=AlertContextResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Get Multi-Stage Kill-Chain Correlation & Blast Radius Summary",
)
def get_alert_context(
    alert_id: str,
    repo: BaseAegisRepository = Depends(get_scoped_repository),
):
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found.",
        )
    host_id = alert.get("host_id", "")
    all_host_alerts, _ = repo.list_alerts(limit=100, offset=0, host_id=host_id)
    evidence_items = repo.get_alert_evidence(alert_id) or []
    return build_alert_context(alert, all_host_alerts, evidence_items)


@router.get(
    "/{alert_id}/evidence-bundle",
    response_model=SignedEvidenceBundleResponse,
    responses={404: {"model": ErrorResponse}},
    summary="Export Signed SHA-256 Forensic Evidence Bundle (.json)",
)
def export_alert_evidence_bundle(
    alert_id: str,
    repo: BaseAegisRepository = Depends(get_scoped_repository),
):
    alert = repo.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found.",
        )
    evidence_items = repo.get_alert_evidence(alert_id) or []
    return build_signed_evidence_bundle(alert, evidence_items)


