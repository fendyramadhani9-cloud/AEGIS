"""
Health Check Endpoints for AEGIS Backend.
Provides shallow application health and deep database connectivity checks
without revealing sensitive connection strings, keys, or internal details.
"""

from fastapi import APIRouter, Depends, status, HTTPException
from datetime import datetime, timezone
from aegis_backend.config import settings
from aegis_backend.schemas import HealthResponse, DatabaseHealthResponse, ReadinessResponse
from aegis_backend.repository import BaseAegisRepository, get_repository
from aegis_backend.state_machine import state_machine, DatabaseState

router = APIRouter(prefix="/api/health", tags=["Health"])


@router.get("", response_model=HealthResponse, summary="Application Health Check")
def get_app_health():
    """Returns basic service health, environment, and version."""
    return HealthResponse(
        status="ok",
        service="aegis-backend",
        environment=settings.aegis_env,
        version="0.1.0",
    )


@router.get("/ready", response_model=ReadinessResponse, summary="Readiness Probe & Traffic Gate")
def get_readiness():
    """
    Evaluates whether the backend is ready to accept operational mutations.
    Fails with HTTP 503 if startup catch-up is incomplete or if in a recovery/failure state.
    """
    health = state_machine.get_health_summary()
    is_ready = state_machine.is_mutation_allowed()

    if not is_ready and state_machine.current_state in (DatabaseState.RECOVERY_REQUIRED, DatabaseState.CLOUD_UNAVAILABLE, DatabaseState.RECONCILIATION):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "ready": False,
                "status": "not_ready",
                "state": health["current_state"],
                "is_mutation_allowed": False,
                "authoritative_database": health["authoritative_database"],
                "reason": health["reason"],
            },
        )

    return ReadinessResponse(
        ready=True,
        status="ready" if is_ready else "read_only",
        state=health["current_state"],
        is_mutation_allowed=is_ready,
        authoritative_database=health["authoritative_database"],
        reason=health["reason"],
    )


@router.get("/database", response_model=DatabaseHealthResponse, summary="Database Connectivity & SSoT Health Check")
def get_database_health(repo: BaseAegisRepository = Depends(get_repository)):
    """
    Performs a lightweight, read-only query against Supabase system_status table.
    Safely reports connection status and SSoT observability indicators without leaking credentials.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    sm_health = state_machine.get_health_summary()

    if not settings.is_supabase_configured and not hasattr(repo, "hosts"):
        return DatabaseHealthResponse(
            status="unconfigured",
            connected=False,
            checked_at=now_iso,
            message="Supabase credentials (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY) are not configured in environment.",
            database_mode=settings.database_mode,
            authoritative_source="sqlite_local" if settings.database_mode == "hybrid" else "unconfigured",
            failover_state="unconfigured",
            state_machine_state=sm_health["current_state"],
            is_mutation_allowed=sm_health["is_mutation_allowed"],
            is_read_allowed=sm_health["is_read_allowed"],
            state_reason=sm_health["reason"],
        )

    connected, message, latency = repo.check_database_health()
    health_status = "healthy" if connected else "degraded"

    # Mirror queue observability stats
    mirror_stats = {}
    if hasattr(repo, "get_mirror_sync_stats"):
        try:
            mirror_stats = repo.get_mirror_sync_stats()
        except Exception:
            pass

    return DatabaseHealthResponse(
        status=health_status,
        connected=connected,
        checked_at=now_iso,
        message=message,
        latency_ms=latency,
        database_mode=settings.database_mode,
        authoritative_source="supabase_cloud" if settings.database_mode == "cloud_ssot" else "sqlite_local",
        mirror_queue_depth=mirror_stats.get("queue_depth", 0),
        oldest_pending_age_seconds=mirror_stats.get("oldest_pending_age_seconds"),
        last_successful_mirror_at=mirror_stats.get("last_successful_mirror_at"),
        failover_state="normal" if connected else "fail_closed_alerting",
        state_machine_state=sm_health["current_state"],
        is_mutation_allowed=sm_health["is_mutation_allowed"],
        is_read_allowed=sm_health["is_read_allowed"],
        state_reason=sm_health["reason"],
    )

