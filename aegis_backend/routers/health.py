"""
Health Check Endpoints for AEGIS Backend.
Provides shallow application health and deep database connectivity checks
without revealing sensitive connection strings, keys, or internal details.
"""

from fastapi import APIRouter, Depends, status
from datetime import datetime, timezone
from aegis_backend.config import settings
from aegis_backend.schemas import HealthResponse, DatabaseHealthResponse
from aegis_backend.repository import BaseAegisRepository, get_repository

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


@router.get("/database", response_model=DatabaseHealthResponse, summary="Database Connectivity & SSoT Health Check")
def get_database_health(repo: BaseAegisRepository = Depends(get_repository)):
    """
    Performs a lightweight, read-only query against Supabase system_status table.
    Safely reports connection status and SSoT observability indicators without leaking credentials.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    if not settings.is_supabase_configured and not hasattr(repo, "hosts"):
        return DatabaseHealthResponse(
            status="unconfigured",
            connected=False,
            checked_at=now_iso,
            message="Supabase credentials (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY) are not configured in environment.",
            database_mode=settings.database_mode,
            authoritative_source="sqlite_local" if settings.database_mode == "hybrid" else "unconfigured",
            failover_state="unconfigured",
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
    )

