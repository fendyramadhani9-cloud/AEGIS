"""
AEGIS Security Checker FastAPI Router.
Provides endpoints for querying security checks, execution runs, findings, posture summaries,
and receiving authenticated agent inspection submissions.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status, Header
import logging

from aegis_backend.config import settings
from aegis_backend.repository import BaseAegisRepository, get_repository
from aegis_backend.security_checker_catalog import SECURITY_CHECKS_CATALOG, SecurityCheckDefinition
from aegis_backend.schemas import (
    SecurityFindingItem,
    PaginatedSecurityFindingsResponse,
    SecurityCheckRunItem,
    PaginatedSecurityRunsResponse,
    SecuritySummaryResponse,
    AgentSecurityCheckResultsRequest,
    AgentSecurityCheckResultsResponse,
    TriggerRunRequest,
    TriggerRunResponse,
)

logger = logging.getLogger("aegis_backend.security_checker")

router = APIRouter(
    prefix="/api/security-checker",
    tags=["Security Checker"],
)


def verify_agent_token(x_agent_token: Optional[str] = Header(None, alias="X-Agent-Token")):
    """Dependency enforcing agent authentication for submission endpoints."""
    if not x_agent_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required authentication token header: X-Agent-Token",
        )
    if x_agent_token != settings.agent_ingest_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent authentication token.",
        )
    return x_agent_token


# ==============================================================================
# 1. HEALTH & METADATA
# ==============================================================================

@router.get("/health")
def security_checker_health():
    """Module liveness & capability endpoint."""
    return {
        "status": "ok",
        "module": "security-checker",
        "version": "1.0.0",
        "total_catalog_checks": len(SECURITY_CHECKS_CATALOG),
    }


@router.get("/checks", response_model=List[SecurityCheckDefinition])
def list_catalog_checks():
    """Returns definition catalog of all available security checks."""
    return list(SECURITY_CHECKS_CATALOG.values())


@router.get("/hosts")
def list_auditable_hosts(repo: BaseAegisRepository = Depends(get_repository)):
    """Returns list of hosts registered and eligible for security posture audits."""
    hosts, _ = repo.list_hosts(limit=100)
    return {
        "items": [
            {
                "id": h["id"],
                "hostname": h["hostname"],
                "ip_address": h.get("ip_address"),
                "agent_status": h.get("agent_status", "unknown"),
                "last_sc_run_at": h.get("last_sc_run_at"),
            }
            for h in hosts
        ],
        "total": len(hosts),
    }


# ==============================================================================
# 2. RUN MANAGEMENT
# ==============================================================================

@router.post("/runs", response_model=TriggerRunResponse)
def request_security_run(
    payload: TriggerRunRequest,
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Requests agent on host to execute a fresh security audit."""
    host = repo.get_host_by_id(payload.host_id)
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{payload.host_id}' not found.",
        )

    if host.get("agent_status") == "offline" and not payload.force:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Host '{payload.host_id}' is currently offline. Use force=true if requesting queued scan.",
        )

    return TriggerRunResponse(
        status="pending",
        host_id=payload.host_id,
        message=f"Security check run requested for host '{host['hostname']}'.",
        requested_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/runs", response_model=PaginatedSecurityRunsResponse)
def list_security_runs(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    host_id: Optional[str] = Query(None),
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Retrieves paginated history of security check execution runs."""
    items, total = repo.list_security_runs(limit=limit, offset=offset, host_id=host_id)
    return PaginatedSecurityRunsResponse(
        items=[SecurityCheckRunItem.model_validate(it) for it in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/runs/{run_id}", response_model=SecurityCheckRunItem)
def get_security_run_detail(
    run_id: str,
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Retrieves metadata and summary for a single security check run."""
    run = repo.get_security_run_by_id(run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security check run with ID '{run_id}' not found.",
        )
    return SecurityCheckRunItem.model_validate(run)


# ==============================================================================
# 3. FINDINGS QUERIES
# ==============================================================================

@router.get("/findings", response_model=PaginatedSecurityFindingsResponse)
def list_security_findings(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    host_id: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    search: Optional[str] = Query(None),
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Retrieves paginated security evaluation findings with multi-criteria filtering."""
    items, total = repo.list_security_findings(
        limit=limit,
        offset=offset,
        host_id=host_id,
        category=category,
        severity=severity,
        status=status_filter,
        search=search,
    )
    return PaginatedSecurityFindingsResponse(
        items=[SecurityFindingItem.model_validate(it) for it in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/findings/{finding_id}", response_model=SecurityFindingItem)
def get_security_finding_detail(
    finding_id: str,
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Retrieves full details and remediation advice for a single finding."""
    fnd = repo.get_security_finding_by_id(finding_id)
    if not fnd:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security finding with ID '{finding_id}' not found.",
        )
    return SecurityFindingItem.model_validate(fnd)


# ==============================================================================
# 4. SUMMARY & HOST HISTORY
# ==============================================================================

@router.get("/summary", response_model=SecuritySummaryResponse)
def get_security_summary(
    host_id: Optional[str] = Query(None),
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Returns aggregated security posture summary statistics."""
    summary_data = repo.get_security_summary(host_id=host_id)
    return SecuritySummaryResponse.model_validate(summary_data)


@router.get("/hosts/{host_id}/latest")
def get_host_latest_results(
    host_id: str,
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Returns findings from the most recent security check run on specified host."""
    runs, total = repo.list_security_runs(limit=1, offset=0, host_id=host_id)
    if not runs:
        return {"host_id": host_id, "latest_run": None, "findings": []}
    
    latest_run = runs[0]
    findings, _ = repo.list_security_findings(limit=200, offset=0, host_id=host_id)
    run_findings = [f for f in findings if f.get("run_id") == latest_run["id"]]
    return {
        "host_id": host_id,
        "latest_run": latest_run,
        "findings": run_findings,
    }


@router.get("/hosts/{host_id}/history")
def get_host_security_history(
    host_id: str,
    limit: int = Query(10, ge=1, le=50),
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Returns execution run history for a host to enable regression tracking."""
    history = repo.get_host_security_history(host_id=host_id, limit=limit)
    return {
        "host_id": host_id,
        "items": history,
        "total": len(history),
    }


# ==============================================================================
# 5. AGENT RESULT SUBMISSION (AUTHENTICATED)
# ==============================================================================

@router.post("/agent-results", response_model=AgentSecurityCheckResultsResponse)
def submit_agent_security_results(
    payload: AgentSecurityCheckResultsRequest,
    _token: str = Depends(verify_agent_token),
    repo: BaseAegisRepository = Depends(get_repository),
):
    """Receives authenticated security audit results submitted by host agent."""
    run_data = payload.run.model_dump()
    findings_data = [f.model_dump() for f in payload.findings]
    host_id = run_data.get("host_id")

    # 1. Verify host exists
    host = repo.get_host_by_id(host_id)
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' is not registered with AEGIS.",
        )

    # 2. Cross-host validation (all findings must match run host_id)
    for f in findings_data:
        if f.get("host_id") != host_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cross-host finding submission rejected: Finding host '{f.get('host_id')}' != Run host '{host_id}'.",
            )
        if f.get("run_id") != run_data.get("id"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Finding run_id mismatch: '{f.get('run_id')}' != '{run_data.get('id')}'.",
            )

    # 3. Persist run and findings
    try:
        repo.insert_security_check_run(run_data, findings_data)
        logger.info(f"Persisted security check run {run_data['id']} with {len(findings_data)} findings for {host_id}.")
        return AgentSecurityCheckResultsResponse(
            status="ok",
            run_id=run_data["id"],
            host_id=host_id,
            stored_findings=len(findings_data),
            message="Security check results stored successfully.",
        )
    except Exception as e:
        logger.error(f"Error persisting security check results: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store security check results.",
        )

