"""
Monitored Linux Hosts Endpoints for AEGIS Backend.
Provides read-only access to host registry and status.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from typing import Optional
from datetime import datetime, timezone
from aegis_backend.schemas import HostItem, PaginatedHostsResponse, ErrorResponse
from aegis_backend.metrics_store import metrics_store
from aegis_backend.repository import BaseAegisRepository, get_repository
from aegis_backend.tenancy import get_scoped_repository

router = APIRouter(prefix="/api/hosts", tags=["Hosts"])


def derive_agent_status(last_data_at_iso: Optional[str], stored_status: Optional[str] = None) -> str:
    """
    Computes agent status dynamically based on elapsed time since last_data_at:
    - <= 300s (5 min): 'online'
    - <= 1800s (30 min): 'delayed'
    - > 1800s: 'offline'
    - None / no data: 'offline'
    """
    if not last_data_at_iso:
        return stored_status if stored_status in ["online", "delayed", "offline"] else "offline"
    try:
        last_dt = datetime.fromisoformat(last_data_at_iso.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff_sec = (now - last_dt).total_seconds()
        if diff_sec <= 300:
            return "online"
        elif diff_sec <= 1800:
            return "delayed"
        else:
            return "offline"
    except Exception:
        return stored_status if stored_status in ["online", "delayed", "offline"] else "offline"



@router.get(
    "",
    response_model=PaginatedHostsResponse,
    responses={500: {"model": ErrorResponse}},
    summary="List Monitored Hosts",
)
def list_hosts(
    limit: int = Query(default=20, ge=1, le=100, description="Number of records to return (1-100)"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    agent_status: Optional[str] = Query(
        default=None,
        pattern="^(online|delayed|offline|unknown)$",
        description="Filter by host agent status",
    ),
    repo: BaseAegisRepository = Depends(get_scoped_repository),
):
    """Retrieves paginated list of monitored Linux hosts."""
    try:
        if agent_status:
            raw_hosts, _ = repo.list_hosts(limit=10000, offset=0, status=None)
            derived_all = []
            for h in raw_hosts:
                h_dict = dict(h)
                h_dict["agent_status"] = derive_agent_status(
                    h_dict.get("last_data_at"), h_dict.get("agent_status", "online")
                )
                h_dict["metrics"] = metrics_store.get(str(h_dict.get("id", "")))
                if h_dict["agent_status"] == agent_status:
                    derived_all.append(HostItem.model_validate(h_dict))
            total = len(derived_all)
            items = derived_all[offset : offset + limit]
        else:
            data, total = repo.list_hosts(limit=limit, offset=offset, status=None)
            items = []
            for h in data:
                h_dict = dict(h)
                h_dict["agent_status"] = derive_agent_status(
                    h_dict.get("last_data_at"), h_dict.get("agent_status", "online")
                )
                h_dict["metrics"] = metrics_store.get(str(h_dict.get("id", "")))
                items.append(HostItem.model_validate(h_dict))
        return PaginatedHostsResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query hosts: {type(e).__name__}",
        )


@router.get(
    "/{host_id}",
    response_model=HostItem,
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Get Single Host Detail",
)
def get_host(
    host_id: str,
    repo: BaseAegisRepository = Depends(get_scoped_repository),
):
    """Retrieves details of a specific host by its ID."""
    try:
        host = repo.get_host_by_id(host_id)
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID '{host_id}' not found.",
            )
        h_dict = dict(host)
        h_dict["agent_status"] = derive_agent_status(h_dict.get("last_data_at"), h_dict.get("agent_status", "online"))
        h_dict["metrics"] = metrics_store.get(str(h_dict.get("id", host_id)))
        return HostItem.model_validate(h_dict)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve host: {type(e).__name__}",
        )
