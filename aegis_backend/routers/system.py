"""
System Status Endpoint for AEGIS Backend.
Retrieves backend components status from system_status table.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from aegis_backend.schemas import SystemStatusResponse, ErrorResponse
from aegis_backend.repository import BaseAegisRepository, get_repository
from aegis_backend.tenancy import get_scoped_repository

router = APIRouter(prefix="/api/system", tags=["System"])


@router.get(
    "/status",
    response_model=SystemStatusResponse,
    responses={500: {"model": ErrorResponse}},
    summary="Get System Component Health Status",
)
def get_system_status(repo: BaseAegisRepository = Depends(get_scoped_repository)):
    """Retrieves operational status for Collector, Rules Engine, and AI Provider."""
    try:
        row = repo.get_system_status()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="System status record not found in database.",
            )
        return SystemStatusResponse.model_validate(row)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query system status: {type(e).__name__}",
        )

