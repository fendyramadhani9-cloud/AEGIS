"""
AEGIS4 Guardian & Self-Defense API Router.
Exposes status, on-demand Prompt Injection inspection, and host-side watchdog tamper reporting.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from aegis_backend.guardian import guardian_engine
from aegis_backend.routers.telemetry import verify_agent_token
from aegis_backend.tenancy import AuthUser, get_request_user

router = APIRouter(prefix="/api/guardian", tags=["AEGIS4 Self-Defense Guardian"])


class GuardianInspectRequest(BaseModel):
    payload: str = Field(..., min_length=1, max_length=8192)
    context_label: str = Field(default="manual_inspection", max_length=64)
    use_ai_on_trigger: bool = Field(default=True)


class TamperReportRequest(BaseModel):
    host_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=256)
    details: Dict[str, Any] = Field(default_factory=dict)


@router.get("/status", summary="Get AEGIS4 Self-Defense & AI Guardrail Status")
def get_guardian_status(user: AuthUser = Depends(get_request_user)):
    status_data = guardian_engine.get_status()
    status_data["integrity"] = guardian_engine.check_integrity()
    return status_data


@router.post("/inspect", summary="Inspect Untrusted Log/Text via AEGIS4 Prompt Injection Firewall")
def inspect_payload(
    req: GuardianInspectRequest,
    user: AuthUser = Depends(get_request_user),
):
    return guardian_engine.inspect_text(
        req.payload,
        context_label=req.context_label,
        use_ai_on_trigger=req.use_ai_on_trigger,
    )


@router.post("/tamper-report", summary="Report Host Watchdog Anti-Tamper Signal")
def report_tamper(
    req: TamperReportRequest,
    agent_tenant: str = Depends(verify_agent_token),
):
    ev = guardian_engine.record_external_tamper(
        host_id=req.host_id,
        reason=req.reason,
        details={**req.details, "tenant": agent_tenant},
    )
    return {"recorded": True, "event": ev}
