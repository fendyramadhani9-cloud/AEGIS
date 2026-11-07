"""
Pydantic Request and Response Schemas for AEGIS HTTP API.
Strictly maps to Supabase PostgreSQL migration (001_initial_schema.sql).
"""

from typing import List, Optional, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict, field_validator


# ==========================================
# 1. HEALTH & SYSTEM MODELS
# ==========================================

class HealthResponse(BaseModel):
    status: str
    service: str = "aegis-backend"
    environment: str
    version: str = "0.1.0"


class DatabaseHealthResponse(BaseModel):
    status: str  # "healthy", "degraded", "unconfigured", "error"
    connected: bool
    checked_at: str
    message: str
    latency_ms: Optional[float] = None


class SystemStatusResponse(BaseModel):
    id: int = 1
    collector: str
    rules_engine: str
    ai_provider: str
    ai_provider_note: Optional[str] = None
    checked_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# 2. HOST SCHEMAS
# ==========================================

class HostItem(BaseModel):
    id: str
    hostname: str
    ip_address: Optional[str] = None
    os: str
    agent_version: str
    agent_status: str
    last_data_at: Optional[str] = None
    last_sc_run_at: Optional[str] = None
    is_archived: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PaginatedHostsResponse(BaseModel):
    items: List[HostItem]
    total: int
    limit: int
    offset: int


# ==========================================
# 3. ALERT SCHEMAS
# ==========================================

class AlertItem(BaseModel):
    id: str
    host_id: str
    rule_id: str
    rule_version: str
    title: str
    severity: str
    detected_at: str
    reason: str
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PaginatedAlertsResponse(BaseModel):
    items: List[AlertItem]
    total: int
    limit: int
    offset: int


class AlertEvidenceItem(BaseModel):
    alert_id: str
    event_id: str
    citation_role: str
    created_at: Optional[str] = None
    event_timestamp: Optional[str] = None
    source_id: Optional[str] = None
    event_type: Optional[str] = None
    message: str
    source_ip: Optional[str] = None
    user_name: Optional[str] = None
    host_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class AlertEvidenceResponse(BaseModel):
    alert_id: str
    items: List[AlertEvidenceItem]
    total: int



# ==========================================
# 4. TELEMETRY INGESTION SCHEMAS
# ==========================================

class TelemetryIngestRequest(BaseModel):
    host_id: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    os: str = Field(default="Ubuntu 22.04 LTS", min_length=1, max_length=100)
    agent_version: str = Field(default="0.1.0", min_length=1, max_length=50)
    raw_logs: List[str] = Field(..., min_length=1, max_length=500, description="Batch of raw log lines (max 500 lines)")

    @field_validator("raw_logs")
    @classmethod
    def validate_line_lengths(cls, lines: List[str]) -> List[str]:
        for i, line in enumerate(lines):
            if len(line) > 4096:
                raise ValueError(f"Line at index {i} exceeds maximum allowed length of 4096 characters.")
        return lines


class HeartbeatRequest(BaseModel):
    host_id: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    os: str = Field(default="Ubuntu 24.04 LTS", min_length=1, max_length=100)
    agent_version: str = Field(default="0.1.0", min_length=1, max_length=50)


class HeartbeatResponse(BaseModel):
    status: str = "ok"
    host_id: str
    agent_status: str = "online"
    timestamp: str
    message: str = "Heartbeat registered successfully."


class TelemetryIngestResponse(BaseModel):
    status: str  # "ok", "partial", "rejected"
    host_id: str
    total_received: int
    sanitized_quarantined: int
    malformed_quarantined: int
    parsed_events: int
    inserted_events: int
    duplicates_ignored: int
    alerts_evaluated: int
    message: str


# ==========================================
# 5. ERROR RESPONSE MODEL
# ==========================================

class ErrorResponse(BaseModel):
    error: str
    message: str
    code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
