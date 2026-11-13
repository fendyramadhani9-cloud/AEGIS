"""
Configuration & Environment Management for AEGIS Backend.
Loads server-side configuration safely without leaking secrets into logs or exceptions.
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment from .env file if present
load_dotenv()


def mask_secret(val: Optional[str]) -> str:
    """Masks secret values for safe logging (e.g., 'eyJh...1234')."""
    if not val:
        return "[NOT SET]"
    if len(val) <= 8:
        return "********"
    return f"{val[:4]}...{val[-4:]}"


class Settings:
    """Server-side configuration model for AEGIS backend."""

    def __init__(self):
        self.aegis_env: str = os.getenv("AEGIS_ENV", "development").lower()
        self.api_host: str = os.getenv("API_HOST", "127.0.0.1")
        self.api_port: int = int(os.getenv("API_PORT", "1709"))

        # Agent Authentication Token (for non-SSH telemetry ingestion)
        self.agent_ingest_token: str = os.getenv("AGENT_INGEST_TOKEN", "aegis-agent-dev-secret-token")

        # Supabase Server-Side Access (strictly kept on backend, never exposed to client)
        self.supabase_url: Optional[str] = os.getenv("SUPABASE_URL")
        self.supabase_service_role_key: Optional[str] = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self.supabase_timeout: int = int(os.getenv("SUPABASE_TIMEOUT", "10"))

        # LLM Provider Configuration with Dedicated 4-Key Role Allocation (AEGIS1, AEGIS2, AEGIS3, AEGIS4)
        self.llm_provider: str = os.getenv("AEGIS_LLM_PROVIDER", "mock").lower()
        self.key_aegis1: Optional[str] = os.getenv("AEGIS1") or os.getenv("AEGIS_LLM_API_KEY")
        self.key_aegis2: Optional[str] = os.getenv("AEGIS2") or self.key_aegis1
        self.key_aegis3: Optional[str] = os.getenv("AEGIS3") or self.key_aegis1
        self.key_aegis4: Optional[str] = os.getenv("AEGIS4") or self.key_aegis1

        # Primary key bindings per AI role:
        # - AEGIS1 -> RM Analysis & Incident Investigation Agent
        # - AEGIS2 -> SC Security Posture Analysis Agent
        # - AEGIS3 -> Dedicated Daily & Incident Reporting Agent
        # - AEGIS4 -> Self-Defense, Anti-Tamper & Prompt Injection Guardian Agent
        self.llm_key_rm: Optional[str] = self.key_aegis1
        self.llm_key_sc: Optional[str] = self.key_aegis2
        self.llm_key_reporting: Optional[str] = self.key_aegis3
        self.llm_key_guardian: Optional[str] = self.key_aegis4

        self.llm_api_key: Optional[str] = (
            os.getenv("AEGIS_LLM_API_KEY")
            or self.key_aegis1
            or self.key_aegis2
            or self.key_aegis3
            or self.key_aegis4
        )
        self.llm_model: str = os.getenv("AEGIS_LLM_MODEL", "gemini-3.5-flash-lite")
        self.llm_timeout: int = int(os.getenv("AEGIS_LLM_TIMEOUT", "30"))

        # Configurable CORS Origins
        raw_origins = os.getenv(
            "AEGIS_CORS_ORIGINS",
            "http://localhost:1708,http://127.0.0.1:1708,http://localhost:1709,http://127.0.0.1:1709,http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
        )
        self.cors_origins: list[str] = [o.strip() for o in raw_origins.split(",") if o.strip()]

        # SQLite Local Persistent Storage (for incidents, analyses, and timelines)
        default_sqlite = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "aegis_incidents.db")
        self.sqlite_db_path: str = os.getenv("AEGIS_SQLITE_DB_PATH", default_sqlite)

        # Authentication, RBAC & Hard Multi-Tenant Isolation
        _data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        self.auth_enabled: bool = os.getenv("AEGIS_AUTH_ENABLED", "false").strip().lower() in (
            "1", "true", "yes", "on",
        )
        self.auth_file: str = os.getenv("AEGIS_AUTH_FILE", os.path.join(_data_dir, "auth.json"))
        self.host_tenant_file: str = os.getenv(
            "AEGIS_HOST_TENANT_FILE", os.path.join(_data_dir, "host_tenants.json")
        )
        # Optional signing secret for session tokens. If empty, a random per-process secret is used
        # (all sessions are invalidated on restart).
        self.auth_secret: str = os.getenv("AEGIS_AUTH_SECRET", "")
        self.token_ttl_min: int = max(5, int(os.getenv("AEGIS_TOKEN_TTL_MIN", "480")))
        # Tenant that owns hosts reporting with the legacy global AGENT_INGEST_TOKEN
        self.default_tenant: str = os.getenv("AEGIS_DEFAULT_TENANT", "default").strip().lower() or "default"

        # Database Architecture Mode: 'hybrid' (transitional) or 'cloud_ssot' (canonical Unified Cloud SSoT)
        raw_mode = os.getenv("AEGIS_DATABASE_MODE") or os.getenv("AEGIS_STORAGE_BACKEND", "hybrid")
        raw_mode = raw_mode.lower().strip()
        if raw_mode in ("cloud_ssot", "unified_cloud", "supabase"):
            self.database_mode = "cloud_ssot"
        else:
            self.database_mode = "hybrid"

    @property
    def aegis_database_mode(self) -> str:
        return self.database_mode

    @property
    def is_supabase_configured(self) -> bool:
        """Returns True only if both URL and Service Role Key are provided."""
        return bool(
            self.supabase_url
            and self.supabase_service_role_key
            and not self.supabase_service_role_key.startswith("your_")
        )

    def get_role_key_chain(self, role: str) -> list[tuple[str, str]]:
        """
        Returns ordered (key_slot, api_key) failover chain for a specific AI role:
        - 'rm': AEGIS1 (Primary) -> AEGIS2 (Backup) -> AEGIS3 (Backup)
        - 'sc': AEGIS2 (Primary) -> AEGIS1 (Backup) -> AEGIS3 (Backup)
        - 'reporting': AEGIS3 (Dedicated Primary for Daily/Incident Reports) -> AEGIS2 (Backup) -> AEGIS1 (Backup)
        - 'guardian': AEGIS4 (Dedicated Primary for Self-Defense & AI Guardrail) -> AEGIS1 (Backup) -> AEGIS2 (Backup)
        """
        r = role.lower()
        if r == "guardian":
            raw_chain = [("AEGIS4", self.key_aegis4), ("AEGIS1", self.key_aegis1), ("AEGIS2", self.key_aegis2)]
        elif r == "reporting":
            raw_chain = [("AEGIS3", self.key_aegis3), ("AEGIS2", self.key_aegis2), ("AEGIS1", self.key_aegis1)]
        elif r == "sc":
            raw_chain = [("AEGIS2", self.key_aegis2), ("AEGIS1", self.key_aegis1), ("AEGIS3", self.key_aegis3)]
        else:
            raw_chain = [("AEGIS1", self.key_aegis1), ("AEGIS2", self.key_aegis2), ("AEGIS3", self.key_aegis3)]

        seen = set()
        chain: list[tuple[str, str]] = []
        for slot, k in raw_chain:
            if k and k not in seen:
                seen.add(k)
                chain.append((slot, k))
        return chain

    def ai_roles_summary(self) -> list[dict]:
        """Returns safe, masked status of the 4 dedicated AI roles and their assigned API keys."""
        return [
            {
                "role_id": "rm_agent",
                "role_name": "RM Analysis Agent",
                "key_slot": "AEGIS1",
                "key_masked": mask_secret(self.key_aegis1),
                "configured": bool(self.key_aegis1),
                "model": self.llm_model,
                "purpose": "Runtime Monitor Alert Investigation, Event Correlation & Handoff Synthesis",
                "failover_slots": ["AEGIS2", "AEGIS3"],
            },
            {
                "role_id": "sc_agent",
                "role_name": "SC Analysis Agent",
                "key_slot": "AEGIS2",
                "key_masked": mask_secret(self.key_aegis2),
                "configured": bool(self.key_aegis2),
                "model": self.llm_model,
                "purpose": "Read-Only Security Checker Posture Evaluation & Hardening Guidance",
                "failover_slots": ["AEGIS1", "AEGIS3"],
            },
            {
                "role_id": "reporting_agent",
                "role_name": "Reporting Agent (Daily & Incident)",
                "key_slot": "AEGIS3",
                "key_masked": mask_secret(self.key_aegis3),
                "configured": bool(self.key_aegis3),
                "model": self.llm_model,
                "purpose": "Dedicated Daily Security Briefing & Incident Forensic Report Generation",
                "failover_slots": ["AEGIS2", "AEGIS1"],
            },
            {
                "role_id": "guardian_agent",
                "role_name": "Self-Defense & AI Integrity Guardian",
                "key_slot": "AEGIS4",
                "key_masked": mask_secret(self.key_aegis4),
                "configured": bool(self.key_aegis4),
                "model": self.llm_model,
                "purpose": "Event-Triggered Prompt Injection Firewall, Anti-Tamper Watchdog & Output Consistency Guard",
                "failover_slots": ["AEGIS1", "AEGIS2"],
            },
        ]

    def safe_summary(self) -> dict:
        """Provides a safe configuration summary for debugging without exposing secrets."""
        return {
            "environment": self.aegis_env,
            "api_host": self.api_host,
            "api_port": self.api_port,
            "agent_token_configured": bool(self.agent_ingest_token),
            "agent_token_masked": mask_secret(self.agent_ingest_token),
            "supabase_url": self.supabase_url or "[NOT SET]",
            "supabase_configured": self.is_supabase_configured,
            "supabase_key_masked": mask_secret(self.supabase_service_role_key),
            "llm_provider": self.llm_provider,
            "sqlite_db_path": self.sqlite_db_path,
            "database_mode": self.database_mode,
            "auth_enabled": self.auth_enabled,
            "default_tenant": self.default_tenant,
        }


# Global singleton instance
settings = Settings()
