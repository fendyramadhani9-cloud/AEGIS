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
        self.api_port: int = int(os.getenv("API_PORT", "8000"))

        # Agent Authentication Token (for non-SSH telemetry ingestion)
        self.agent_ingest_token: str = os.getenv("AGENT_INGEST_TOKEN", "aegis-agent-dev-secret-token")

        # Supabase Server-Side Access (strictly kept on backend, never exposed to client)
        self.supabase_url: Optional[str] = os.getenv("SUPABASE_URL")
        self.supabase_service_role_key: Optional[str] = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self.supabase_timeout: int = int(os.getenv("SUPABASE_TIMEOUT", "10"))

        # LLM Provider Configuration
        self.llm_provider: str = os.getenv("AEGIS_LLM_PROVIDER", "mock")
        self.llm_api_key: Optional[str] = os.getenv("AEGIS_LLM_API_KEY")

        # SQLite Local Persistent Storage (for incidents, analyses, and timelines)
        default_sqlite = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "aegis_incidents.db")
        self.sqlite_db_path: str = os.getenv("AEGIS_SQLITE_DB_PATH", default_sqlite)

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
        }


# Global singleton instance
settings = Settings()
