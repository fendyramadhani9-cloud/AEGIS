"""
Database Repository Layer for AEGIS Backend.
Handles all interactions with Supabase PostgreSQL without allowing agents
or untrusted components direct access to database connections.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple, Dict, Any, Set
from datetime import datetime, timezone
import time
import logging
from supabase import create_client, Client
from aegis_backend.config import settings
from aegis_backend.sanitizer import TelemetrySanitizer
from aegis_backend.sqlite_storage import SqliteIncidentStore

logger = logging.getLogger(__name__)


class BaseAegisRepository(ABC):
    """Abstract interface defining required database operations."""

    @abstractmethod
    def check_database_health(self) -> Tuple[bool, str, Optional[float]]:
        """Returns (connected, message, latency_ms)."""
        pass

    @abstractmethod
    def get_system_status(self) -> Optional[Dict[str, Any]]:
        """Retrieves singleton row from system_status."""
        pass

    @abstractmethod
    def list_hosts(self, limit: int = 20, offset: int = 0, status: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
        """Returns paginated hosts and total count."""
        pass

    @abstractmethod
    def get_host_by_id(self, host_id: str) -> Optional[Dict[str, Any]]:
        """Returns single host record or None."""
        pass

    @abstractmethod
    def upsert_host(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """Upserts a host record in hosts table and returns updated record."""
        pass

    @abstractmethod
    def insert_telemetry_events(self, events: List[Dict[str, Any]]) -> Tuple[int, int]:
        """
        Inserts normalized telemetry events. Safely ignores duplicates on event_id.
        Returns (inserted_count, duplicates_count).
        """
        pass

    @abstractmethod
    def list_alerts(
        self,
        limit: int = 20,
        offset: int = 0,
        host_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Returns paginated alerts and total count."""
        pass

    @staticmethod
    def _sanitize_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Recursively sanitizes event details dictionaries before returning via API."""
        if not details or not isinstance(details, dict):
            return {}
        cleaned = {}
        sensitive_keys = {"password", "passwd", "token", "secret", "private_key", "api_key", "authorization"}
        for k, v in details.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in sensitive_keys):
                cleaned[k] = "[REDACTED]"
            elif isinstance(v, str):
                is_safe, _ = TelemetrySanitizer.inspect_line(v)
                cleaned[k] = v if is_safe else "[REDACTED]"
            elif isinstance(v, dict):
                cleaned[k] = BaseAegisRepository._sanitize_details(v)
            elif isinstance(v, list):
                cleaned_list = []
                for item in v:
                    if isinstance(item, dict):
                        cleaned_list.append(BaseAegisRepository._sanitize_details(item))
                    elif isinstance(item, str):
                        is_safe, _ = TelemetrySanitizer.inspect_line(item)
                        cleaned_list.append(item if is_safe else "[REDACTED]")
                    else:
                        cleaned_list.append(item)
                cleaned[k] = cleaned_list
            else:
                cleaned[k] = v
        return cleaned

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Returns single alert record or None."""
        pass

    @abstractmethod
    def get_alert_evidence(self, alert_id: str) -> Optional[List[Dict[str, Any]]]:
        """
        Retrieves supporting telemetry evidence events bound to a specific alert.
        Returns None if alert does not exist (to trigger 404), or list of evidence items.
        """
        pass


    @abstractmethod
    def insert_alerts(
        self,
        alerts: List[Dict[str, Any]],
        alert_evidence: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """
        Atomically saves alerts and their corresponding evidence links.
        Idempotent on alert id and (alert_id, event_id).
        Returns (new_alerts_count, new_evidence_count).
        """
        pass

    @abstractmethod
    def insert_security_check_run(
        self,
        run_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Persists security check run and associated findings."""
        pass

    @abstractmethod
    def list_security_findings(
        self,
        limit: int = 50,
        offset: int = 0,
        host_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Returns paginated security findings matching filters and total count."""
        pass

    @abstractmethod
    def get_security_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Returns single finding by ID or None."""
        pass

    @abstractmethod
    def list_security_runs(
        self,
        limit: int = 20,
        offset: int = 0,
        host_id: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Returns paginated security check execution runs and total count."""
        pass

    @abstractmethod
    def get_security_run_by_id(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Returns run by ID with its summary or None."""
        pass

    @abstractmethod
    def get_security_summary(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns aggregated posture counters (total, pass, fail, warning, etc.)."""
        pass

    @abstractmethod
    def get_host_security_history(self, host_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns recent security runs for a host to enable history comparison."""
        pass

    @abstractmethod
    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Returns single incident by ID or None."""
        pass

    @abstractmethod
    def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        host_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Returns paginated incidents matching filters and total count."""
        pass

    @abstractmethod
    def upsert_incident(
        self,
        incident_data: Dict[str, Any],
        alert_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Creates or updates an incident and links its correlated alerts."""
        pass

    @abstractmethod
    def update_incident_status(
        self,
        incident_id: str,
        status: str,
        note: Optional[str] = None,
        operator: str = "admin",
    ) -> Optional[Dict[str, Any]]:
        """Updates incident status and logs transition in history."""
        pass

    @abstractmethod
    def get_incident_alerts(self, incident_id: str) -> List[Dict[str, Any]]:
        """Returns all alerts linked to an incident."""
        pass

    @abstractmethod
    def save_ai_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Saves an AI analysis result linked to an incident or alert."""
        pass

    @abstractmethod
    def get_latest_ai_analysis(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Returns the most recent AI analysis for an incident or None."""
        pass

    @abstractmethod
    def get_incident_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Returns chronological timeline items for an incident."""
        pass

    @abstractmethod
    def get_incidents_summary(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns aggregated incident lifecycle metrics and risk distribution."""
        pass

    @abstractmethod
    def get_mirror_sync_stats(self) -> Dict[str, Any]:
        """Returns statistics and logs of Cloud-to-SQLite mirror synchronization."""
        pass



class SupabaseRepository(BaseAegisRepository):
    """
    Live Supabase Repository connecting via server-side service_role key.
    Enforces read-only safety for reporting and queries unless explicitly invoked for ingestion.
    """

    def __init__(self, client: Optional[Client] = None):
        self.simulate_db_error = False
        self.sqlite_store = SqliteIncidentStore(settings.sqlite_db_path)
        if client:
            self.client = client
        else:
            if not settings.is_supabase_configured:
                raise ValueError("Cannot initialize SupabaseRepository: Supabase credentials not configured in environment.")
            self.client: Client = create_client(settings.supabase_url, settings.supabase_service_role_key)

    def _execute_mirror(self, entity_type: str, entity_id: str, action: str, mirror_fn) -> None:
        """
        Executes local SQLite mirroring with retry (up to 3 attempts with exponential backoff)
        and deterministic tracking in mirror_sync_log. Prevents silent synchronization drift.
        """
        attempts = 0
        max_retries = 3
        last_err = None
        while attempts < max_retries:
            attempts += 1
            try:
                mirror_fn()
                self.sqlite_store.log_mirror_attempt(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    action=action,
                    status="synced",
                    retry_count=attempts - 1,
                )
                return
            except Exception as e:
                last_err = e
                time.sleep(0.05 * (2 ** (attempts - 1)))

        logger.error(
            "SQLite mirror sync failed for %s:%s after %d retries: %s",
            entity_type, entity_id, max_retries, last_err,
        )
        self.sqlite_store.log_mirror_attempt(
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            status="failed",
            retry_count=max_retries,
            error_message=str(last_err),
        )

    def check_database_health(self) -> Tuple[bool, str, Optional[float]]:
        start_t = time.perf_counter()
        try:
            res = self.client.table("system_status").select("id, checked_at").limit(1).execute()
            latency = (time.perf_counter() - start_t) * 1000.0
            if res.data:
                return True, "Database connection verified successfully.", round(latency, 2)
            return True, "Database responded with empty status.", round(latency, 2)
        except Exception as e:
            return False, f"Supabase query failed: {type(e).__name__}", None

    def get_system_status(self) -> Optional[Dict[str, Any]]:
        res = self.client.table("system_status").select("*").eq("id", 1).limit(1).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]
        return None

    def list_hosts(self, limit: int = 20, offset: int = 0, status: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
        query = self.client.table("hosts").select("*", count="exact")
        if status:
            query = query.eq("agent_status", status)
        query = query.order("last_data_at", desc=True).range(offset, offset + limit - 1)
        res = query.execute()
        total = res.count or len(res.data)
        return res.data, total

    def get_host_by_id(self, host_id: str) -> Optional[Dict[str, Any]]:
        res = self.client.table("hosts").select("*").eq("id", host_id).limit(1).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]
        return None

    def upsert_host(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        res = self.client.table("hosts").upsert(host_data, on_conflict="id").execute()
        if res.data and len(res.data) > 0:
            return res.data[0]
        return host_data

    def insert_telemetry_events(self, events: List[Dict[str, Any]]) -> Tuple[int, int]:
        if not events:
            return 0, 0
        res = self.client.table("telemetry_events").upsert(
            events,
            on_conflict="id",
            ignore_duplicates=True
        ).execute()
        inserted = len(res.data) if res.data else 0
        duplicates = max(0, len(events) - inserted)
        return inserted, duplicates

    def list_alerts(
        self,
        limit: int = 20,
        offset: int = 0,
        host_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        query = self.client.table("alerts").select("*", count="exact")
        if host_id:
            query = query.eq("host_id", host_id)
        if severity:
            query = query.eq("severity", severity)
        query = query.order("detected_at", desc=True).range(offset, offset + limit - 1)
        res = query.execute()
        total = res.count or len(res.data)
        return res.data, total

    @staticmethod
    def _sanitize_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Recursively sanitizes event details dictionaries before returning via API."""
        if not details or not isinstance(details, dict):
            return {}
        cleaned = {}
        sensitive_keys = {"password", "passwd", "token", "secret", "private_key", "api_key", "authorization"}
        for k, v in details.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in sensitive_keys):
                cleaned[k] = "[REDACTED]"
            elif isinstance(v, str):
                is_safe, _ = TelemetrySanitizer.inspect_line(v)
                cleaned[k] = v if is_safe else "[REDACTED]"
            elif isinstance(v, dict):
                cleaned[k] = BaseAegisRepository._sanitize_details(v)
            elif isinstance(v, list):
                cleaned_list = []
                for item in v:
                    if isinstance(item, dict):
                        cleaned_list.append(BaseAegisRepository._sanitize_details(item))
                    elif isinstance(item, str):
                        is_safe, _ = TelemetrySanitizer.inspect_line(item)
                        cleaned_list.append(item if is_safe else "[REDACTED]")
                    else:
                        cleaned_list.append(item)
                cleaned[k] = cleaned_list
            else:
                cleaned[k] = v
        return cleaned

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        res = self.client.table("alerts").select("*").eq("id", alert_id).limit(1).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]
        return None

    def get_alert_evidence(self, alert_id: str) -> Optional[List[Dict[str, Any]]]:
        # 1. Fetch parent alert to verify existence and get host_id
        alert = self.get_alert_by_id(alert_id)
        if not alert:
            return None  # Triggers 404

        expected_host_id = alert.get("host_id")

        # 2. Query alert_evidence with joined telemetry_events
        res = self.client.table("alert_evidence").select(
            "alert_id, event_id, citation_role, created_at, telemetry_events(id, host_id, source_id, event_type, event_timestamp, message, source_ip, user_name, details)"
        ).eq("alert_id", alert_id).order("created_at").execute()

        rows = res.data or []
        items = []

        # Fallback if embedded relation is not returned by PostgREST
        missing_event_ids = [r["event_id"] for r in rows if not r.get("telemetry_events")]
        events_by_id = {}
        if missing_event_ids:
            try:
                ev_res = self.client.table("telemetry_events").select("*").in_("id", missing_event_ids).execute()
                for ev in (ev_res.data or []):
                    events_by_id[ev["id"]] = ev
            except Exception as e:
                logger.warning(f"Failed fallback query for telemetry_events: {e}")

        for r in rows:
            te = r.get("telemetry_events") or events_by_id.get(r["event_id"]) or {}
            event_host_id = te.get("host_id")

            # Validate host isolation: ignore cross-host mismatch
            if event_host_id and expected_host_id and event_host_id != expected_host_id:
                logger.warning(f"Cross-host evidence excluded: alert host {expected_host_id} != event host {event_host_id}")
                continue

            raw_msg = te.get("message") or ""
            is_safe, _ = TelemetrySanitizer.inspect_line(raw_msg)
            safe_msg = raw_msg if is_safe else "[REDACTED - SENSITIVE CREDENTIAL MASKED]"

            items.append({
                "alert_id": r.get("alert_id"),
                "event_id": r.get("event_id"),
                "citation_role": r.get("citation_role", "supporting"),
                "created_at": r.get("created_at"),
                "host_id": event_host_id or expected_host_id,
                "source_id": te.get("source_id", "ssh-auth"),
                "event_type": te.get("event_type", "auth"),
                "event_timestamp": te.get("event_timestamp") or r.get("created_at"),
                "message": safe_msg,
                "source_ip": te.get("source_ip"),
                "user_name": te.get("user_name"),
                "details": self._sanitize_details(te.get("details")),
            })
        return items

    @staticmethod
    def _extract_postgrest_error_code(e: Exception) -> Optional[str]:
        """
        Extracts structured PostgREST or PostgreSQL error codes from exception objects.
        Returns error code in uppercase (e.g. 'PGRST202', '42883', '23514', 'P0001') or None.
        """
        # 1. Direct attribute 'code'
        if hasattr(e, "code") and getattr(e, "code"):
            return str(getattr(e, "code")).strip().upper()
        # 2. Inside args dictionary
        if hasattr(e, "args") and e.args:
            first = e.args[0]
            if isinstance(first, dict):
                if "code" in first:
                    return str(first["code"]).strip().upper()
                if "error" in first and isinstance(first["error"], dict) and "code" in first["error"]:
                    return str(first["error"]["code"]).strip().upper()
        # 3. Regex match on structured error code pattern (PGRSTxxx or standard 5-char SQLSTATE)
        import re
        match = re.search(r"\b(PGRST\d{3}|[0-9A-Z]{5})\b", str(e))
        if match:
            return match.group(1).upper()
        return None

    def insert_alerts(
        self,
        alerts: List[Dict[str, Any]],
        alert_evidence: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        if not alerts:
            return 0, 0

        # Try atomic RPC first if available (Migration 002)
        try:
            res = self.client.rpc(
                "fn_ingest_alert_with_evidence",
                {"p_alerts": alerts, "p_evidence": alert_evidence or []}
            ).execute()
            if res.data and isinstance(res.data, dict) and res.data.get("success"):
                return res.data.get("inserted_alerts", 0), res.data.get("inserted_evidence", 0)
        except Exception as e:
            error_code = self._extract_postgrest_error_code(e)
            # Strict Fallback Audit:
            # ONLY fall back to sequential upsert if the RPC function itself is missing/not deployed yet:
            # - PGRST202: PostgREST schema cache missing function
            # - 42883: PostgreSQL SQLSTATE undefined_function
            is_function_missing = error_code in ("PGRST202", "42883")
            if is_function_missing:
                logger.warning(
                    f"Atomic RPC 'fn_ingest_alert_with_evidence' not available on database (code: {error_code}): {e}. "
                    "Temporary sequential fallback active only until migration 002 is applied."
                )
            else:
                # INTEGRITY ERROR, VALIDATION ERROR, PERMISSION ERROR, OR TRANSACTION ROLLBACK:
                # DO NOT FALL BACK! Re-raise immediately to preserve atomicity and prevent orphaned alerts!
                logger.error(
                    f"Atomic alert ingestion rejected by database constraints or integrity checks (code: {error_code}): {e}. "
                    "Sequential fallback BLOCKED to preserve atomicity and prevent orphaned alerts."
                )
                raise



        # 1. Insert alerts (idempotent on id)
        res_alerts = self.client.table("alerts").upsert(
            alerts,
            on_conflict="id",
            ignore_duplicates=True,
        ).execute()
        inserted_alerts = len(res_alerts.data) if res_alerts.data else 0

        # 2. Insert alert_evidence (idempotent on alert_id,event_id)
        inserted_evidence = 0
        if alert_evidence:
            res_ev = self.client.table("alert_evidence").upsert(
                alert_evidence,
                on_conflict="alert_id,event_id",
                ignore_duplicates=True,
            ).execute()
            inserted_evidence = len(res_ev.data) if res_ev.data else 0

        return inserted_alerts, inserted_evidence

    def insert_security_check_run(
        self,
        run_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Persists security check execution runs and findings.
        Attempts Supabase Cloud table write first. If migration 003 is not deployed
        (PGRST205 relation does not exist) or cloud is unreachable, falls back to
        the persistent, disk-backed SQLite store.
        If both fail, raises RuntimeError to prevent silent in-memory data loss.
        """
        try:
            self.client.table("security_check_runs").upsert(
                run_data,
                on_conflict="id",
            ).execute()

            if findings:
                self.client.table("security_findings").upsert(
                    findings,
                    on_conflict="run_id,check_id",
                ).execute()

            # Update host last_sc_run_at
            if run_data.get("completed_at"):
                self.client.table("hosts").update({
                    "last_sc_run_at": run_data["completed_at"]
                }).eq("id", run_data["host_id"]).execute()

            # Mirror to local SQLite store with retry and audit logging
            self._execute_mirror(
                "security_check_run",
                run_data["id"],
                "upsert",
                lambda: self.sqlite_store.upsert_security_check_run(run_data, findings),
            )

            return run_data
        except Exception as e:
            if settings.database_mode == "cloud_ssot":
                logger.error("FATAL [Cloud SSoT]: Security check run write failed on Supabase Cloud: %s", e)
                raise RuntimeError(f"Cloud SSoT write failed for security check run: {e}") from e
            err_code = self._extract_postgrest_error_code(e)
            logger.warning(
                "Supabase security check run write unavailable (code: %s: %s). "
                "Persisting to disk-backed SQLite storage.",
                err_code,
                e,
            )
            try:
                return self.sqlite_store.upsert_security_check_run(run_data, findings)
            except Exception as sqlite_err:
                logger.critical("FATAL: Both Supabase and SQLite storage failed for security check run: %s", sqlite_err)
                raise RuntimeError(f"Database write failed on both Supabase and SQLite: {sqlite_err}") from sqlite_err

    def list_security_findings(
        self,
        limit: int = 50,
        offset: int = 0,
        host_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        try:
            query = self.client.table("security_findings").select("*", count="exact")
            if host_id:
                query = query.eq("host_id", host_id)
            if category:
                query = query.eq("category", category)
            if severity:
                query = query.eq("severity", severity)
            if status:
                query = query.eq("status", status)
            if search:
                query = query.ilike("check_name", f"%{search}%")
            query = query.order("checked_at", desc=True).range(offset, offset + limit - 1)
            res = query.execute()
            total = res.count if res.count is not None else len(res.data or [])
            return res.data or [], total
        except Exception as e:
            if settings.database_mode == "cloud_ssot":
                logger.error("FATAL [Cloud SSoT]: Failed to query security findings from Supabase Cloud: %s", e)
                raise RuntimeError(f"Cloud SSoT query failed for security findings: {e}") from e
            err_code = self._extract_postgrest_error_code(e)
            logger.debug("Supabase security_findings unavailable (%s). Reading from persistent SQLite store.", err_code)
            return self.sqlite_store.list_security_findings(
                limit=limit,
                offset=offset,
                host_id=host_id,
                category=category,
                severity=severity,
                status=status,
                search=search,
            )

    def get_security_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.client.table("security_findings").select("*").eq("id", finding_id).limit(1).execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
            if settings.database_mode == "cloud_ssot":
                return None
            return self.sqlite_store.get_security_finding_by_id(finding_id)
        except Exception as e:
            if settings.database_mode == "cloud_ssot":
                logger.error("FATAL [Cloud SSoT]: Failed to fetch security finding %s: %s", finding_id, e)
                raise RuntimeError(f"Cloud SSoT lookup failed for security finding: {e}") from e
            err_code = self._extract_postgrest_error_code(e)
            logger.debug("Supabase finding lookup unavailable (%s). Reading from persistent SQLite store.", err_code)
            return self.sqlite_store.get_security_finding_by_id(finding_id)

    def list_security_runs(
        self,
        limit: int = 20,
        offset: int = 0,
        host_id: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        try:
            query = self.client.table("security_check_runs").select("*", count="exact")
            if host_id:
                query = query.eq("host_id", host_id)
            query = query.order("started_at", desc=True).range(offset, offset + limit - 1)
            res = query.execute()
            total = res.count if res.count is not None else len(res.data or [])
            return res.data or [], total
        except Exception as e:
            if settings.database_mode == "cloud_ssot":
                logger.error("FATAL [Cloud SSoT]: Failed to list security runs from Supabase: %s", e)
                raise RuntimeError(f"Cloud SSoT query failed for security runs: {e}") from e
            err_code = self._extract_postgrest_error_code(e)
            logger.debug("Supabase security_check_runs unavailable (%s). Reading from persistent SQLite store.", err_code)
            return self.sqlite_store.list_security_runs(limit=limit, offset=offset, host_id=host_id)

    def get_security_run_by_id(self, run_id: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.client.table("security_check_runs").select("*").eq("id", run_id).limit(1).execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
            if settings.database_mode == "cloud_ssot":
                return None
            return self.sqlite_store.get_security_run_by_id(run_id)
        except Exception as e:
            if settings.database_mode == "cloud_ssot":
                logger.error("FATAL [Cloud SSoT]: Failed to fetch security run %s: %s", run_id, e)
                raise RuntimeError(f"Cloud SSoT lookup failed for security run: {e}") from e
            err_code = self._extract_postgrest_error_code(e)
            logger.debug("Supabase security run lookup unavailable (%s). Reading from persistent SQLite store.", err_code)
            return self.sqlite_store.get_security_run_by_id(run_id)

    def get_security_summary(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        findings, _ = self.list_security_findings(limit=1000, offset=0, host_id=host_id)
        _, total_hosts = self.list_hosts(limit=100)
        
        last_run_time = None
        runs, _ = self.list_security_runs(limit=1, offset=0, host_id=host_id)
        if runs:
            last_run_time = runs[0].get("completed_at") or runs[0].get("started_at")

        return {
            "total_checks": len(findings),
            "passed": sum(1 for f in findings if f.get("status") == "pass"),
            "failed": sum(1 for f in findings if f.get("status") == "fail"),
            "warning": sum(1 for f in findings if f.get("status") == "warning"),
            "not_applicable": sum(1 for f in findings if f.get("status") == "not_applicable"),
            "error": sum(1 for f in findings if f.get("status") == "error"),
            "total_hosts": total_hosts,
            "last_checked_at": last_run_time,
            "critical_fails": sum(1 for f in findings if f.get("status") == "fail" and f.get("severity") == "critical"),
            "high_fails": sum(1 for f in findings if f.get("status") == "fail" and f.get("severity") == "high"),
            "medium_fails": sum(1 for f in findings if f.get("status") == "fail" and f.get("severity") == "medium"),
            "low_fails": sum(1 for f in findings if f.get("status") == "fail" and f.get("severity") == "low"),
        }

    def get_host_security_history(self, host_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        runs, _ = self.list_security_runs(limit=limit, offset=0, host_id=host_id)
        return runs

    # ==========================================
    # INCIDENT INVESTIGATION & AI ANALYSIS (SQLITE PERSISTENT)
    # ==========================================

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get incident.")
        if settings.database_mode == "cloud_ssot":
            try:
                res = self.client.table("incidents").select("*").eq("id", incident_id).limit(1).execute()
                if not res.data or len(res.data) == 0:
                    return None
                inc = res.data[0]
                rel_res = self.client.table("incident_alerts").select("alert_id").eq("incident_id", incident_id).execute()
                inc["alert_ids"] = [r["alert_id"] for r in (rel_res.data or [])]
                if not inc["alert_ids"] and inc.get("primary_alert_id"):
                    inc["alert_ids"] = [inc["primary_alert_id"]]
                inc["alert_count"] = len(inc["alert_ids"])
                rf_res = self.client.table("incident_risk_factors").select("*").eq("incident_id", incident_id).execute()
                inc["risk_factors"] = rf_res.data or []
                return inc
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to fetch incident %s: %s", incident_id, e)
                raise RuntimeError(f"Cloud SSoT incident lookup failed: {e}") from e
        return self.sqlite_store.get_incident_by_id(incident_id)

    def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        host_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on list incidents.")
        if settings.database_mode == "cloud_ssot":
            try:
                query = self.client.table("incidents").select("*", count="exact")
                if host_id:
                    query = query.eq("host_id", host_id)
                if status:
                    query = query.eq("status", status)
                if severity:
                    query = query.eq("risk_level", severity)
                query = query.order("created_at", desc=True).range(offset, offset + limit - 1)
                res = query.execute()
                items = res.data or []
                total = res.count if res.count is not None else len(items)
                if search:
                    s_low = search.lower()
                    items = [
                        i for i in items
                        if s_low in i.get("id", "").lower()
                        or s_low in i.get("title", "").lower()
                        or s_low in (i.get("attack_scenario") or "").lower()
                    ]
                return items, total
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to list incidents: %s", e)
                raise RuntimeError(f"Cloud SSoT list incidents failed: {e}") from e

        items, total = self.sqlite_store.list_incidents(
            limit=limit,
            offset=offset,
            status=status,
            risk_level=severity,
            host_id=host_id,
        )
        if search:
            s_low = search.lower()
            items = [
                i for i in items
                if s_low in i.get("id", "").lower()
                or s_low in i.get("title", "").lower()
                or s_low in i.get("attack_scenario", "").lower()
            ]
        return items, total

    def upsert_incident(
        self,
        incident_data: Dict[str, Any],
        alert_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on upsert incident.")
        if settings.database_mode == "cloud_ssot":
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                inc_record = {
                    "id": incident_data["id"],
                    "host_id": incident_data.get("host_id") or "host-fenn-ubuntu",
                    "title": incident_data.get("title", "Untitled Incident"),
                    "severity": incident_data.get("severity", "medium"),
                    "status": incident_data.get("status", "new"),
                    "risk_level": incident_data.get("risk_level", "medium"),
                    "risk_score": int(incident_data.get("risk_score", 50)),
                    "alert_count": int(incident_data.get("alert_count", len(alert_ids or []))),
                    "primary_alert_id": incident_data.get("primary_alert_id") or ((alert_ids or [])[0] if alert_ids else None),
                    "source_ip": incident_data.get("source_ip"),
                    "target_user": incident_data.get("target_user"),
                    "attack_scenario": incident_data.get("attack_scenario"),
                    "correlation_reason": incident_data.get("correlation_reason"),
                    "provenance": incident_data.get("provenance", "synthetic_benchmark"),
                    "source_category": incident_data.get("source_category", "unknown"),
                    "source_label": incident_data.get("source_label"),
                    "threat_actor_context": incident_data.get("threat_actor_context"),
                    "first_seen_at": incident_data.get("first_seen_at") or now_iso,
                    "last_seen_at": incident_data.get("last_seen_at") or now_iso,
                    "created_at": incident_data.get("created_at") or now_iso,
                    "updated_at": now_iso,
                }
                if "assigned_to" in incident_data:
                    inc_record["assigned_to"] = incident_data["assigned_to"]

                self.client.table("incidents").upsert(inc_record, on_conflict="id").execute()

                all_alert_ids = list(dict.fromkeys((alert_ids or []) + ([inc_record["primary_alert_id"]] if inc_record.get("primary_alert_id") else [])))
                if all_alert_ids:
                    links = [
                        {
                            "id": f"REL-{incident_data['id']}-{aid}",
                            "incident_id": incident_data["id"],
                            "alert_id": aid,
                            "created_at": now_iso,
                        }
                        for aid in all_alert_ids
                    ]
                    self.client.table("incident_alerts").upsert(links, on_conflict="incident_id,alert_id").execute()

                risk_factors = incident_data.get("risk_factors") or []
                if risk_factors:
                    rf_rows = []
                    for rf in risk_factors:
                        fid = rf.get("factor_id") or rf.get("name") or "factor"
                        rf_rows.append({
                            "id": f"RF-{incident_data['id']}-{fid}",
                            "incident_id": incident_data["id"],
                            "factor_id": fid,
                            "factor_name": rf.get("factor_name") or rf.get("name", fid),
                            "points": int(rf.get("points", 0)),
                            "category": rf.get("category", "base"),
                            "description": rf.get("description", ""),
                            "supporting_evidence_ids": rf.get("supporting_evidence_ids", []),
                            "created_at": now_iso,
                        })
                    self.client.table("incident_risk_factors").upsert(rf_rows, on_conflict="incident_id,factor_id").execute()

                self._execute_mirror(
                    "incident",
                    incident_data["id"],
                    "upsert",
                    lambda: self.sqlite_store.upsert_incident(incident_data, alert_ids, risk_factors),
                )

                return incident_data
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to upsert incident %s: %s", incident_data.get("id"), e)
                raise RuntimeError(f"Cloud SSoT upsert incident failed: {e}") from e

        return self.sqlite_store.upsert_incident(
            incident_data=incident_data,
            alert_ids=alert_ids,
            risk_factors=incident_data.get("risk_factors", []),
        )

    def update_incident_status(
        self,
        incident_id: str,
        status: str,
        note: Optional[str] = None,
        operator: str = "admin",
    ) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on update incident status.")
        if settings.database_mode == "cloud_ssot":
            try:
                curr = self.get_incident_by_id(incident_id)
                if not curr:
                    return None
                old_st = curr.get("status", "new")
                now_iso = datetime.now(timezone.utc).isoformat()
                self.client.table("incidents").update({"status": status, "updated_at": now_iso}).eq("id", incident_id).execute()
                hist_row = {
                    "id": f"SH-{int(time.time()*1000)}",
                    "incident_id": incident_id,
                    "old_status": old_st,
                    "new_status": status,
                    "note": note,
                    "operator": operator,
                    "transitioned_at": now_iso,
                }
                self.client.table("incident_status_history").insert(hist_row).execute()
                tl_row = {
                    "id": f"TL-ST-{int(time.time()*1000)}",
                    "incident_id": incident_id,
                    "timestamp": now_iso,
                    "kind": "status_change",
                    "title": f"Status changed to {status}",
                    "description": note or f"Status transitioned from {old_st} to {status} by {operator}",
                    "severity": curr.get("severity", "medium"),
                    "metadata": {"operator": operator, "old_status": old_st, "new_status": status},
                    "created_at": now_iso,
                }
                self.client.table("incident_timeline").insert(tl_row).execute()
                self._execute_mirror(
                    "incident_status",
                    incident_id,
                    "update_status",
                    lambda: self.sqlite_store.update_incident_status(incident_id, status, note, operator),
                )
                return self.get_incident_by_id(incident_id)
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to update status: %s", e)
                raise RuntimeError(f"Cloud SSoT status update failed: {e}") from e

        return self.sqlite_store.update_incident_status(
            incident_id=incident_id,
            status=status,
            note=note,
            operator=operator,
        )

    def get_incident_alerts(self, incident_id: str) -> List[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get incident alerts.")
        if settings.database_mode == "cloud_ssot":
            try:
                res = self.client.table("incident_alerts").select("alert_id").eq("incident_id", incident_id).execute()
                alert_ids = [r["alert_id"] for r in (res.data or [])]
                if not alert_ids:
                    inc = self.get_incident_by_id(incident_id)
                    if inc and inc.get("primary_alert_id"):
                        alert_ids = [inc["primary_alert_id"]]
                out = []
                for aid in alert_ids:
                    a = self.get_alert_by_id(aid)
                    if a:
                        out.append(a)
                return out
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to get incident alerts: %s", e)
                raise RuntimeError(f"Cloud SSoT get incident alerts failed: {e}") from e

        alert_ids = self.sqlite_store.get_incident_alerts(incident_id)
        if not alert_ids:
            inc = self.sqlite_store.get_incident_by_id(incident_id)
            if inc and inc.get("primary_alert_id"):
                alert_ids = [inc["primary_alert_id"]]

        out = []
        for aid in alert_ids:
            a = self.get_alert_by_id(aid)
            if a:
                out.append(a)
        return out

    def save_ai_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on save ai analysis.")
        if settings.database_mode == "cloud_ssot":
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                row = {
                    "id": analysis_data["id"],
                    "incident_id": analysis_data.get("incident_id"),
                    "alert_id": analysis_data.get("alert_id"),
                    "host_id": analysis_data.get("host_id") or "host-fenn-ubuntu",
                    "analysis_status": analysis_data.get("analysis_status", "completed"),
                    "threat_classification": analysis_data.get("threat_classification", "Unclassified"),
                    "executive_summary": analysis_data.get("executive_summary", ""),
                    "attack_scenario": analysis_data.get("attack_scenario", ""),
                    "observed_behaviors": analysis_data.get("observed_behaviors", []),
                    "timeline": analysis_data.get("timeline", []),
                    "risk_level": analysis_data.get("risk_level", "medium"),
                    "risk_score": int(analysis_data.get("risk_score", 50)),
                    "confidence_level": analysis_data.get("confidence_level", "medium"),
                    "confidence_reason": analysis_data.get("confidence_reason", ""),
                    "facts": analysis_data.get("facts", []),
                    "inferences": analysis_data.get("inferences", []),
                    "hypotheses": analysis_data.get("hypotheses", []),
                    "unknowns": analysis_data.get("unknowns", []),
                    "unknown_items": analysis_data.get("unknown_items", []),
                    "supporting_evidence": analysis_data.get("supporting_evidence", []),
                    "contradicting_evidence": analysis_data.get("contradicting_evidence", []),
                    "impact_assessment": analysis_data.get("impact_assessment", ""),
                    "recommended_actions": analysis_data.get("recommended_actions", []),
                    "containment_recommendations": analysis_data.get("containment_recommendations", []),
                    "investigation_notes": analysis_data.get("investigation_notes"),
                    "provider": analysis_data.get("provider", "gemini"),
                    "model": analysis_data.get("model", "gemini-2.5-flash"),
                    "created_at": analysis_data.get("created_at") or now_iso,
                    "completed_at": analysis_data.get("completed_at") or now_iso,
                }
                self.client.table("ai_analyses").upsert(row, on_conflict="id").execute()
                self._execute_mirror(
                    "ai_analysis",
                    analysis_data["id"],
                    "save",
                    lambda: self.sqlite_store.save_ai_analysis(analysis_data),
                )
                return analysis_data
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to save AI analysis: %s", e)
                raise RuntimeError(f"Cloud SSoT save AI analysis failed: {e}") from e

        return self.sqlite_store.save_ai_analysis(analysis_data)

    def get_latest_ai_analysis(self, incident_id: str) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get latest ai analysis.")
        if settings.database_mode == "cloud_ssot":
            try:
                res = self.client.table("ai_analyses").select("*").eq("incident_id", incident_id).order("created_at", desc=True).limit(1).execute()
                if res.data and len(res.data) > 0:
                    return res.data[0]
                return None
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to get latest AI analysis: %s", e)
                raise RuntimeError(f"Cloud SSoT get latest AI analysis failed: {e}") from e

        return self.sqlite_store.get_latest_ai_analysis(incident_id)

    def get_incident_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get incident timeline.")
        if settings.database_mode == "cloud_ssot":
            try:
                res = self.client.table("incident_timeline").select("*").eq("incident_id", incident_id).order("timestamp", desc=False).execute()
                items = res.data or []
                alerts = self.get_incident_alerts(incident_id)
                for a in alerts:
                    aid = a.get("id")
                    if aid:
                        evs = self.get_alert_evidence(aid) or []
                        for ev in evs:
                            items.append({
                                "id": f"TL-EVT-{ev.get('event_id') or ev.get('id')}",
                                "incident_id": incident_id,
                                "timestamp": ev.get("event_timestamp") or ev.get("created_at") or datetime.now(timezone.utc).isoformat(),
                                "kind": "event",
                                "title": f"Telemetry: {ev.get('source_id') or 'auth'}",
                                "description": ev.get("message", ""),
                                "severity": a.get("severity"),
                                "metadata": {
                                    "source_ip": ev.get("source_ip"),
                                    "user_name": ev.get("user_name"),
                                    "alert_id": aid,
                                },
                            })
                items.sort(key=lambda x: x.get("timestamp", ""))
                return items
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to get incident timeline: %s", e)
                raise RuntimeError(f"Cloud SSoT get timeline failed: {e}") from e

        items = self.sqlite_store.get_incident_timeline(incident_id)
        alerts = self.get_incident_alerts(incident_id)
        for a in alerts:
            aid = a.get("id")
            if aid:
                evs = self.get_alert_evidence(aid) or []
                for ev in evs:
                    items.append({
                        "id": f"TL-EVT-{ev.get('event_id') or ev.get('id')}",
                        "incident_id": incident_id,
                        "timestamp": ev.get("event_timestamp") or ev.get("created_at") or datetime.now(timezone.utc).isoformat(),
                        "kind": "event",
                        "title": f"Telemetry: {ev.get('source_id') or 'auth'}",
                        "description": ev.get("message", ""),
                        "severity": a.get("severity"),
                        "metadata": {
                            "source_ip": ev.get("source_ip"),
                            "user_name": ev.get("user_name"),
                            "alert_id": aid,
                        },
                    })
        items.sort(key=lambda x: x.get("timestamp", ""))
        return items

    def get_incidents_summary(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get incidents summary.")
        if settings.database_mode == "cloud_ssot":
            try:
                query = self.client.table("incidents").select("id, status, risk_level, risk_score, created_at")
                if host_id:
                    query = query.eq("host_id", host_id)
                res = query.execute()
                incs = res.data or []
                total = len(incs)
                open_c = sum(1 for i in incs if i.get("status") in ("new", "investigating", "confirmed", "open"))
                investigating = sum(1 for i in incs if i.get("status") == "investigating")
                contained = sum(1 for i in incs if i.get("status") == "contained")
                resolved = sum(1 for i in incs if i.get("status") in ("resolved", "closed"))
                fp = sum(1 for i in incs if i.get("status") == "false_positive")
                crit = sum(1 for i in incs if i.get("risk_level") == "critical")
                high = sum(1 for i in incs if i.get("risk_level") == "high")
                med = sum(1 for i in incs if i.get("risk_level") == "medium")
                low = sum(1 for i in incs if i.get("risk_level") == "low")
                avg_risk = round(sum(i.get("risk_score", 50) for i in incs) / max(total, 1), 1)

                return {
                    "total_incidents": total,
                    "open_incidents": open_c,
                    "investigating_incidents": investigating,
                    "contained_incidents": contained,
                    "resolved_incidents": resolved,
                    "false_positives": fp,
                    "critical_incidents": crit,
                    "high_incidents": high,
                    "medium_incidents": med,
                    "low_incidents": low,
                    "avg_risk_score": avg_risk,
                }
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to get incidents summary: %s", e)
                raise RuntimeError(f"Cloud SSoT summary failed: {e}") from e

        return self.sqlite_store.get_incident_summary()

    def get_mirror_sync_stats(self) -> Dict[str, Any]:
        """Returns statistics and logs of Cloud-to-SQLite mirror synchronization."""
        return self.sqlite_store.get_mirror_sync_stats()



class MockAegisRepository(BaseAegisRepository):
    """
    In-memory Mock Repository for offline testing and local development.
    Guarantees that tests run completely offline without needing network or credentials.
    """

    def __init__(self, simulate_db_error: bool = False):
        self.simulate_db_error = simulate_db_error
        self.sqlite_store = SqliteIncidentStore(settings.sqlite_db_path)
        self.security_runs: List[Dict[str, Any]] = []
        self.security_findings: List[Dict[str, Any]] = []
        self.system_status = {
            "id": 1,
            "collector": "ok",
            "rules_engine": "ok",
            "ai_provider": "ok",
            "ai_provider_note": "Mock provider active offline.",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        self.hosts: List[Dict[str, Any]] = [
            {
                "id": "srv-prod-auth",
                "hostname": "core-auth-srv01",
                "ip_address": "10.0.0.15",
                "os": "Ubuntu 22.04 LTS",
                "agent_version": "0.1.0",
                "agent_status": "online",
                "last_data_at": datetime.now(timezone.utc).isoformat(),
                "last_sc_run_at": datetime.now(timezone.utc).isoformat(),
                "is_archived": False,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            {
                "id": "srv-db-01",
                "hostname": "primary-db01",
                "ip_address": "10.0.0.20",
                "os": "Ubuntu 22.04 LTS",
                "agent_version": "0.1.0",
                "agent_status": "offline",
                "last_data_at": None,
                "last_sc_run_at": None,
                "is_archived": False,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        ]
        self.alerts: List[Dict[str, Any]] = [
            {
                "id": "ALT-001",
                "host_id": "srv-prod-auth",
                "rule_id": "RULE-AUTH-003",
                "rule_version": "1.0",
                "title": "Multiple Failed Logins Followed by Success",
                "severity": "high",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "reason": "1 authentication failure event observed followed by success.",
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            {
                "id": "ALT-002",
                "host_id": "srv-prod-auth",
                "rule_id": "RULE-SUSP-EXEC",
                "rule_version": "1.0",
                "title": "Suspicious Process Execution",
                "severity": "medium",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "reason": "Execution of curl downloading shell script.",
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        ]
        self.telemetry_events: List[Dict[str, Any]] = []
        self.event_ids: Set[str] = set()
        self.alert_evidence: List[Dict[str, Any]] = []

    def check_database_health(self) -> Tuple[bool, str, Optional[float]]:
        if self.simulate_db_error:
            return False, "Simulated database connection failure.", None
        return True, "Mock database healthy (in-memory mode).", 1.25

    def get_system_status(self) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database unavailable.")
        return dict(self.system_status)

    def list_hosts(self, limit: int = 20, offset: int = 0, status: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
        if self.simulate_db_error:
            raise RuntimeError("Database query error.")
        filtered = [h for h in self.hosts if not status or h["agent_status"] == status]
        return filtered[offset : offset + limit], len(filtered)

    def get_host_by_id(self, host_id: str) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database query error.")
        for h in self.hosts:
            if h["id"] == host_id:
                return dict(h)
        return None

    def upsert_host(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        if self.simulate_db_error:
            raise RuntimeError("Database write error.")
        now_iso = datetime.now(timezone.utc).isoformat()
        for idx, h in enumerate(self.hosts):
            if h["id"] == host_data["id"]:
                merged = {**h, **host_data, "updated_at": now_iso}
                self.hosts[idx] = merged
                return merged
        new_host = {
            "is_archived": False,
            "created_at": now_iso,
            "updated_at": now_iso,
            **host_data,
        }
        self.hosts.append(new_host)
        return new_host

    def insert_telemetry_events(self, events: List[Dict[str, Any]]) -> Tuple[int, int]:
        if self.simulate_db_error:
            raise RuntimeError("Database write error.")
        inserted = 0
        duplicates = 0
        for ev in events:
            ev_id = ev["id"]
            if ev_id in self.event_ids:
                duplicates += 1
            else:
                self.event_ids.add(ev_id)
                self.telemetry_events.append(dict(ev))
                inserted += 1
        return inserted, duplicates

    def list_alerts(
        self,
        limit: int = 20,
        offset: int = 0,
        host_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        if self.simulate_db_error:
            raise RuntimeError("Database query error.")
        filtered = [
            a
            for a in self.alerts
            if (not host_id or a["host_id"] == host_id) and (not severity or a["severity"] == severity)
        ]
        return filtered[offset : offset + limit], len(filtered)

    @staticmethod
    def _sanitize_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Recursively sanitizes event details dictionaries before returning via API."""
        if not details or not isinstance(details, dict):
            return {}
        cleaned = {}
        sensitive_keys = {"password", "passwd", "token", "secret", "private_key", "api_key", "authorization"}
        for k, v in details.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in sensitive_keys):
                cleaned[k] = "[REDACTED]"
            elif isinstance(v, str):
                is_safe, _ = TelemetrySanitizer.inspect_line(v)
                cleaned[k] = v if is_safe else "[REDACTED]"
            elif isinstance(v, dict):
                cleaned[k] = BaseAegisRepository._sanitize_details(v)
            elif isinstance(v, list):
                cleaned_list = []
                for item in v:
                    if isinstance(item, dict):
                        cleaned_list.append(BaseAegisRepository._sanitize_details(item))
                    elif isinstance(item, str):
                        is_safe, _ = TelemetrySanitizer.inspect_line(item)
                        cleaned_list.append(item if is_safe else "[REDACTED]")
                    else:
                        cleaned_list.append(item)
                cleaned[k] = cleaned_list
            else:
                cleaned[k] = v
        return cleaned

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database query error.")
        for a in self.alerts:
            if a["id"] == alert_id:
                return dict(a)
        return None

    def get_alert_evidence(self, alert_id: str) -> Optional[List[Dict[str, Any]]]:
        if self.simulate_db_error:
            raise RuntimeError("Database query error.")
        alert = self.get_alert_by_id(alert_id)
        if not alert:
            return None

        expected_host_id = alert.get("host_id")
        if not hasattr(self, "alert_evidence"):
            self.alert_evidence = []

        matching_ev = [e for e in self.alert_evidence if e["alert_id"] == alert_id]
        events_map = {e["id"]: e for e in self.telemetry_events}

        items = []
        for me in matching_ev:
            te = events_map.get(me["event_id"], {})
            event_host_id = te.get("host_id")
            if event_host_id and expected_host_id and event_host_id != expected_host_id:
                continue
            raw_msg = te.get("message") or ""
            is_safe, _ = TelemetrySanitizer.inspect_line(raw_msg)
            safe_msg = raw_msg if is_safe else "[REDACTED - SENSITIVE CREDENTIAL MASKED]"
            items.append({
                "alert_id": me["alert_id"],
                "event_id": me["event_id"],
                "citation_role": me.get("citation_role", "supporting"),
                "created_at": me.get("created_at") or datetime.now(timezone.utc).isoformat(),
                "host_id": event_host_id or expected_host_id,
                "source_id": te.get("source_id", "ssh-auth"),
                "event_type": te.get("event_type", "auth"),
                "event_timestamp": te.get("event_timestamp") or datetime.now(timezone.utc).isoformat(),
                "message": safe_msg,
                "source_ip": te.get("source_ip"),
                "user_name": te.get("user_name"),
                "details": self._sanitize_details(te.get("details")),
            })
        return items


    def insert_alerts(
        self,
        alerts: List[Dict[str, Any]],
        alert_evidence: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        if self.simulate_db_error:
            raise RuntimeError("Database insert error.")
        if not hasattr(self, "alert_evidence"):
            self.alert_evidence = []

        existing_alert_ids = {a["id"] for a in self.alerts}
        new_alerts = 0
        for a in alerts:
            if a["id"] not in existing_alert_ids:
                self.alerts.append(dict(a))
                existing_alert_ids.add(a["id"])
                new_alerts += 1

        existing_ev_keys = {(e["alert_id"], e["event_id"]) for e in self.alert_evidence}
        new_evidence = 0
        for e in alert_evidence:
            key = (e["alert_id"], e["event_id"])
            if key not in existing_ev_keys:
                self.alert_evidence.append(dict(e))
                existing_ev_keys.add(key)
                new_evidence += 1

        return new_alerts, new_evidence

    def insert_security_check_run(
        self,
        run_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on security check run insert.")
        
        # Check host exists
        if not any(h["id"] == run_data.get("host_id") for h in self.hosts):
            raise ValueError(f"Foreign key violation: Host '{run_data.get('host_id')}' not found.")

        # Upsert run
        self.security_runs = [r for r in self.security_runs if r["id"] != run_data["id"]]
        self.security_runs.append(dict(run_data))

        # Upsert findings
        existing_keys = {(f["run_id"], f["check_id"]) for f in self.security_findings}
        for f in findings:
            key = (f["run_id"], f["check_id"])
            if key in existing_keys:
                self.security_findings = [ef for ef in self.security_findings if (ef["run_id"], ef["check_id"]) != key]
            self.security_findings.append(dict(f))
            existing_keys.add(key)

        # Update host last_sc_run_at
        for h in self.hosts:
            if h["id"] == run_data.get("host_id"):
                h["last_sc_run_at"] = run_data.get("completed_at") or datetime.now(timezone.utc).isoformat()

        return run_data

    def list_security_findings(
        self,
        limit: int = 50,
        offset: int = 0,
        host_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on security findings list.")

        filtered = list(self.security_findings)
        if host_id:
            filtered = [f for f in filtered if f.get("host_id") == host_id]
        if category:
            filtered = [f for f in filtered if f.get("category") == category]
        if severity:
            filtered = [f for f in filtered if f.get("severity") == severity]
        if status:
            filtered = [f for f in filtered if f.get("status") == status]
        if search:
            s_lower = search.lower()
            filtered = [
                f for f in filtered
                if s_lower in f.get("check_name", "").lower() or s_lower in f.get("check_id", "").lower()
            ]

        filtered.sort(key=lambda x: x.get("checked_at", ""), reverse=True)
        total = len(filtered)
        paginated = filtered[offset : offset + limit]
        return paginated, total

    def get_security_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get finding.")
        for f in self.security_findings:
            if f["id"] == finding_id:
                return dict(f)
        return None

    def list_security_runs(
        self,
        limit: int = 20,
        offset: int = 0,
        host_id: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on list security runs.")
        filtered = [r for r in self.security_runs if not host_id or r.get("host_id") == host_id]
        filtered.sort(key=lambda x: x.get("started_at", ""), reverse=True)
        total = len(filtered)
        return filtered[offset : offset + limit], total

    def get_security_run_by_id(self, run_id: str) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get security run.")
        for r in self.security_runs:
            if r["id"] == run_id:
                return dict(r)
        return None

    def get_security_summary(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on security summary.")
        findings = [f for f in self.security_findings if not host_id or f.get("host_id") == host_id]
        runs = [r for r in self.security_runs if not host_id or r.get("host_id") == host_id]
        runs.sort(key=lambda x: x.get("started_at", ""), reverse=True)
        last_checked = runs[0].get("completed_at") or runs[0].get("started_at") if runs else None

        return {
            "total_checks": len(findings),
            "passed": sum(1 for f in findings if f.get("status") == "pass"),
            "failed": sum(1 for f in findings if f.get("status") == "fail"),
            "warning": sum(1 for f in findings if f.get("status") == "warning"),
            "not_applicable": sum(1 for f in findings if f.get("status") == "not_applicable"),
            "error": sum(1 for f in findings if f.get("status") == "error"),
            "total_hosts": len(self.hosts),
            "last_checked_at": last_checked,
            "critical_fails": sum(1 for f in findings if f.get("status") == "fail" and f.get("severity") == "critical"),
            "high_fails": sum(1 for f in findings if f.get("status") == "fail" and f.get("severity") == "high"),
            "medium_fails": sum(1 for f in findings if f.get("status") == "fail" and f.get("severity") == "medium"),
            "low_fails": sum(1 for f in findings if f.get("status") == "fail" and f.get("severity") == "low"),
        }

    def get_host_security_history(self, host_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        runs, _ = self.list_security_runs(limit=limit, offset=0, host_id=host_id)
        return runs

    # ==========================================
    # INCIDENT INVESTIGATION & AI ANALYSIS (SQLITE PERSISTENT)
    # ==========================================

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get incident.")
        if settings.database_mode == "cloud_ssot":
            try:
                res = self.client.table("incidents").select("*").eq("id", incident_id).limit(1).execute()
                if not res.data or len(res.data) == 0:
                    return None
                inc = res.data[0]
                rel_res = self.client.table("incident_alerts").select("alert_id").eq("incident_id", incident_id).execute()
                inc["alert_ids"] = [r["alert_id"] for r in (rel_res.data or [])]
                if not inc["alert_ids"] and inc.get("primary_alert_id"):
                    inc["alert_ids"] = [inc["primary_alert_id"]]
                inc["alert_count"] = len(inc["alert_ids"])
                rf_res = self.client.table("incident_risk_factors").select("*").eq("incident_id", incident_id).execute()
                inc["risk_factors"] = rf_res.data or []
                return inc
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to fetch incident %s: %s", incident_id, e)
                raise RuntimeError(f"Cloud SSoT incident lookup failed: {e}") from e
        return self.sqlite_store.get_incident_by_id(incident_id)

    def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        host_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on list incidents.")
        if settings.database_mode == "cloud_ssot":
            try:
                query = self.client.table("incidents").select("*", count="exact")
                if host_id:
                    query = query.eq("host_id", host_id)
                if status:
                    query = query.eq("status", status)
                if severity:
                    query = query.eq("risk_level", severity)
                query = query.order("created_at", desc=True).range(offset, offset + limit - 1)
                res = query.execute()
                items = res.data or []
                total = res.count if res.count is not None else len(items)
                if search:
                    s_low = search.lower()
                    items = [
                        i for i in items
                        if s_low in i.get("id", "").lower()
                        or s_low in i.get("title", "").lower()
                        or s_low in (i.get("attack_scenario") or "").lower()
                    ]
                return items, total
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to list incidents: %s", e)
                raise RuntimeError(f"Cloud SSoT list incidents failed: {e}") from e

        items, total = self.sqlite_store.list_incidents(
            limit=limit,
            offset=offset,
            status=status,
            risk_level=severity,
            host_id=host_id,
        )
        if search:
            s_low = search.lower()
            items = [
                i for i in items
                if s_low in i.get("id", "").lower()
                or s_low in i.get("title", "").lower()
                or s_low in i.get("attack_scenario", "").lower()
            ]
        return items, total

    def upsert_incident(
        self,
        incident_data: Dict[str, Any],
        alert_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on upsert incident.")
        if settings.database_mode == "cloud_ssot":
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                inc_record = {
                    "id": incident_data["id"],
                    "host_id": incident_data.get("host_id") or "host-fenn-ubuntu",
                    "title": incident_data.get("title", "Untitled Incident"),
                    "severity": incident_data.get("severity", "medium"),
                    "status": incident_data.get("status", "new"),
                    "risk_level": incident_data.get("risk_level", "medium"),
                    "risk_score": int(incident_data.get("risk_score", 50)),
                    "alert_count": int(incident_data.get("alert_count", len(alert_ids or []))),
                    "primary_alert_id": incident_data.get("primary_alert_id") or ((alert_ids or [])[0] if alert_ids else None),
                    "source_ip": incident_data.get("source_ip"),
                    "target_user": incident_data.get("target_user"),
                    "attack_scenario": incident_data.get("attack_scenario"),
                    "correlation_reason": incident_data.get("correlation_reason"),
                    "provenance": incident_data.get("provenance", "synthetic_benchmark"),
                    "source_category": incident_data.get("source_category", "unknown"),
                    "source_label": incident_data.get("source_label"),
                    "threat_actor_context": incident_data.get("threat_actor_context"),
                    "first_seen_at": incident_data.get("first_seen_at") or now_iso,
                    "last_seen_at": incident_data.get("last_seen_at") or now_iso,
                    "created_at": incident_data.get("created_at") or now_iso,
                    "updated_at": now_iso,
                }
                if "assigned_to" in incident_data:
                    inc_record["assigned_to"] = incident_data["assigned_to"]

                self.client.table("incidents").upsert(inc_record, on_conflict="id").execute()

                all_alert_ids = list(dict.fromkeys((alert_ids or []) + ([inc_record["primary_alert_id"]] if inc_record.get("primary_alert_id") else [])))
                if all_alert_ids:
                    links = [
                        {
                            "id": f"REL-{incident_data['id']}-{aid}",
                            "incident_id": incident_data["id"],
                            "alert_id": aid,
                            "created_at": now_iso,
                        }
                        for aid in all_alert_ids
                    ]
                    self.client.table("incident_alerts").upsert(links, on_conflict="incident_id,alert_id").execute()

                risk_factors = incident_data.get("risk_factors") or []
                if risk_factors:
                    rf_rows = []
                    for rf in risk_factors:
                        fid = rf.get("factor_id") or rf.get("name") or "factor"
                        rf_rows.append({
                            "id": f"RF-{incident_data['id']}-{fid}",
                            "incident_id": incident_data["id"],
                            "factor_id": fid,
                            "factor_name": rf.get("factor_name") or rf.get("name", fid),
                            "points": int(rf.get("points", 0)),
                            "category": rf.get("category", "base"),
                            "description": rf.get("description", ""),
                            "supporting_evidence_ids": rf.get("supporting_evidence_ids", []),
                            "created_at": now_iso,
                        })
                    self.client.table("incident_risk_factors").upsert(rf_rows, on_conflict="incident_id,factor_id").execute()

                self._execute_mirror(
                    "incident",
                    incident_data["id"],
                    "upsert",
                    lambda: self.sqlite_store.upsert_incident(incident_data, alert_ids, risk_factors),
                )

                return incident_data
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to upsert incident %s: %s", incident_data.get("id"), e)
                raise RuntimeError(f"Cloud SSoT upsert incident failed: {e}") from e

        return self.sqlite_store.upsert_incident(
            incident_data=incident_data,
            alert_ids=alert_ids,
            risk_factors=incident_data.get("risk_factors", []),
        )

    def update_incident_status(
        self,
        incident_id: str,
        status: str,
        note: Optional[str] = None,
        operator: str = "admin",
    ) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on update incident status.")
        if settings.database_mode == "cloud_ssot":
            try:
                curr = self.get_incident_by_id(incident_id)
                if not curr:
                    return None
                old_st = curr.get("status", "new")
                now_iso = datetime.now(timezone.utc).isoformat()
                self.client.table("incidents").update({"status": status, "updated_at": now_iso}).eq("id", incident_id).execute()
                hist_row = {
                    "id": f"SH-{int(time.time()*1000)}",
                    "incident_id": incident_id,
                    "old_status": old_st,
                    "new_status": status,
                    "note": note,
                    "operator": operator,
                    "transitioned_at": now_iso,
                }
                self.client.table("incident_status_history").insert(hist_row).execute()
                tl_row = {
                    "id": f"TL-ST-{int(time.time()*1000)}",
                    "incident_id": incident_id,
                    "timestamp": now_iso,
                    "kind": "status_change",
                    "title": f"Status changed to {status}",
                    "description": note or f"Status transitioned from {old_st} to {status} by {operator}",
                    "severity": curr.get("severity", "medium"),
                    "metadata": {"operator": operator, "old_status": old_st, "new_status": status},
                    "created_at": now_iso,
                }
                self.client.table("incident_timeline").insert(tl_row).execute()
                self._execute_mirror(
                    "incident_status",
                    incident_id,
                    "update_status",
                    lambda: self.sqlite_store.update_incident_status(incident_id, status, note, operator),
                )
                return self.get_incident_by_id(incident_id)
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to update status: %s", e)
                raise RuntimeError(f"Cloud SSoT status update failed: {e}") from e

        return self.sqlite_store.update_incident_status(
            incident_id=incident_id,
            status=status,
            note=note,
            operator=operator,
        )

    def get_incident_alerts(self, incident_id: str) -> List[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get incident alerts.")
        if settings.database_mode == "cloud_ssot":
            try:
                res = self.client.table("incident_alerts").select("alert_id").eq("incident_id", incident_id).execute()
                alert_ids = [r["alert_id"] for r in (res.data or [])]
                if not alert_ids:
                    inc = self.get_incident_by_id(incident_id)
                    if inc and inc.get("primary_alert_id"):
                        alert_ids = [inc["primary_alert_id"]]
                out = []
                for aid in alert_ids:
                    a = self.get_alert_by_id(aid)
                    if a:
                        out.append(a)
                return out
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to get incident alerts: %s", e)
                raise RuntimeError(f"Cloud SSoT get incident alerts failed: {e}") from e

        alert_ids = self.sqlite_store.get_incident_alerts(incident_id)
        if not alert_ids:
            inc = self.sqlite_store.get_incident_by_id(incident_id)
            if inc and inc.get("primary_alert_id"):
                alert_ids = [inc["primary_alert_id"]]

        out = []
        for aid in alert_ids:
            a = self.get_alert_by_id(aid)
            if a:
                out.append(a)
        return out

    def save_ai_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on save ai analysis.")
        if settings.database_mode == "cloud_ssot":
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                row = {
                    "id": analysis_data["id"],
                    "incident_id": analysis_data.get("incident_id"),
                    "alert_id": analysis_data.get("alert_id"),
                    "host_id": analysis_data.get("host_id") or "host-fenn-ubuntu",
                    "analysis_status": analysis_data.get("analysis_status", "completed"),
                    "threat_classification": analysis_data.get("threat_classification", "Unclassified"),
                    "executive_summary": analysis_data.get("executive_summary", ""),
                    "attack_scenario": analysis_data.get("attack_scenario", ""),
                    "observed_behaviors": analysis_data.get("observed_behaviors", []),
                    "timeline": analysis_data.get("timeline", []),
                    "risk_level": analysis_data.get("risk_level", "medium"),
                    "risk_score": int(analysis_data.get("risk_score", 50)),
                    "confidence_level": analysis_data.get("confidence_level", "medium"),
                    "confidence_reason": analysis_data.get("confidence_reason", ""),
                    "facts": analysis_data.get("facts", []),
                    "inferences": analysis_data.get("inferences", []),
                    "hypotheses": analysis_data.get("hypotheses", []),
                    "unknowns": analysis_data.get("unknowns", []),
                    "unknown_items": analysis_data.get("unknown_items", []),
                    "supporting_evidence": analysis_data.get("supporting_evidence", []),
                    "contradicting_evidence": analysis_data.get("contradicting_evidence", []),
                    "impact_assessment": analysis_data.get("impact_assessment", ""),
                    "recommended_actions": analysis_data.get("recommended_actions", []),
                    "containment_recommendations": analysis_data.get("containment_recommendations", []),
                    "investigation_notes": analysis_data.get("investigation_notes"),
                    "provider": analysis_data.get("provider", "gemini"),
                    "model": analysis_data.get("model", "gemini-2.5-flash"),
                    "created_at": analysis_data.get("created_at") or now_iso,
                    "completed_at": analysis_data.get("completed_at") or now_iso,
                }
                self.client.table("ai_analyses").upsert(row, on_conflict="id").execute()
                self._execute_mirror(
                    "ai_analysis",
                    analysis_data["id"],
                    "save",
                    lambda: self.sqlite_store.save_ai_analysis(analysis_data),
                )
                return analysis_data
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to save AI analysis: %s", e)
                raise RuntimeError(f"Cloud SSoT save AI analysis failed: {e}") from e

        return self.sqlite_store.save_ai_analysis(analysis_data)

    def get_latest_ai_analysis(self, incident_id: str) -> Optional[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get latest ai analysis.")
        if settings.database_mode == "cloud_ssot":
            try:
                res = self.client.table("ai_analyses").select("*").eq("incident_id", incident_id).order("created_at", desc=True).limit(1).execute()
                if res.data and len(res.data) > 0:
                    return res.data[0]
                return None
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to get latest AI analysis: %s", e)
                raise RuntimeError(f"Cloud SSoT get latest AI analysis failed: {e}") from e

        return self.sqlite_store.get_latest_ai_analysis(incident_id)

    def get_incident_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get incident timeline.")
        if settings.database_mode == "cloud_ssot":
            try:
                res = self.client.table("incident_timeline").select("*").eq("incident_id", incident_id).order("timestamp", desc=False).execute()
                items = res.data or []
                alerts = self.get_incident_alerts(incident_id)
                for a in alerts:
                    aid = a.get("id")
                    if aid:
                        evs = self.get_alert_evidence(aid) or []
                        for ev in evs:
                            items.append({
                                "id": f"TL-EVT-{ev.get('event_id') or ev.get('id')}",
                                "incident_id": incident_id,
                                "timestamp": ev.get("event_timestamp") or ev.get("created_at") or datetime.now(timezone.utc).isoformat(),
                                "kind": "event",
                                "title": f"Telemetry: {ev.get('source_id') or 'auth'}",
                                "description": ev.get("message", ""),
                                "severity": a.get("severity"),
                                "metadata": {
                                    "source_ip": ev.get("source_ip"),
                                    "user_name": ev.get("user_name"),
                                    "alert_id": aid,
                                },
                            })
                items.sort(key=lambda x: x.get("timestamp", ""))
                return items
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to get incident timeline: %s", e)
                raise RuntimeError(f"Cloud SSoT get timeline failed: {e}") from e

        items = self.sqlite_store.get_incident_timeline(incident_id)
        alerts = self.get_incident_alerts(incident_id)
        for a in alerts:
            aid = a.get("id")
            if aid:
                evs = self.get_alert_evidence(aid) or []
                for ev in evs:
                    items.append({
                        "id": f"TL-EVT-{ev.get('event_id') or ev.get('id')}",
                        "incident_id": incident_id,
                        "timestamp": ev.get("event_timestamp") or ev.get("created_at") or datetime.now(timezone.utc).isoformat(),
                        "kind": "event",
                        "title": f"Telemetry: {ev.get('source_id') or 'auth'}",
                        "description": ev.get("message", ""),
                        "severity": a.get("severity"),
                        "metadata": {
                            "source_ip": ev.get("source_ip"),
                            "user_name": ev.get("user_name"),
                            "alert_id": aid,
                        },
                    })
        items.sort(key=lambda x: x.get("timestamp", ""))
        return items

    def get_incidents_summary(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        if self.simulate_db_error:
            raise RuntimeError("Database error on get incidents summary.")
        if settings.database_mode == "cloud_ssot":
            try:
                query = self.client.table("incidents").select("id, status, risk_level, risk_score, created_at")
                if host_id:
                    query = query.eq("host_id", host_id)
                res = query.execute()
                incs = res.data or []
                total = len(incs)
                open_c = sum(1 for i in incs if i.get("status") in ("new", "investigating", "confirmed", "open"))
                investigating = sum(1 for i in incs if i.get("status") == "investigating")
                contained = sum(1 for i in incs if i.get("status") == "contained")
                resolved = sum(1 for i in incs if i.get("status") in ("resolved", "closed"))
                fp = sum(1 for i in incs if i.get("status") == "false_positive")
                crit = sum(1 for i in incs if i.get("risk_level") == "critical")
                high = sum(1 for i in incs if i.get("risk_level") == "high")
                med = sum(1 for i in incs if i.get("risk_level") == "medium")
                low = sum(1 for i in incs if i.get("risk_level") == "low")
                avg_risk = round(sum(i.get("risk_score", 50) for i in incs) / max(total, 1), 1)

                return {
                    "total_incidents": total,
                    "open_incidents": open_c,
                    "investigating_incidents": investigating,
                    "contained_incidents": contained,
                    "resolved_incidents": resolved,
                    "false_positives": fp,
                    "critical_incidents": crit,
                    "high_incidents": high,
                    "medium_incidents": med,
                    "low_incidents": low,
                    "avg_risk_score": avg_risk,
                }
            except Exception as e:
                logger.error("FATAL [Cloud SSoT]: Failed to get incidents summary: %s", e)
                raise RuntimeError(f"Cloud SSoT summary failed: {e}") from e

        return self.sqlite_store.get_incident_summary()

    def get_mirror_sync_stats(self) -> Dict[str, Any]:
        """Returns statistics and logs of Cloud-to-SQLite mirror synchronization."""
        return self.sqlite_store.get_mirror_sync_stats()



# Global repository instance holder for dependency injection
_active_repository: Optional[BaseAegisRepository] = None


def get_repository() -> BaseAegisRepository:
    """FastAPI Dependency providing repository instance."""
    global _active_repository
    if _active_repository is not None:
        return _active_repository

    if settings.is_supabase_configured:
        try:
            _active_repository = SupabaseRepository()
            return _active_repository
        except Exception:
            pass

    _active_repository = MockAegisRepository()
    return _active_repository


def set_repository(repo: Optional[BaseAegisRepository]):
    """Allows test fixtures to inject custom or mock repositories."""
    global _active_repository
    _active_repository = repo
