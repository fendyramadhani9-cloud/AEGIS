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



class SupabaseRepository(BaseAegisRepository):
    """
    Live Supabase Repository connecting via server-side service_role key.
    Enforces read-only safety for reporting and queries unless explicitly invoked for ingestion.
    """

    def __init__(self, client: Optional[Client] = None):
        if client:
            self.client = client
        else:
            if not settings.is_supabase_configured:
                raise ValueError("Cannot initialize SupabaseRepository: Supabase credentials not configured in environment.")
            self.client: Client = create_client(settings.supabase_url, settings.supabase_service_role_key)

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



class MockAegisRepository(BaseAegisRepository):
    """
    In-memory Mock Repository for offline testing and local development.
    Guarantees that tests run completely offline without needing network or credentials.
    """

    def __init__(self, simulate_db_error: bool = False):
        self.simulate_db_error = simulate_db_error
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
