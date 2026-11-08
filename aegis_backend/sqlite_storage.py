"""
AEGIS SQLite Local Persistent Storage Engine.
Provides ACID-compliant, disk-backed local persistence for incidents, alerts correlation,
timelines, status transitions, and AI analyses when Supabase Cloud migration is pending.

Guarantees:
1. Zero Data Loss Across Process / VM Restarts.
2. WAL Mode for concurrent reader-writer efficiency.
3. Strict Foreign Key enforcement.
4. Atomic transactions with automatic rollback on error.
5. Zero secrets/passwords stored.
"""

import os
import json
import sqlite3
import logging
import threading
from contextlib import contextmanager
from typing import List, Dict, Any, Optional, Tuple, Iterator
from datetime import datetime, timezone
from aegis_backend.source_attribution import classify_ip_source

logger = logging.getLogger(__name__)

CURRENT_SCHEMA_VERSION = 2


class SqliteIncidentStore:
    """ACID-compliant SQLite store for AEGIS Incident Investigation subsystem."""

    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)
        self._lock = threading.Lock()
        self._ensure_storage_dir()
        self._init_schema()

    def _ensure_storage_dir(self) -> None:
        """Ensures storage directory exists with restricted permissions on POSIX."""
        parent_dir = os.path.dirname(self.db_path)
        if not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
            if hasattr(os, "chmod") and os.name != "nt":
                try:
                    os.chmod(parent_dir, 0o750)
                except OSError as e:
                    logger.warning("Could not set 0750 permissions on %s: %s", parent_dir, e)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Yields a connection configured with WAL mode, busy timeout, and foreign keys, safely closing it after."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            yield conn
        finally:
            conn.close()

    def check_integrity(self) -> Tuple[bool, str]:
        """Runs PRAGMA integrity_check to verify database health."""
        with self._lock:
            try:
                with self._connection() as conn:
                    cursor = conn.execute("PRAGMA integrity_check;")
                    rows = cursor.fetchall()
                    if rows and rows[0][0] == "ok":
                        return True, "ok"
                    return False, f"Integrity issues: {[r[0] for r in rows]}"
            except Exception as e:
                return False, f"Integrity check failed: {str(e)}"

    def create_backup(self, backup_path: Optional[str] = None) -> str:
        """Creates a hot online backup using SQLite's backup API."""
        if not backup_path:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = f"{self.db_path}.backup_{timestamp}"
        with self._lock:
            with self._connection() as src_conn:
                dest_conn = sqlite3.connect(backup_path)
                try:
                    with dest_conn:
                        src_conn.backup(dest_conn)
                finally:
                    dest_conn.close()
        logger.info("Created SQLite backup at %s", backup_path)
        return backup_path

    def _init_schema(self) -> None:
        """Runs idempotent versioned schema migration."""
        with self._lock:
            with self._connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_at TEXT NOT NULL,
                        description TEXT NOT NULL
                    );
                """)
                cur = conn.execute("SELECT MAX(version) FROM schema_migrations;")
                row = cur.fetchone()
                current_ver = row[0] if row and row[0] is not None else 0

                if current_ver < 1:
                    logger.info("Applying SQLite schema migration v1 to %s", self.db_path)
                    conn.executescript("""
                        CREATE TABLE IF NOT EXISTS incidents (
                            id TEXT PRIMARY KEY,
                            host_id TEXT NOT NULL,
                            title TEXT NOT NULL,
                            severity TEXT NOT NULL,
                            risk_level TEXT NOT NULL,
                            risk_score INTEGER NOT NULL,
                            status TEXT NOT NULL DEFAULT 'new',
                            primary_alert_id TEXT,
                            alert_count INTEGER DEFAULT 1,
                            source_ip TEXT,
                            target_user TEXT,
                            attack_scenario TEXT,
                            correlation_reason TEXT,
                            assigned_to TEXT,
                            first_seen_at TEXT NOT NULL,
                            last_seen_at TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        );

                        CREATE INDEX IF NOT EXISTS idx_incidents_host ON incidents(host_id);
                        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
                        CREATE INDEX IF NOT EXISTS idx_incidents_risk ON incidents(risk_level);

                        CREATE TABLE IF NOT EXISTS incident_alerts (
                            id TEXT PRIMARY KEY,
                            incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                            alert_id TEXT NOT NULL,
                            added_at TEXT NOT NULL,
                            UNIQUE(incident_id, alert_id)
                        );

                        CREATE INDEX IF NOT EXISTS idx_incident_alerts_inc ON incident_alerts(incident_id);
                        CREATE INDEX IF NOT EXISTS idx_incident_alerts_alt ON incident_alerts(alert_id);

                        CREATE TABLE IF NOT EXISTS incident_risk_factors (
                            id TEXT PRIMARY KEY,
                            incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                            factor_id TEXT NOT NULL,
                            factor_name TEXT NOT NULL,
                            points INTEGER NOT NULL,
                            category TEXT NOT NULL,
                            description TEXT,
                            supporting_evidence_ids TEXT DEFAULT '[]'
                        );

                        CREATE INDEX IF NOT EXISTS idx_risk_factors_inc ON incident_risk_factors(incident_id);

                        CREATE TABLE IF NOT EXISTS incident_timeline (
                            id TEXT PRIMARY KEY,
                            incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                            timestamp TEXT NOT NULL,
                            kind TEXT NOT NULL,
                            title TEXT NOT NULL,
                            description TEXT,
                            severity TEXT,
                            metadata_json TEXT DEFAULT '{}'
                        );

                        CREATE INDEX IF NOT EXISTS idx_timeline_inc ON incident_timeline(incident_id);
                        CREATE INDEX IF NOT EXISTS idx_timeline_ts ON incident_timeline(timestamp);

                        CREATE TABLE IF NOT EXISTS incident_status_history (
                            id TEXT PRIMARY KEY,
                            incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                            old_status TEXT NOT NULL,
                            new_status TEXT NOT NULL,
                            note TEXT,
                            operator TEXT NOT NULL,
                            transitioned_at TEXT NOT NULL
                        );

                        CREATE INDEX IF NOT EXISTS idx_status_history_inc ON incident_status_history(incident_id);

                        CREATE TABLE IF NOT EXISTS ai_analyses (
                            id TEXT PRIMARY KEY,
                            incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                            alert_id TEXT,
                            host_id TEXT NOT NULL,
                            analysis_status TEXT NOT NULL,
                            threat_classification TEXT NOT NULL,
                            executive_summary TEXT NOT NULL,
                            attack_scenario TEXT NOT NULL,
                            risk_level TEXT NOT NULL,
                            risk_score INTEGER NOT NULL,
                            confidence_level TEXT NOT NULL,
                            confidence_reason TEXT,
                            facts_json TEXT NOT NULL DEFAULT '[]',
                            inferences_json TEXT NOT NULL DEFAULT '[]',
                            hypotheses_json TEXT NOT NULL DEFAULT '[]',
                            unknowns_json TEXT NOT NULL DEFAULT '[]',
                            observed_behaviors_json TEXT DEFAULT '[]',
                            timeline_json TEXT DEFAULT '[]',
                            supporting_evidence_json TEXT NOT NULL DEFAULT '[]',
                            contradicting_evidence_json TEXT DEFAULT '[]',
                            impact_assessment TEXT,
                            recommended_actions_json TEXT DEFAULT '[]',
                            containment_recommendations_json TEXT DEFAULT '[]',
                            investigation_notes TEXT,
                            provider TEXT NOT NULL,
                            model TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            completed_at TEXT NOT NULL
                        );

                        CREATE INDEX IF NOT EXISTS idx_ai_analyses_inc ON ai_analyses(incident_id);
                    """)
                    now_iso = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?);",
                        (1, now_iso, "Initial v1 incident investigation schema"),
                    )
                    conn.commit()

                # Provenance and Source Attribution schema evolution
                try:
                    conn.execute("ALTER TABLE incidents ADD COLUMN provenance TEXT DEFAULT 'synthetic_benchmark';")
                    conn.commit()
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE incidents ADD COLUMN source_category TEXT DEFAULT 'unknown';")
                    conn.commit()
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE incidents ADD COLUMN source_label TEXT;")
                    conn.commit()
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE incidents ADD COLUMN threat_actor_context TEXT;")
                    conn.commit()
                except Exception:
                    pass

                # Version 2: Security Checker Persistent Runs and Findings
                if current_ver < 2:
                    logger.info("Applying SQLite schema migration v2 (security checker persistence) to %s", self.db_path)
                    conn.executescript("""
                        CREATE TABLE IF NOT EXISTS security_check_runs (
                            id TEXT PRIMARY KEY,
                            host_id TEXT NOT NULL,
                            status TEXT NOT NULL DEFAULT 'completed',
                            total_checks INTEGER NOT NULL DEFAULT 0,
                            passed_checks INTEGER NOT NULL DEFAULT 0,
                            failed_checks INTEGER NOT NULL DEFAULT 0,
                            warning_checks INTEGER NOT NULL DEFAULT 0,
                            error_checks INTEGER NOT NULL DEFAULT 0,
                            checker_version TEXT NOT NULL DEFAULT '1.0.0',
                            summary TEXT NOT NULL DEFAULT '{}',
                            started_at TEXT NOT NULL,
                            completed_at TEXT,
                            created_at TEXT NOT NULL
                        );

                        CREATE INDEX IF NOT EXISTS idx_sc_runs_host_started ON security_check_runs(host_id, started_at DESC);
                        CREATE INDEX IF NOT EXISTS idx_sc_runs_status ON security_check_runs(status);

                        CREATE TABLE IF NOT EXISTS security_findings (
                            id TEXT PRIMARY KEY,
                            run_id TEXT NOT NULL REFERENCES security_check_runs(id) ON DELETE CASCADE,
                            host_id TEXT NOT NULL,
                            check_id TEXT NOT NULL,
                            check_name TEXT NOT NULL,
                            category TEXT NOT NULL,
                            severity TEXT NOT NULL,
                            status TEXT NOT NULL,
                            actual_value TEXT,
                            expected_value TEXT,
                            description TEXT NOT NULL,
                            security_impact TEXT,
                            recommendation TEXT,
                            evidence_summary TEXT,
                            remediation_reference TEXT,
                            checked_at TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            UNIQUE(run_id, check_id)
                        );

                        CREATE INDEX IF NOT EXISTS idx_sc_findings_host_checked ON security_findings(host_id, checked_at DESC);
                        CREATE INDEX IF NOT EXISTS idx_sc_findings_run_id ON security_findings(run_id);
                        CREATE INDEX IF NOT EXISTS idx_sc_findings_check_id ON security_findings(check_id);
                        CREATE INDEX IF NOT EXISTS idx_sc_findings_category ON security_findings(category);
                        CREATE INDEX IF NOT EXISTS idx_sc_findings_severity ON security_findings(severity);
                        CREATE INDEX IF NOT EXISTS idx_sc_findings_status ON security_findings(status);
                    """)
                    now_iso = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?);",
                        (2, now_iso, "Security checker persistent runs and findings schema"),
                    )
                    conn.commit()

                conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION};")

                # Mirror status tracking table for Cloud-to-SQLite synchronization auditing with durable payload
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS mirror_sync_log (
                        id TEXT PRIMARY KEY,
                        entity_type TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        payload TEXT,
                        status TEXT NOT NULL,
                        retry_count INTEGER NOT NULL DEFAULT 0,
                        error_message TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_mirror_status ON mirror_sync_log(status);")
                try:
                    conn.execute("ALTER TABLE mirror_sync_log ADD COLUMN payload TEXT;")
                except Exception:
                    pass

                # Catch-up watermark tracking table for crash-recovery state preservation
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS catch_up_watermark (
                        entity_type TEXT PRIMARY KEY,
                        last_synced_at TEXT NOT NULL,
                        records_checked INTEGER NOT NULL DEFAULT 0,
                        records_caught_up INTEGER NOT NULL DEFAULT 0,
                        status TEXT NOT NULL DEFAULT 'completed',
                        completed_at TEXT NOT NULL
                    );
                """)
                conn.commit()

    def log_mirror_attempt(
        self,
        entity_type: str,
        entity_id: str,
        action: str,
        status: str,
        retry_count: int = 0,
        error_message: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Records the status of a Cloud-to-SQLite mirror synchronization attempt with durable payload."""
        now_iso = datetime.now(timezone.utc).isoformat()
        log_id = f"LOG-{entity_type}-{entity_id}"
        payload_json = json.dumps(payload) if payload else None
        with self._lock:
            try:
                with self._connection() as conn:
                    conn.execute("""
                        INSERT INTO mirror_sync_log (id, entity_type, entity_id, action, payload, status, retry_count, error_message, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            action = excluded.action,
                            payload = COALESCE(excluded.payload, mirror_sync_log.payload),
                            status = excluded.status,
                            retry_count = excluded.retry_count,
                            error_message = excluded.error_message,
                            updated_at = excluded.updated_at;
                    """, (log_id, entity_type, entity_id, action, payload_json, status, retry_count, error_message, now_iso, now_iso))
                    conn.commit()
            except Exception as e:
                logger.warning("Failed to record mirror sync log: %s", e)

    def get_mirror_sync_stats(self) -> Dict[str, Any]:
        """Returns aggregated mirror status counts, queue depth, latency, and last failed records."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT status, count(*) FROM mirror_sync_log GROUP BY status;")
                counts = {r[0]: r[1] for r in cur.fetchall()}
                cur = conn.execute("SELECT entity_type, entity_id, error_message, updated_at FROM mirror_sync_log WHERE status != 'synced' ORDER BY updated_at DESC LIMIT 10;")
                failures = [dict(r) for r in cur.fetchall()]
                
                # Observability calculations
                cur = conn.execute("SELECT MIN(created_at) FROM mirror_sync_log WHERE status != 'synced';")
                oldest_row = cur.fetchone()
                oldest_pending_age_seconds = None
                if oldest_row and oldest_row[0]:
                    try:
                        oldest_dt = datetime.fromisoformat(oldest_row[0])
                        oldest_pending_age_seconds = round((datetime.now(timezone.utc) - oldest_dt).total_seconds(), 1)
                    except Exception:
                        pass

                cur = conn.execute("SELECT MAX(updated_at) FROM mirror_sync_log WHERE status = 'synced';")
                last_synced_row = cur.fetchone()
                last_successful_mirror_at = last_synced_row[0] if last_synced_row else None

                cur = conn.execute("SELECT MAX(updated_at) FROM mirror_sync_log WHERE status != 'synced';")
                last_failed_row = cur.fetchone()
                last_failed_mirror_at = last_failed_row[0] if last_failed_row else None

                pending_cnt = counts.get("pending_retry", 0)
                failed_cnt = counts.get("failed", 0)
                queue_depth = pending_cnt + failed_cnt

                return {
                    "total_logs": sum(counts.values()),
                    "synced": counts.get("synced", 0),
                    "failed": failed_cnt,
                    "pending_retry": pending_cnt,
                    "queue_depth": queue_depth,
                    "oldest_pending_age_seconds": oldest_pending_age_seconds,
                    "last_successful_mirror_at": last_successful_mirror_at,
                    "last_failed_mirror_at": last_failed_mirror_at,
                    "recent_failures": failures,
                }

    def get_failed_mirror_logs(self) -> List[Dict[str, Any]]:
        """Returns all mirror sync records that have not successfully synced."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT id, entity_type, entity_id, action, payload, status, retry_count, error_message, created_at, updated_at "
                    "FROM mirror_sync_log WHERE status != 'synced';"
                )
                return [dict(r) for r in cur.fetchall()]

    def record_catch_up_watermark(
        self,
        entity_type: str,
        records_checked: int,
        records_caught_up: int,
        status: str = "completed",
    ) -> None:
        """Persists or updates progress watermark for catch-up operations."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                with self._connection() as conn:
                    conn.execute("""
                        INSERT INTO catch_up_watermark (
                            entity_type, last_synced_at, records_checked, records_caught_up, status, completed_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(entity_type) DO UPDATE SET
                            last_synced_at = excluded.last_synced_at,
                            records_checked = excluded.records_checked,
                            records_caught_up = excluded.records_caught_up,
                            status = excluded.status,
                            completed_at = excluded.completed_at;
                    """, (entity_type, now_iso, records_checked, records_caught_up, status, now_iso))
                    conn.commit()
            except Exception as e:
                logger.warning("Failed to record catch-up watermark for %s: %s", entity_type, e)

    def get_catch_up_watermarks(self) -> Dict[str, Dict[str, Any]]:
        """Returns all recorded catch-up watermarks."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT entity_type, last_synced_at, records_checked, records_caught_up, status, completed_at FROM catch_up_watermark;")
                return {row["entity_type"]: dict(row) for row in cur.fetchall()}

    def upsert_incident_timeline_event(self, event_dict: Dict[str, Any]) -> None:
        """Idempotently inserts or updates an incident timeline entry."""
        ev_id = event_dict.get("id") or f"TL-{event_dict.get('incident_id')}-{int(datetime.now(timezone.utc).timestamp())}"
        meta = event_dict.get("metadata_json") or event_dict.get("metadata")
        meta_str = json.dumps(meta) if isinstance(meta, (dict, list)) else (str(meta) if meta else "{}")
        with self._lock:
            with self._connection() as conn:
                conn.execute("""
                    INSERT INTO incident_timeline (id, incident_id, timestamp, kind, title, description, severity, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        timestamp = excluded.timestamp,
                        kind = excluded.kind,
                        title = excluded.title,
                        description = excluded.description,
                        severity = excluded.severity,
                        metadata_json = excluded.metadata_json;
                """, (
                    ev_id, event_dict.get("incident_id"), event_dict.get("timestamp"),
                    event_dict.get("kind", "alert"), event_dict.get("title", ""),
                    event_dict.get("description", ""), event_dict.get("severity", "medium"),
                    meta_str,
                ))
                conn.commit()

    def upsert_incident_status_history(self, history_dict: Dict[str, Any]) -> None:
        """Idempotently inserts or updates an incident status audit history entry."""
        hist_id = history_dict.get("id")
        with self._lock:
            with self._connection() as conn:
                conn.execute("""
                    INSERT INTO incident_status_history (id, incident_id, old_status, new_status, changed_at, changed_by, reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        old_status = excluded.old_status,
                        new_status = excluded.new_status,
                        changed_at = excluded.changed_at,
                        changed_by = excluded.changed_by,
                        reason = excluded.reason;
                """, (
                    hist_id, history_dict.get("incident_id"), history_dict.get("old_status"),
                    history_dict.get("new_status"), history_dict.get("changed_at"),
                    history_dict.get("changed_by", "system"), history_dict.get("reason"),
                ))
                conn.commit()

    # =========================================================================
    # INCIDENT OPERATIONS
    # =========================================================================

    def upsert_incident(
        self,
        incident_data: Dict[str, Any],
        alert_ids: Optional[List[str]] = None,
        risk_factors: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Atomically upserts incident, links alert IDs, and updates risk factor breakdowns."""
        inc_id = incident_data["id"]
        now_iso = datetime.now(timezone.utc).isoformat()
        alert_ids = alert_ids or []
        risk_factors = risk_factors or []

        # Determine data provenance
        default_prov = (
            "synthetic_benchmark"
            if (
                "ALT-SEED-" in str(incident_data.get("primary_alert_id", ""))
                or "198.51.100." in str(incident_data.get("source_ip", ""))
                or "09e84aeac243e448" in str(incident_data.get("primary_alert_id", ""))
            )
            else "controlled_operational_test"
        )
        prov = incident_data.get("provenance") or default_prov

        with self._lock:
            with self._connection() as conn:
                # 1. Upsert incident header
                conn.execute("""
                    INSERT INTO incidents (
                        id, host_id, title, severity, risk_level, risk_score,
                        status, primary_alert_id, alert_count, source_ip, target_user,
                        attack_scenario, correlation_reason, assigned_to,
                        first_seen_at, last_seen_at, created_at, updated_at, provenance,
                        source_category, source_label, threat_actor_context
                    ) VALUES (
                        :id, :host_id, :title, :severity, :risk_level, :risk_score,
                        :status, :primary_alert_id, :alert_count, :source_ip, :target_user,
                        :attack_scenario, :correlation_reason, :assigned_to,
                        :first_seen_at, :last_seen_at, :created_at, :updated_at, :provenance,
                        :source_category, :source_label, :threat_actor_context
                    )
                    ON CONFLICT(id) DO UPDATE SET
                        title = excluded.title,
                        severity = excluded.severity,
                        risk_level = excluded.risk_level,
                        risk_score = excluded.risk_score,
                        status = excluded.status,
                        primary_alert_id = excluded.primary_alert_id,
                        alert_count = excluded.alert_count,
                        source_ip = excluded.source_ip,
                        target_user = excluded.target_user,
                        attack_scenario = excluded.attack_scenario,
                        correlation_reason = excluded.correlation_reason,
                        last_seen_at = excluded.last_seen_at,
                        updated_at = excluded.updated_at,
                        provenance = excluded.provenance,
                        source_category = excluded.source_category,
                        source_label = excluded.source_label,
                        threat_actor_context = excluded.threat_actor_context;
                """, {
                    "id": inc_id,
                    "host_id": incident_data.get("host_id", ""),
                    "title": incident_data.get("title", ""),
                    "severity": incident_data.get("severity", "medium"),
                    "risk_level": incident_data.get("risk_level", "medium"),
                    "risk_score": incident_data.get("risk_score", 0),
                    "status": incident_data.get("status", "new"),
                    "primary_alert_id": incident_data.get("primary_alert_id"),
                    "alert_count": max(len(alert_ids), incident_data.get("alert_count", 1)),
                    "source_ip": incident_data.get("source_ip"),
                    "target_user": incident_data.get("target_user"),
                    "attack_scenario": incident_data.get("attack_scenario"),
                    "correlation_reason": incident_data.get("correlation_reason"),
                    "assigned_to": incident_data.get("assigned_to"),
                    "first_seen_at": incident_data.get("first_seen_at", now_iso),
                    "last_seen_at": incident_data.get("last_seen_at", now_iso),
                    "created_at": incident_data.get("created_at", now_iso),
                    "updated_at": now_iso,
                    "provenance": prov,
                    "source_category": incident_data.get("source_category", "unknown"),
                    "source_label": incident_data.get("source_label"),
                    "threat_actor_context": incident_data.get("threat_actor_context"),
                })

                # 2. Insert alert relationships idempotently
                for aid in alert_ids:
                    rel_id = f"REL-{inc_id}-{aid}"
                    conn.execute("""
                        INSERT INTO incident_alerts (id, incident_id, alert_id, added_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(incident_id, alert_id) DO NOTHING;
                    """, (rel_id, inc_id, aid, now_iso))

                # 3. Replace risk factors
                if risk_factors:
                    conn.execute("DELETE FROM incident_risk_factors WHERE incident_id = ?;", (inc_id,))
                    for idx, rf in enumerate(risk_factors):
                        rf_id = f"RF-{inc_id}-{idx}-{rf.get('factor_id', 'fact')}"
                        ev_json = json.dumps(rf.get("supporting_evidence_ids", []))
                        conn.execute("""
                            INSERT INTO incident_risk_factors (
                                id, incident_id, factor_id, factor_name, points, category, description, supporting_evidence_ids
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            rf_id, inc_id, rf.get("factor_id", f"FACTOR-{idx}"),
                            rf.get("factor_name", rf.get("name", "Risk Factor")),
                            rf.get("points", 0), rf.get("category", "general"),
                            rf.get("description", ""), ev_json
                        ))

                # 4. Synthesize initial creation timeline entry if not present
                conn.execute("""
                    INSERT OR IGNORE INTO incident_timeline (id, incident_id, timestamp, kind, title, description, severity, metadata_json)
                    VALUES (?, ?, ?, 'alert', ?, ?, ?, ?);
                """, (
                    f"TL-{inc_id}-INIT", inc_id, incident_data.get("first_seen_at", now_iso),
                    f"Incident Identified: {incident_data.get('title')}",
                    incident_data.get("attack_scenario") or "Correlated security detection sequence.",
                    incident_data.get("severity", "medium"),
                    json.dumps({"alert_count": len(alert_ids), "source_ip": incident_data.get("source_ip")})
                ))

                conn.commit()

        stored = self.get_incident_by_id(inc_id)
        return stored or incident_data

    def _enrich_incident_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        data["storage_backend"] = "sqlite_local"
        data["provenance"] = data.get("provenance") or "synthetic_benchmark"
        if not data.get("source_category") or data.get("source_category") in ("unknown", None):
            attr = classify_ip_source(data.get("source_ip"))
            data["source_category"] = attr["category"]
            data["source_label"] = attr["label"]
            data["threat_actor_context"] = attr["threat_actor_context"]
        return data

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single incident by ID."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT * FROM incidents WHERE id = ?;", (incident_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return self._enrich_incident_dict(dict(row))

    def list_incidents(
        self,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None,
        risk_level: Optional[str] = None,
        host_id: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Lists incidents with optional filters and returns paginated list + total count."""
        where_clauses = []
        params = []

        if status:
            where_clauses.append("status = ?")
            params.append(status.lower())
        if risk_level:
            where_clauses.append("risk_level = ?")
            params.append(risk_level.lower())
        if host_id:
            where_clauses.append("host_id = ?")
            params.append(host_id)

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        with self._lock:
            with self._connection() as conn:
                count_cur = conn.execute(f"SELECT COUNT(*) FROM incidents {where_sql};", params)
                total = count_cur.fetchone()[0]

                query = f"""
                    SELECT * FROM incidents {where_sql}
                    ORDER BY updated_at DESC, first_seen_at DESC
                    LIMIT ? OFFSET ?;
                """
                cur = conn.execute(query, params + [limit, offset])
                items = [self._enrich_incident_dict(dict(r)) for r in cur.fetchall()]
                return items, total

    def get_incident_summary(self) -> Dict[str, Any]:
        """Aggregates KPI metrics across all stored incidents."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT status, risk_level, host_id, updated_at FROM incidents;")
                rows = cur.fetchall()

                total = len(rows)
                new_cnt = sum(1 for r in rows if r["status"] == "new")
                investigating = sum(1 for r in rows if r["status"] == "investigating")
                confirmed = sum(1 for r in rows if r["status"] == "confirmed")
                resolved = sum(1 for r in rows if r["status"] == "resolved")
                false_pos = sum(1 for r in rows if r["status"] == "false_positive")
                contained = sum(1 for r in rows if r["status"] == "contained")

                crit = sum(1 for r in rows if r["risk_level"] == "critical")
                high = sum(1 for r in rows if r["risk_level"] == "high")
                med = sum(1 for r in rows if r["risk_level"] == "medium")
                low = sum(1 for r in rows if r["risk_level"] == "low")

                hosts = len(set(r["host_id"] for r in rows if r["host_id"]))
                latest = max([r["updated_at"] for r in rows], default=None)

                return {
                    "total_incidents": total,
                    "new_incidents": new_cnt,
                    "open_incidents": new_cnt + investigating,
                    "investigating": investigating,
                    "confirmed": confirmed,
                    "resolved": resolved,
                    "false_positives": false_pos,
                    "contained": contained,
                    "critical_risk": crit,
                    "high_risk": high,
                    "medium_risk": med,
                    "low_risk": low,
                    "total_hosts_affected": hosts,
                    "latest_incident_at": latest,
                    "storage_backend": "sqlite_local",
                }

    def update_incident_status(
        self,
        incident_id: str,
        status: str,
        note: Optional[str] = None,
        operator: str = "admin",
    ) -> Optional[Dict[str, Any]]:
        """Atomically transitions status, records status history, and appends timeline event."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT * FROM incidents WHERE id = ?;", (incident_id,))
                row = cur.fetchone()
                if not row:
                    return None
                old_status = row["status"]
                new_st = status.lower()

                # Update header
                conn.execute(
                    "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?;",
                    (new_st, now_iso, incident_id),
                )

                # Record status history
                hist_id = f"HIST-{incident_id}-{int(datetime.now(timezone.utc).timestamp())}"
                conn.execute("""
                    INSERT INTO incident_status_history (id, incident_id, old_status, new_status, note, operator, transitioned_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                """, (hist_id, incident_id, old_status, new_st, note, operator, now_iso))

                # Append timeline event
                tl_id = f"TL-{incident_id}-ST-{int(datetime.now(timezone.utc).timestamp())}"
                conn.execute("""
                    INSERT INTO incident_timeline (id, incident_id, timestamp, kind, title, description, severity, metadata_json)
                    VALUES (?, ?, ?, 'status_change', ?, ?, ?, ?);
                """, (
                    tl_id, incident_id, now_iso,
                    f"Status updated to {new_st.upper()}",
                    note or f"Status transitioned by operator '{operator}'.",
                    row["severity"],
                    json.dumps({"old_status": old_status, "new_status": new_st, "operator": operator})
                ))

                conn.commit()

        return self.get_incident_by_id(incident_id)

    def get_incident_alerts(self, incident_id: str) -> List[str]:
        """Returns list of alert IDs linked to this incident."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT alert_id FROM incident_alerts WHERE incident_id = ? ORDER BY added_at ASC;", (incident_id,))
                return [r["alert_id"] for r in cur.fetchall()]

    def get_incident_risk_factors(self, incident_id: str) -> List[Dict[str, Any]]:
        """Returns structured risk factors for the incident."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT * FROM incident_risk_factors WHERE incident_id = ?;", (incident_id,))
                out = []
                for r in cur.fetchall():
                    ev_list = []
                    try:
                        ev_list = json.loads(r["supporting_evidence_ids"] or "[]")
                    except Exception:
                        pass
                    out.append({
                        "factor_id": r["factor_id"],
                        "factor_name": r["factor_name"],
                        "name": r["factor_name"],
                        "points": r["points"],
                        "category": r["category"],
                        "description": r["description"],
                        "supporting_evidence_ids": ev_list,
                    })
                return out

    def get_incident_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Returns ordered timeline items for an incident."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM incident_timeline WHERE incident_id = ? ORDER BY timestamp ASC;",
                    (incident_id,),
                )
                items = []
                for r in cur.fetchall():
                    meta = {}
                    try:
                        meta = json.loads(r["metadata_json"] or "{}")
                    except Exception:
                        pass
                    items.append({
                        "id": r["id"],
                        "incident_id": r["incident_id"],
                        "timestamp": r["timestamp"],
                        "kind": r["kind"],
                        "title": r["title"],
                        "description": r["description"],
                        "severity": r["severity"],
                        "metadata": meta,
                    })
                return items

    def get_incident_status_history(self, incident_id: str) -> List[Dict[str, Any]]:
        """Returns status history transitions."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM incident_status_history WHERE incident_id = ? ORDER BY transitioned_at ASC;",
                    (incident_id,),
                )
                return [dict(r) for r in cur.fetchall()]

    # =========================================================================
    # AI ANALYSIS OPERATIONS
    # =========================================================================

    def save_ai_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Atomically stores AI analysis and creates a timeline milestone entry."""
        now_iso = datetime.now(timezone.utc).isoformat()
        analysis_id = analysis_data.get("id") or analysis_data.get("analysis_id") or f"ANL-{analysis_data.get('incident_id')}-{int(datetime.now(timezone.utc).timestamp())}"
        inc_id = analysis_data["incident_id"]

        with self._lock:
            with self._connection() as conn:
                # Enforce Single Source of Truth for Risk Score:
                # Always bind analysis risk_score and risk_level to the incident's official Risk Engine values
                cur_inc = conn.execute("SELECT risk_score, risk_level FROM incidents WHERE id = ?;", (inc_id,))
                inc_row = cur_inc.fetchone()
                official_score = inc_row["risk_score"] if inc_row else analysis_data.get("risk_score", 0)
                official_level = inc_row["risk_level"] if inc_row else analysis_data.get("risk_level", "medium")

                conn.execute("""
                    INSERT INTO ai_analyses (
                        id, incident_id, alert_id, host_id, analysis_status,
                        threat_classification, executive_summary, attack_scenario,
                        risk_level, risk_score, confidence_level, confidence_reason,
                        facts_json, inferences_json, hypotheses_json, unknowns_json,
                        observed_behaviors_json, timeline_json, supporting_evidence_json,
                        contradicting_evidence_json, impact_assessment,
                        recommended_actions_json, containment_recommendations_json,
                        investigation_notes, provider, model, created_at, completed_at
                    ) VALUES (
                        :id, :incident_id, :alert_id, :host_id, :analysis_status,
                        :threat_classification, :executive_summary, :attack_scenario,
                        :risk_level, :risk_score, :confidence_level, :confidence_reason,
                        :facts_json, :inferences_json, :hypotheses_json, :unknowns_json,
                        :observed_behaviors_json, :timeline_json, :supporting_evidence_json,
                        :contradicting_evidence_json, :impact_assessment,
                        :recommended_actions_json, :containment_recommendations_json,
                        :investigation_notes, :provider, :model, :created_at, :completed_at
                    )
                    ON CONFLICT(id) DO UPDATE SET
                        analysis_status = excluded.analysis_status,
                        threat_classification = excluded.threat_classification,
                        executive_summary = excluded.executive_summary,
                        attack_scenario = excluded.attack_scenario,
                        risk_level = excluded.risk_level,
                        risk_score = excluded.risk_score,
                        confidence_level = excluded.confidence_level,
                        confidence_reason = excluded.confidence_reason,
                        facts_json = excluded.facts_json,
                        inferences_json = excluded.inferences_json,
                        hypotheses_json = excluded.hypotheses_json,
                        unknowns_json = excluded.unknowns_json,
                        observed_behaviors_json = excluded.observed_behaviors_json,
                        timeline_json = excluded.timeline_json,
                        supporting_evidence_json = excluded.supporting_evidence_json,
                        impact_assessment = excluded.impact_assessment,
                        recommended_actions_json = excluded.recommended_actions_json,
                        containment_recommendations_json = excluded.containment_recommendations_json,
                        completed_at = excluded.completed_at;
                """, {
                    "id": analysis_id,
                    "incident_id": inc_id,
                    "alert_id": analysis_data.get("alert_id"),
                    "host_id": analysis_data.get("host_id", ""),
                    "analysis_status": analysis_data.get("analysis_status", "completed"),
                    "threat_classification": analysis_data.get("threat_classification", "Unclassified Anomaly"),
                    "executive_summary": analysis_data.get("executive_summary", ""),
                    "attack_scenario": analysis_data.get("attack_scenario", ""),
                    "risk_level": official_level,
                    "risk_score": official_score,
                    "confidence_level": analysis_data.get("confidence_level", "medium"),
                    "confidence_reason": analysis_data.get("confidence_reason", ""),
                    "facts_json": json.dumps(analysis_data.get("facts", analysis_data.get("observed_behaviors", []))),
                    "inferences_json": json.dumps(analysis_data.get("inferences", [])),
                    "hypotheses_json": json.dumps(analysis_data.get("hypotheses", [])),
                    "unknowns_json": json.dumps(analysis_data.get("unknown_items", analysis_data.get("unknowns", []))),
                    "observed_behaviors_json": json.dumps(analysis_data.get("observed_behaviors", [])),
                    "timeline_json": json.dumps(analysis_data.get("timeline", [])),
                    "supporting_evidence_json": json.dumps(analysis_data.get("supporting_evidence", [])),
                    "contradicting_evidence_json": json.dumps(analysis_data.get("contradicting_evidence", [])),
                    "impact_assessment": analysis_data.get("impact_assessment", ""),
                    "recommended_actions_json": json.dumps(analysis_data.get("recommended_actions", [])),
                    "containment_recommendations_json": json.dumps(analysis_data.get("containment_recommendations", [])),
                    "investigation_notes": analysis_data.get("investigation_notes"),
                    "provider": analysis_data.get("provider", "gemini"),
                    "model": analysis_data.get("model", "gemini-3.5-flash-lite"),
                    "created_at": analysis_data.get("created_at", now_iso),
                    "completed_at": analysis_data.get("completed_at", now_iso),
                })

                # Insert timeline milestone
                tl_id = f"TL-{inc_id}-ANL-{int(datetime.now(timezone.utc).timestamp())}"
                conn.execute("""
                    INSERT INTO incident_timeline (id, incident_id, timestamp, kind, title, description, severity, metadata_json)
                    VALUES (?, ?, ?, 'analysis', ?, ?, ?, ?);
                """, (
                    tl_id, inc_id, analysis_data.get("completed_at", now_iso),
                    f"AI Investigation: {analysis_data.get('threat_classification', 'Completed')}",
                    (analysis_data.get("executive_summary") or "")[:200],
                    analysis_data.get("risk_level", "medium"),
                    json.dumps({
                        "provider": analysis_data.get("provider"),
                        "model": analysis_data.get("model"),
                        "confidence": analysis_data.get("confidence_level"),
                    })
                ))

                conn.commit()

        stored = self.get_latest_ai_analysis(inc_id)
        return stored or analysis_data

    def get_latest_ai_analysis(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves most recent analysis for the incident."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT * FROM ai_analyses WHERE incident_id = ? ORDER BY completed_at DESC, created_at DESC LIMIT 1;",
                    (incident_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return self._deserialize_analysis(dict(row))

    def get_analysis_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves analysis record by unique ID."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT * FROM ai_analyses WHERE id = ?;", (analysis_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return self._deserialize_analysis(dict(row))

    def _deserialize_analysis(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Unpacks JSON fields from database row into Python structures."""
        out = dict(row)
        out["storage_backend"] = "sqlite_local"
        out["analysis_id"] = out["id"]

        for json_key, target_key in [
            ("facts_json", "facts"),
            ("inferences_json", "inferences"),
            ("hypotheses_json", "hypotheses"),
            ("observed_behaviors_json", "observed_behaviors"),
            ("timeline_json", "timeline"),
            ("supporting_evidence_json", "supporting_evidence"),
            ("contradicting_evidence_json", "contradicting_evidence"),
            ("recommended_actions_json", "recommended_actions"),
            ("containment_recommendations_json", "containment_recommendations"),
        ]:
            raw = out.pop(json_key, "[]")
            try:
                out[target_key] = json.loads(raw or "[]")
            except Exception:
                out[target_key] = []

        # Handle unknowns (ensuring List[str]) and unknown_items (List[Dict])
        raw_unknowns = out.pop("unknowns_json", "[]")
        try:
            parsed_u = json.loads(raw_unknowns or "[]")
        except Exception:
            parsed_u = []

        if parsed_u and isinstance(parsed_u[0], dict):
            out["unknown_items"] = parsed_u
            out["unknowns"] = [str(item.get("data_gap", item)) for item in parsed_u]
        else:
            out["unknowns"] = [str(x) for x in parsed_u]
            out["unknown_items"] = [{"data_gap": str(x), "impact": "Forensic telemetry gap."} for x in parsed_u]

        return out

    # =========================================================================
    # SECURITY CHECKER PERSISTENT OPERATIONS
    # =========================================================================

    def upsert_security_check_run(
        self,
        run_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Atomically persists security check run and findings with foreign key cascade."""
        now_iso = datetime.now(timezone.utc).isoformat()
        run_id = run_data["id"]
        host_id = run_data["host_id"]

        raw_summary = run_data.get("summary", {})
        summary_str = json.dumps(raw_summary) if isinstance(raw_summary, (dict, list)) else str(raw_summary or "{}")

        with self._lock:
            with self._connection() as conn:
                # 1. Upsert run
                conn.execute("""
                    INSERT INTO security_check_runs (
                        id, host_id, status, total_checks, passed_checks,
                        failed_checks, warning_checks, error_checks,
                        checker_version, summary, started_at, completed_at, created_at
                    ) VALUES (
                        :id, :host_id, :status, :total_checks, :passed_checks,
                        :failed_checks, :warning_checks, :error_checks,
                        :checker_version, :summary, :started_at, :completed_at, :created_at
                    )
                    ON CONFLICT(id) DO UPDATE SET
                        status = excluded.status,
                        total_checks = excluded.total_checks,
                        passed_checks = excluded.passed_checks,
                        failed_checks = excluded.failed_checks,
                        warning_checks = excluded.warning_checks,
                        error_checks = excluded.error_checks,
                        checker_version = excluded.checker_version,
                        summary = excluded.summary,
                        completed_at = excluded.completed_at;
                """, {
                    "id": run_id,
                    "host_id": host_id,
                    "status": run_data.get("status", "completed"),
                    "total_checks": run_data.get("total_checks", 0),
                    "passed_checks": run_data.get("passed_checks", 0),
                    "failed_checks": run_data.get("failed_checks", 0),
                    "warning_checks": run_data.get("warning_checks", 0),
                    "error_checks": run_data.get("error_checks", 0),
                    "checker_version": run_data.get("checker_version", "1.0.0"),
                    "summary": summary_str,
                    "started_at": run_data.get("started_at") or now_iso,
                    "completed_at": run_data.get("completed_at"),
                    "created_at": run_data.get("created_at") or now_iso,
                })

                # 2. Upsert findings
                for f in findings:
                    f_id = f.get("id") or f"FND-{host_id}-{f.get('check_id')}-{run_id}"
                    conn.execute("""
                        INSERT INTO security_findings (
                            id, run_id, host_id, check_id, check_name, category,
                            severity, status, actual_value, expected_value, description,
                            security_impact, recommendation, evidence_summary,
                            remediation_reference, checked_at, created_at
                        ) VALUES (
                            :id, :run_id, :host_id, :check_id, :check_name, :category,
                            :severity, :status, :actual_value, :expected_value, :description,
                            :security_impact, :recommendation, :evidence_summary,
                            :remediation_reference, :checked_at, :created_at
                        )
                        ON CONFLICT(run_id, check_id) DO UPDATE SET
                            severity = excluded.severity,
                            status = excluded.status,
                            actual_value = excluded.actual_value,
                            expected_value = excluded.expected_value,
                            description = excluded.description,
                            security_impact = excluded.security_impact,
                            recommendation = excluded.recommendation,
                            evidence_summary = excluded.evidence_summary,
                            remediation_reference = excluded.remediation_reference,
                            checked_at = excluded.checked_at;
                    """, {
                        "id": f_id,
                        "run_id": f.get("run_id") or run_id,
                        "host_id": f.get("host_id") or host_id,
                        "check_id": f.get("check_id", ""),
                        "check_name": f.get("check_name", ""),
                        "category": f.get("category", "system"),
                        "severity": f.get("severity", "medium"),
                        "status": f.get("status", "pass"),
                        "actual_value": str(f.get("actual_value")) if f.get("actual_value") is not None else None,
                        "expected_value": str(f.get("expected_value")) if f.get("expected_value") is not None else None,
                        "description": f.get("description", ""),
                        "security_impact": f.get("security_impact"),
                        "recommendation": f.get("recommendation"),
                        "evidence_summary": f.get("evidence_summary"),
                        "remediation_reference": f.get("remediation_reference"),
                        "checked_at": f.get("checked_at") or now_iso,
                        "created_at": f.get("created_at") or now_iso,
                    })

                conn.commit()

        logger.info("Persisted security check run %s (%d findings) to SQLite.", run_id, len(findings))
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
        """Returns paginated security findings matching query criteria."""
        clauses = []
        params: List[Any] = []

        if host_id:
            clauses.append("host_id = ?")
            params.append(host_id)
        if category:
            clauses.append("category = ?")
            params.append(category)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if search:
            clauses.append("(check_name LIKE ? OR check_id LIKE ?)")
            s_param = f"%{search}%"
            params.extend([s_param, s_param])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._lock:
            with self._connection() as conn:
                count_cur = conn.execute(f"SELECT COUNT(*) FROM security_findings {where_sql};", params)
                total = count_cur.fetchone()[0]

                data_params = list(params) + [limit, offset]
                cur = conn.execute(
                    f"SELECT * FROM security_findings {where_sql} ORDER BY checked_at DESC LIMIT ? OFFSET ?;",
                    data_params,
                )
                rows = [dict(r) for r in cur.fetchall()]
                return rows, total

    def get_security_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Returns single security finding by ID."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT * FROM security_findings WHERE id = ? LIMIT 1;", (finding_id,))
                row = cur.fetchone()
                return dict(row) if row else None

    def list_security_runs(
        self,
        limit: int = 20,
        offset: int = 0,
        host_id: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Returns paginated execution runs."""
        clauses = []
        params: List[Any] = []

        if host_id:
            clauses.append("host_id = ?")
            params.append(host_id)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._lock:
            with self._connection() as conn:
                count_cur = conn.execute(f"SELECT COUNT(*) FROM security_check_runs {where_sql};", params)
                total = count_cur.fetchone()[0]

                data_params = list(params) + [limit, offset]
                cur = conn.execute(
                    f"SELECT * FROM security_check_runs {where_sql} ORDER BY started_at DESC LIMIT ? OFFSET ?;",
                    data_params,
                )
                runs = []
                for r in cur.fetchall():
                    item = dict(r)
                    if isinstance(item.get("summary"), str):
                        try:
                            item["summary"] = json.loads(item["summary"])
                        except Exception:
                            item["summary"] = {}
                    runs.append(item)
                return runs, total

    def get_security_run_by_id(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Returns security check run by ID."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT * FROM security_check_runs WHERE id = ? LIMIT 1;", (run_id,))
                row = cur.fetchone()
                if not row:
                    return None
                item = dict(row)
                if isinstance(item.get("summary"), str):
                    try:
                        item["summary"] = json.loads(item["summary"])
                    except Exception:
                        item["summary"] = {}
                return item

    def get_security_summary(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        """Returns aggregated posture counters and last run timestamp."""
        with self._lock:
            with self._connection() as conn:
                sql = """
                    SELECT
                        COUNT(*) as total_checks,
                        COALESCE(SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END), 0) as passed,
                        COALESCE(SUM(CASE WHEN status = 'fail' THEN 1 ELSE 0 END), 0) as failed,
                        COALESCE(SUM(CASE WHEN status = 'warning' THEN 1 ELSE 0 END), 0) as warning,
                        COALESCE(SUM(CASE WHEN status = 'not_applicable' THEN 1 ELSE 0 END), 0) as not_applicable,
                        COALESCE(SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END), 0) as error,
                        COALESCE(SUM(CASE WHEN status = 'fail' AND severity = 'critical' THEN 1 ELSE 0 END), 0) as critical_fails,
                        COALESCE(SUM(CASE WHEN status = 'fail' AND severity = 'high' THEN 1 ELSE 0 END), 0) as high_fails,
                        COALESCE(SUM(CASE WHEN status = 'fail' AND severity = 'medium' THEN 1 ELSE 0 END), 0) as medium_fails,
                        COALESCE(SUM(CASE WHEN status = 'fail' AND severity = 'low' THEN 1 ELSE 0 END), 0) as low_fails
                    FROM security_findings
                """
                params: List[Any] = []
                if host_id:
                    sql += " WHERE host_id = ?"
                    params.append(host_id)

                cur = conn.execute(sql, params)
                row = cur.fetchone()

                # Get latest run timestamp
                run_sql = "SELECT completed_at, started_at FROM security_check_runs"
                run_params: List[Any] = []
                if host_id:
                    run_sql += " WHERE host_id = ?"
                    run_params.append(host_id)
                run_sql += " ORDER BY started_at DESC LIMIT 1;"

                run_cur = conn.execute(run_sql, run_params)
                last_run = run_cur.fetchone()
                last_checked_at = None
                if last_run:
                    last_checked_at = last_run["completed_at"] or last_run["started_at"]

                # Distinct host count
                host_cur = conn.execute("SELECT COUNT(DISTINCT host_id) FROM security_check_runs;")
                total_hosts = host_cur.fetchone()[0] or 1

                return {
                    "total_checks": row["total_checks"] if row else 0,
                    "passed": row["passed"] if row else 0,
                    "failed": row["failed"] if row else 0,
                    "warning": row["warning"] if row else 0,
                    "not_applicable": row["not_applicable"] if row else 0,
                    "error": row["error"] if row else 0,
                    "total_hosts": total_hosts,
                    "last_checked_at": last_checked_at,
                    "critical_fails": row["critical_fails"] if row else 0,
                    "high_fails": row["high_fails"] if row else 0,
                    "medium_fails": row["medium_fails"] if row else 0,
                    "low_fails": row["low_fails"] if row else 0,
                }

    def get_host_security_history(self, host_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        runs, _ = self.list_security_runs(limit=limit, offset=0, host_id=host_id)
        return runs
