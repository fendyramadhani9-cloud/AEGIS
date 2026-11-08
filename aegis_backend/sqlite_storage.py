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

logger = logging.getLogger(__name__)

CURRENT_SCHEMA_VERSION = 1


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

                # Provenance schema evolution
                try:
                    conn.execute("ALTER TABLE incidents ADD COLUMN provenance TEXT DEFAULT 'synthetic_benchmark';")
                    conn.commit()
                except Exception:
                    pass

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
                        first_seen_at, last_seen_at, created_at, updated_at, provenance
                    ) VALUES (
                        :id, :host_id, :title, :severity, :risk_level, :risk_score,
                        :status, :primary_alert_id, :alert_count, :source_ip, :target_user,
                        :attack_scenario, :correlation_reason, :assigned_to,
                        :first_seen_at, :last_seen_at, :created_at, :updated_at, :provenance
                    )
                    ON CONFLICT(id) DO UPDATE SET
                        title = excluded.title,
                        severity = excluded.severity,
                        risk_level = excluded.risk_level,
                        risk_score = excluded.risk_score,
                        primary_alert_id = excluded.primary_alert_id,
                        alert_count = excluded.alert_count,
                        source_ip = excluded.source_ip,
                        target_user = excluded.target_user,
                        attack_scenario = excluded.attack_scenario,
                        correlation_reason = excluded.correlation_reason,
                        last_seen_at = excluded.last_seen_at,
                        updated_at = excluded.updated_at,
                        provenance = excluded.provenance;
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

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single incident by ID."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT * FROM incidents WHERE id = ?;", (incident_id,))
                row = cur.fetchone()
                if not row:
                    return None
                data = dict(row)
                data["storage_backend"] = "sqlite_local"
                data["provenance"] = data.get("provenance") or "synthetic_benchmark"
                return data

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
                items = [dict(r) for r in cur.fetchall()]
                for it in items:
                    it["storage_backend"] = "sqlite_local"
                    it["provenance"] = it.get("provenance") or "synthetic_benchmark"
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
                    "risk_level": analysis_data.get("risk_level", "medium"),
                    "risk_score": analysis_data.get("risk_score", 0),
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
