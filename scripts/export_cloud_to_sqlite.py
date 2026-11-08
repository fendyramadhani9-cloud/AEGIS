#!/usr/bin/env python3
"""
AEGIS Cloud-to-SQLite Reverse Data Export & Evacuation Tool.
Used for non-destructive data recovery before any potential schema rollback,
ensuring that records created on Supabase Cloud during cutover are safely
evacuated back to local SQLite.
"""

import os
import sys
import json
import sqlite3
import logging
import argparse
from typing import Dict, Any, List
from datetime import datetime, timezone

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis_reverse_sync")


class CloudToSqliteExporter:
    """Exports all AEGIS operational entities from Supabase Cloud to SQLite."""

    def __init__(self, sqlite_db_path: str, dry_run: bool = False):
        self.sqlite_db_path = sqlite_db_path
        self.dry_run = dry_run
        self.client = None

        if not settings.is_supabase_configured:
            raise ValueError("Supabase credentials not configured in environment.")

        from supabase import create_client
        self.client = create_client(settings.supabase_url, settings.supabase_service_role_key)

        self.report = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "source_supabase": settings.supabase_url,
            "target_sqlite": self.sqlite_db_path,
            "dry_run": self.dry_run,
            "stages": {},
            "status": "INITIALIZED",
            "errors": [],
        }

    def run(self) -> Dict[str, Any]:
        logger.info("Starting Cloud-to-SQLite Reverse Evacuation (Dry-run: %s)...", self.dry_run)
        conn = sqlite3.connect(self.sqlite_db_path)
        conn.row_factory = sqlite3.Row
        try:
            # 1. Security Check Runs
            self._export_security_check_runs(conn)
            # 2. Security Findings
            self._export_security_findings(conn)
            # 3. Incidents
            self._export_incidents(conn)
            # 4. Incident Alerts
            self._export_incident_alerts(conn)
            # 5. Incident Risk Factors
            self._export_incident_risk_factors(conn)
            # 6. Incident Timeline
            self._export_incident_timeline(conn)
            # 7. AI Analyses
            self._export_ai_analyses(conn)
            # 8. Incident Status History
            self._export_incident_status_history(conn)

            if not self.dry_run:
                conn.commit()
            self.report["status"] = "SUCCESS"
            logger.info("Cloud-to-SQLite export completed successfully.")
        except Exception as e:
            logger.error("Export failed: %s", e)
            self.report["status"] = "FAILED"
            self.report["errors"].append(str(e))
            if not self.dry_run:
                conn.rollback()
        finally:
            conn.close()

        return self.report

    def _safe_query(self, table_name: str) -> List[Dict[str, Any]]:
        """Safely queries a table from Supabase Cloud, returning empty list if missing."""
        try:
            res = self.client.table(table_name).select("*").execute()
            return res.data or []
        except Exception as e:
            logger.warning("Cloud table %s query failed or table does not exist: %s", table_name, e)
            return []

    def _export_security_check_runs(self, conn: sqlite3.Connection) -> None:
        rows = self._safe_query("security_check_runs")
        self.report["stages"]["security_check_runs"] = {"cloud_rows": len(rows), "status": "PASS"}
        if self.dry_run or not rows:
            return
        cur = conn.cursor()
        for r in rows:
            cur.execute("""
                INSERT INTO security_check_runs (
                    id, host_id, total_checks, passed, failed, warning, not_applicable, error,
                    raw_summary_json, started_at, completed_at, duration_seconds, scan_type, trigger_source, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    completed_at = excluded.completed_at,
                    passed = excluded.passed,
                    failed = excluded.failed;
            """, (
                r["id"], r["host_id"], r["total_checks"], r["passed"], r["failed"], r["warning"],
                r["not_applicable"], r["error"], json.dumps(r.get("raw_summary_json") or {}),
                r["started_at"], r.get("completed_at"), r.get("duration_seconds", 0.0),
                r.get("scan_type", "manual"), r.get("trigger_source", "admin"), r.get("created_at")
            ))

    def _export_security_findings(self, conn: sqlite3.Connection) -> None:
        rows = self._safe_query("security_findings")
        self.report["stages"]["security_findings"] = {"cloud_rows": len(rows), "status": "PASS"}
        if self.dry_run or not rows:
            return
        cur = conn.cursor()
        for r in rows:
            cur.execute("""
                INSERT INTO security_findings (
                    id, run_id, host_id, check_id, check_name, category, severity, status,
                    description, remediation, details_json, checked_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    details_json = excluded.details_json;
            """, (
                r["id"], r["run_id"], r["host_id"], r["check_id"], r["check_name"], r["category"],
                r["severity"], r["status"], r.get("description", ""), r.get("remediation", ""),
                json.dumps(r.get("details_json") or {}), r["checked_at"], r.get("created_at")
            ))

    def _export_incidents(self, conn: sqlite3.Connection) -> None:
        rows = self._safe_query("incidents")
        self.report["stages"]["incidents"] = {"cloud_rows": len(rows), "status": "PASS"}
        if self.dry_run or not rows:
            return
        cur = conn.cursor()
        for r in rows:
            cur.execute("""
                INSERT INTO incidents (
                    id, host_id, title, severity, risk_level, risk_score, status, primary_alert_id,
                    alert_count, source_ip, target_user, attack_scenario, correlation_reason,
                    assigned_to, first_seen_at, last_seen_at, created_at, updated_at,
                    provenance, source_category, source_label, threat_actor_context
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    risk_score = excluded.risk_score,
                    updated_at = excluded.updated_at;
            """, (
                r["id"], r["host_id"], r["title"], r["severity"], r.get("risk_level", "medium"),
                r.get("risk_score", 50), r.get("status", "new"), r.get("primary_alert_id"),
                r.get("alert_count", 1), r.get("source_ip"), r.get("target_user"), r.get("attack_scenario"),
                r.get("correlation_reason"), r.get("assigned_to"), r.get("first_seen_at"),
                r.get("last_seen_at"), r.get("created_at"), r.get("updated_at"),
                r.get("provenance", "synthetic_benchmark"), r.get("source_category", "unknown"),
                r.get("source_label"), r.get("threat_actor_context")
            ))

    def _export_incident_alerts(self, conn: sqlite3.Connection) -> None:
        rows = self._safe_query("incident_alerts")
        self.report["stages"]["incident_alerts"] = {"cloud_rows": len(rows), "status": "PASS"}
        if self.dry_run or not rows:
            return
        cur = conn.cursor()
        for r in rows:
            cur.execute("""
                INSERT INTO incident_alerts (id, incident_id, alert_id, added_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(incident_id, alert_id) DO NOTHING;
            """, (r["id"], r["incident_id"], r["alert_id"], r.get("added_at") or r.get("created_at")))

    def _export_incident_risk_factors(self, conn: sqlite3.Connection) -> None:
        rows = self._safe_query("incident_risk_factors")
        self.report["stages"]["incident_risk_factors"] = {"cloud_rows": len(rows), "status": "PASS"}
        if self.dry_run or not rows:
            return
        cur = conn.cursor()
        for r in rows:
            cur.execute("""
                INSERT INTO incident_risk_factors (
                    id, incident_id, factor_id, factor_name, points, category, description,
                    supporting_evidence_ids_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id, factor_id) DO UPDATE SET points = excluded.points;
            """, (
                r["id"], r["incident_id"], r["factor_id"], r["factor_name"], r["points"],
                r["category"], r.get("description", ""),
                json.dumps(r.get("supporting_evidence_ids") or []),
                r.get("created_at")
            ))

    def _export_incident_timeline(self, conn: sqlite3.Connection) -> None:
        rows = self._safe_query("incident_timeline")
        self.report["stages"]["incident_timeline"] = {"cloud_rows": len(rows), "status": "PASS"}
        if self.dry_run or not rows:
            return
        cur = conn.cursor()
        for r in rows:
            cur.execute("""
                INSERT INTO incident_timeline (id, incident_id, timestamp, kind, title, description, severity, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO NOTHING;
            """, (
                r["id"], r["incident_id"], r["timestamp"], r["kind"], r["title"], r["description"],
                r.get("severity"), json.dumps(r.get("metadata") or {}), r.get("created_at")
            ))

    def _export_ai_analyses(self, conn: sqlite3.Connection) -> None:
        rows = self._safe_query("ai_analyses")
        self.report["stages"]["ai_analyses"] = {"cloud_rows": len(rows), "status": "PASS"}
        if self.dry_run or not rows:
            return
        cur = conn.cursor()
        for r in rows:
            cur.execute("""
                INSERT INTO ai_analyses (
                    id, incident_id, alert_id, host_id, analysis_status, threat_classification,
                    executive_summary, attack_scenario, risk_level, risk_score, confidence_level,
                    confidence_reason, facts_json, inferences_json, hypotheses_json, unknowns_json,
                    observed_behaviors_json, timeline_json, supporting_evidence_json, contradicting_evidence_json,
                    impact_assessment, recommended_actions_json, containment_recommendations_json,
                    investigation_notes, provider, model, created_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    analysis_status = excluded.analysis_status,
                    executive_summary = excluded.executive_summary;
            """, (
                r["id"], r.get("incident_id"), r.get("alert_id"), r["host_id"], r["analysis_status"],
                r["threat_classification"], r["executive_summary"], r["attack_scenario"],
                r["risk_level"], r["risk_score"], r["confidence_level"], r.get("confidence_reason", ""),
                json.dumps(r.get("facts") or []), json.dumps(r.get("inferences") or []),
                json.dumps(r.get("hypotheses") or []), json.dumps(r.get("unknowns") or []),
                json.dumps(r.get("observed_behaviors") or []), json.dumps(r.get("timeline") or []),
                json.dumps(r.get("supporting_evidence") or []), json.dumps(r.get("contradicting_evidence") or []),
                r.get("impact_assessment", ""), json.dumps(r.get("recommended_actions") or []),
                json.dumps(r.get("containment_recommendations") or []), r.get("investigation_notes"),
                r["provider"], r["model"], r["created_at"], r.get("completed_at")
            ))

    def _export_incident_status_history(self, conn: sqlite3.Connection) -> None:
        rows = self._safe_query("incident_status_history")
        self.report["stages"]["incident_status_history"] = {"cloud_rows": len(rows), "status": "PASS"}
        if self.dry_run or not rows:
            return
        cur = conn.cursor()
        for r in rows:
            cur.execute("""
                INSERT INTO incident_status_history (id, incident_id, old_status, new_status, note, operator, transitioned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO NOTHING;
            """, (r["id"], r["incident_id"], r.get("old_status"), r["new_status"], r.get("note"), r.get("operator", "admin"), r["transitioned_at"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Cloud-to-SQLite Reverse Data Export")
    parser.add_argument("--sqlite-path", default="data/aegis_incidents.db", help="Path to target SQLite DB")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Inspect Cloud records without writing")
    args = parser.parse_args()

    exporter = CloudToSqliteExporter(sqlite_db_path=args.sqlite_path, dry_run=args.dry_run)
    rep = exporter.run()
    print(json.dumps(rep, indent=2))

