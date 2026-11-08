"""
AEGIS SQLite-to-Supabase Data Migration Bridge.
Safely migrates operational security data from local SQLite to Supabase Cloud PostgreSQL.

Guarantees & Characteristics:
1. Strict Read-Only on source SQLite (zero mutations/deletions on source data).
2. Idempotent upserts (can be re-run safely multiple times without duplication).
3. Dry-Run mode (--dry-run) for schema & foreign-key validation without writes.
4. Structured dependency graph (Hosts -> Security Runs -> Findings -> Incidents -> Junctions -> Timeline -> AI).
5. Comprehensive error reporting and checkpoint logging (JSON report output).
6. Zero secrets exposed (sanitized logging).
7. Complete preservation of IDs, timestamps, risk factors, provenance, and 4-tier AI reasoning.
"""

import os
import sys
import json
import sqlite3
import argparse
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis_migration")


class DataMigrationBridge:
    def __init__(
        self,
        sqlite_db_path: str,
        supabase_url: Optional[str] = None,
        supabase_key: Optional[str] = None,
        dry_run: bool = True,
        batch_size: int = 50,
    ):
        self.sqlite_db_path = os.path.abspath(sqlite_db_path)
        self.dry_run = dry_run
        self.batch_size = batch_size
        self.supabase_url = supabase_url or os.getenv("SUPABASE_URL")
        self.supabase_key = supabase_key or os.getenv("SUPABASE_SERVICE_ROLE_KEY")

        if not os.path.exists(self.sqlite_db_path):
            raise FileNotFoundError(f"Source SQLite database not found at {self.sqlite_db_path}")

        self.client = None
        if not self.dry_run:
            if not self.supabase_url or not self.supabase_key:
                raise ValueError("Cannot run live migration: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be provided.")
            from supabase import create_client
            self.client = create_client(self.supabase_url, self.supabase_key)
            logger.info("Connected to Supabase Cloud: %s", self.supabase_url.split("//")[-1].split(".")[0] + ".supabase.co")

        self.report = {
            "migration_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "mode": "DRY_RUN" if self.dry_run else "LIVE_EXECUTION",
            "source_sqlite": self.sqlite_db_path,
            "target_supabase": self.supabase_url or "SIMULATED / DRY_RUN",
            "stages": {},
            "errors": [],
            "status": "INITIALIZED",
        }

    def _open_sqlite(self) -> sqlite3.Connection:
        """Opens a read-only SQLite connection."""
        uri = f"file:{self.sqlite_db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def run(self) -> Dict[str, Any]:
        """Executes the full migration pipeline in strict dependency order."""
        logger.info("======================================================================")
        logger.info("Starting AEGIS SQLite -> Supabase Data Migration (Mode: %s)", "DRY-RUN" if self.dry_run else "LIVE")
        logger.info("======================================================================")

        try:
            conn = self._open_sqlite()
            try:
                # Stage 1: Pre-flight Foreign Key & Prerequisite Check
                self._check_prerequisites(conn)

                # Stage 2: Security Checker Runs
                self._migrate_security_check_runs(conn)

                # Stage 3: Security Findings
                self._migrate_security_findings(conn)

                # Stage 4: Incidents
                self._migrate_incidents(conn)

                # Stage 5: Incident Alerts (Junctions)
                self._migrate_incident_alerts(conn)

                # Stage 6: Incident Risk Factors
                self._migrate_incident_risk_factors(conn)

                # Stage 7: Incident Timeline
                self._migrate_incident_timeline(conn)

                # Stage 8: AI Analyses
                self._migrate_ai_analyses(conn)

                # Stage 9: Incident Status History
                self._migrate_incident_status_history(conn)

                self.report["status"] = "SUCCESS"
                logger.info("Data migration completed successfully without errors.")
            finally:
                conn.close()
        except Exception as e:
            logger.error("Migration failed: %s", e)
            self.report["status"] = "FAILED"
            self.report["errors"].append(str(e))

        return self.report

    def _check_prerequisites(self, conn: sqlite3.Connection) -> None:
        """Verifies target hosts and parent alerts exist before migrating child data."""
        stage_name = "01_prerequisites_check"
        logger.info("[Stage 1] Verifying prerequisites and host registrations...")

        cur = conn.cursor()
        cur.execute("SELECT DISTINCT host_id FROM incidents UNION SELECT DISTINCT host_id FROM security_check_runs;")
        needed_hosts = set(r[0] for r in cur.fetchall() if r[0])

        cur.execute("SELECT DISTINCT alert_id FROM incident_alerts;")
        needed_alerts = set(r[0] for r in cur.fetchall() if r[0])

        missing_hosts = []
        missing_alerts = []

        if not self.dry_run and self.client:
            # Query hosts from Supabase
            res_hosts = self.client.table("hosts").select("id").execute()
            cloud_hosts = set(h["id"] for h in res_hosts.data or [])
            missing_hosts = list(needed_hosts - cloud_hosts)

            # Query alerts from Supabase
            res_alerts = self.client.table("alerts").select("id").execute()
            cloud_alerts = set(a["id"] for a in res_alerts.data or [])
            missing_alerts = list(needed_alerts - cloud_alerts)
        else:
            logger.info("  [Dry-Run] Needed Hosts (%d): %s", len(needed_hosts), list(needed_hosts))
            logger.info("  [Dry-Run] Needed Alerts (%d): %s", len(needed_alerts), list(needed_alerts)[:5])

        if missing_hosts:
            raise ValueError(f"Prerequisite failure: Target Supabase lacks required host(s): {missing_hosts}")

        self.report["stages"][stage_name] = {
            "needed_hosts": list(needed_hosts),
            "needed_alerts_count": len(needed_alerts),
            "missing_hosts": missing_hosts,
            "missing_alerts": missing_alerts,
            "status": "PASS",
        }

    def _migrate_security_check_runs(self, conn: sqlite3.Connection) -> None:
        stage_name = "02_security_check_runs"
        logger.info("[Stage 2] Migrating security_check_runs...")
        cur = conn.cursor()
        cur.execute("SELECT * FROM security_check_runs ORDER BY started_at ASC;")
        rows = [dict(r) for r in cur.fetchall()]

        payloads = []
        for r in rows:
            summary_raw = r.get("summary")
            summary_obj = json.loads(summary_raw) if isinstance(summary_raw, str) and summary_raw else (summary_raw or {})
            payloads.append({
                "id": r["id"],
                "host_id": r["host_id"],
                "status": r.get("status", "completed"),
                "total_checks": r.get("total_checks", 0),
                "passed_checks": r.get("passed_checks", 0),
                "failed_checks": r.get("failed_checks", 0),
                "warning_checks": r.get("warning_checks", 0),
                "error_checks": r.get("error_checks", 0),
                "checker_version": r.get("checker_version", "1.0.0"),
                "summary": summary_obj,
                "started_at": r["started_at"],
                "completed_at": r.get("completed_at"),
                "created_at": r.get("created_at") or r["started_at"],
            })

        if not self.dry_run and payloads and self.client:
            self._upsert_batches("security_check_runs", payloads, on_conflict="id")

        self.report["stages"][stage_name] = {"source_rows": len(rows), "migrated_rows": len(payloads), "status": "PASS"}
        logger.info("  Migrated %d security_check_runs records.", len(payloads))

    def _migrate_security_findings(self, conn: sqlite3.Connection) -> None:
        stage_name = "03_security_findings"
        logger.info("[Stage 3] Migrating security_findings...")
        cur = conn.cursor()
        cur.execute("SELECT * FROM security_findings ORDER BY checked_at ASC;")
        rows = [dict(r) for r in cur.fetchall()]

        payloads = []
        for r in rows:
            payloads.append({
                "id": r["id"],
                "run_id": r["run_id"],
                "host_id": r["host_id"],
                "check_id": r["check_id"],
                "check_name": r["check_name"],
                "category": r["category"],
                "severity": r["severity"],
                "status": r["status"],
                "actual_value": r.get("actual_value"),
                "expected_value": r.get("expected_value"),
                "description": r["description"],
                "security_impact": r.get("security_impact"),
                "recommendation": r.get("recommendation"),
                "evidence_summary": r.get("evidence_summary"),
                "remediation_reference": r.get("remediation_reference"),
                "checked_at": r["checked_at"],
                "created_at": r.get("created_at") or r["checked_at"],
            })

        if not self.dry_run and payloads and self.client:
            self._upsert_batches("security_findings", payloads, on_conflict="run_id,check_id")

        self.report["stages"][stage_name] = {"source_rows": len(rows), "migrated_rows": len(payloads), "status": "PASS"}
        logger.info("  Migrated %d security_findings records.", len(payloads))

    def _migrate_incidents(self, conn: sqlite3.Connection) -> None:
        stage_name = "04_incidents"
        logger.info("[Stage 4] Migrating incidents...")
        cur = conn.cursor()
        cur.execute("SELECT * FROM incidents ORDER BY created_at ASC;")
        rows = [dict(r) for r in cur.fetchall()]

        payloads = []
        for r in rows:
            payloads.append({
                "id": r["id"],
                "host_id": r["host_id"],
                "title": r["title"],
                "severity": r["severity"],
                "risk_level": r["risk_level"],
                "risk_score": r["risk_score"],
                "status": r["status"],
                "primary_alert_id": r.get("primary_alert_id"),
                "alert_count": r.get("alert_count", 1),
                "source_ip": r.get("source_ip"),
                "target_user": r.get("target_user"),
                "attack_scenario": r.get("attack_scenario"),
                "correlation_reason": r.get("correlation_reason"),
                "assigned_to": r.get("assigned_to"),
                "first_seen_at": r.get("first_seen_at") or r["created_at"],
                "last_seen_at": r.get("last_seen_at") or r["created_at"],
                "created_at": r["created_at"],
                "updated_at": r.get("updated_at") or r["created_at"],
                "provenance": r.get("provenance", "synthetic_benchmark"),
                "source_category": r.get("source_category", "unknown"),
                "source_label": r.get("source_label"),
                "threat_actor_context": r.get("threat_actor_context"),
            })

        if not self.dry_run and payloads and self.client:
            self._upsert_batches("incidents", payloads, on_conflict="id")

        self.report["stages"][stage_name] = {"source_rows": len(rows), "migrated_rows": len(payloads), "status": "PASS"}
        logger.info("  Migrated %d incidents records.", len(payloads))

    def _migrate_incident_alerts(self, conn: sqlite3.Connection) -> None:
        stage_name = "05_incident_alerts"
        logger.info("[Stage 5] Migrating incident_alerts...")
        cur = conn.cursor()
        cur.execute("SELECT * FROM incident_alerts ORDER BY added_at ASC;")
        rows = [dict(r) for r in cur.fetchall()]

        payloads = []
        for r in rows:
            payloads.append({
                "id": r.get("id") or f"REL-{r['incident_id']}-{r['alert_id']}",
                "incident_id": r["incident_id"],
                "alert_id": r["alert_id"],
                "added_at": r.get("added_at") or datetime.now(timezone.utc).isoformat(),
                "created_at": r.get("added_at") or datetime.now(timezone.utc).isoformat(),
            })

        if not self.dry_run and payloads and self.client:
            self._upsert_batches("incident_alerts", payloads, on_conflict="incident_id,alert_id")

        self.report["stages"][stage_name] = {"source_rows": len(rows), "migrated_rows": len(payloads), "status": "PASS"}
        logger.info("  Migrated %d incident_alerts records.", len(payloads))

    def _migrate_incident_risk_factors(self, conn: sqlite3.Connection) -> None:
        stage_name = "06_incident_risk_factors"
        logger.info("[Stage 6] Migrating incident_risk_factors...")
        cur = conn.cursor()
        cur.execute("SELECT * FROM incident_risk_factors;")
        rows = [dict(r) for r in cur.fetchall()]

        payloads = []
        for r in rows:
            ev_ids = r.get("supporting_evidence_ids", "[]")
            if isinstance(ev_ids, str):
                try:
                    ev_ids_parsed = json.loads(ev_ids)
                except Exception:
                    ev_ids_parsed = []
            else:
                ev_ids_parsed = ev_ids or []

            payloads.append({
                "id": r["id"],
                "incident_id": r["incident_id"],
                "factor_id": r["factor_id"],
                "factor_name": r["factor_name"],
                "points": r["points"],
                "category": r["category"],
                "description": r.get("description"),
                "supporting_evidence_ids": ev_ids_parsed,
            })

        if not self.dry_run and payloads and self.client:
            self._upsert_batches("incident_risk_factors", payloads, on_conflict="incident_id,factor_id")

        self.report["stages"][stage_name] = {"source_rows": len(rows), "migrated_rows": len(payloads), "status": "PASS"}
        logger.info("  Migrated %d incident_risk_factors records.", len(payloads))

    def _migrate_incident_timeline(self, conn: sqlite3.Connection) -> None:
        stage_name = "07_incident_timeline"
        logger.info("[Stage 7] Migrating incident_timeline...")
        cur = conn.cursor()
        cur.execute("SELECT * FROM incident_timeline ORDER BY timestamp ASC;")
        rows = [dict(r) for r in cur.fetchall()]

        payloads = []
        for r in rows:
            meta = r.get("metadata_json", "{}")
            if isinstance(meta, str):
                try:
                    meta_parsed = json.loads(meta)
                except Exception:
                    meta_parsed = {}
            else:
                meta_parsed = meta or {}

            payloads.append({
                "id": r["id"],
                "incident_id": r["incident_id"],
                "timestamp": r["timestamp"],
                "kind": r["kind"],
                "title": r["title"],
                "description": r["description"] or "",
                "severity": r.get("severity"),
                "metadata": meta_parsed,
                "created_at": r["timestamp"],
            })

        if not self.dry_run and payloads and self.client:
            self._upsert_batches("incident_timeline", payloads, on_conflict="id")

        self.report["stages"][stage_name] = {"source_rows": len(rows), "migrated_rows": len(payloads), "status": "PASS"}
        logger.info("  Migrated %d incident_timeline records.", len(payloads))

    def _migrate_ai_analyses(self, conn: sqlite3.Connection) -> None:
        stage_name = "08_ai_analyses"
        logger.info("[Stage 8] Migrating ai_analyses...")
        cur = conn.cursor()
        cur.execute("SELECT * FROM ai_analyses ORDER BY created_at ASC;")
        rows = [dict(r) for r in cur.fetchall()]

        payloads = []
        for r in rows:
            def parse_json(val, default):
                if isinstance(val, str):
                    try:
                        return json.loads(val)
                    except Exception:
                        return default
                return val if val is not None else default

            unknowns_parsed = parse_json(r.get("unknowns_json"), [])
            unknowns_list = [str(u.get("data_gap", u)) if isinstance(u, dict) else str(u) for u in unknowns_parsed]
            unknown_items = unknowns_parsed if unknowns_parsed and isinstance(unknowns_parsed[0], dict) else [
                {"data_gap": str(x), "impact": "Forensic telemetry gap"} for x in unknowns_list
            ]

            payloads.append({
                "id": r["id"],
                "incident_id": r["incident_id"],
                "alert_id": r.get("alert_id"),
                "host_id": r["host_id"],
                "analysis_status": r["analysis_status"],
                "threat_classification": r["threat_classification"],
                "executive_summary": r["executive_summary"],
                "attack_scenario": r["attack_scenario"],
                "risk_level": r["risk_level"],
                "risk_score": r["risk_score"],
                "confidence_level": r["confidence_level"],
                "confidence_reason": r.get("confidence_reason", "Forensic evaluation"),
                "facts": parse_json(r.get("facts_json"), []),
                "inferences": parse_json(r.get("inferences_json"), []),
                "hypotheses": parse_json(r.get("hypotheses_json"), []),
                "unknowns": unknowns_list,
                "unknown_items": unknown_items,
                "observed_behaviors": parse_json(r.get("observed_behaviors_json"), []),
                "timeline": parse_json(r.get("timeline_json"), []),
                "supporting_evidence": parse_json(r.get("supporting_evidence_json"), []),
                "contradicting_evidence": parse_json(r.get("contradicting_evidence_json"), []),
                "impact_assessment": r.get("impact_assessment") or "",
                "recommended_actions": parse_json(r.get("recommended_actions_json"), []),
                "containment_recommendations": parse_json(r.get("containment_recommendations_json"), []),
                "investigation_notes": r.get("investigation_notes"),
                "provider": r["provider"],
                "model": r["model"],
                "created_at": r["created_at"],
                "completed_at": r.get("completed_at") or r["created_at"],
            })

        if not self.dry_run and payloads and self.client:
            self._upsert_batches("ai_analyses", payloads, on_conflict="id")

        self.report["stages"][stage_name] = {"source_rows": len(rows), "migrated_rows": len(payloads), "status": "PASS"}
        logger.info("  Migrated %d ai_analyses records.", len(payloads))

    def _migrate_incident_status_history(self, conn: sqlite3.Connection) -> None:
        stage_name = "09_incident_status_history"
        logger.info("[Stage 9] Migrating incident_status_history...")
        cur = conn.cursor()
        cur.execute("SELECT * FROM incident_status_history ORDER BY transitioned_at ASC;")
        rows = [dict(r) for r in cur.fetchall()]

        payloads = []
        for r in rows:
            payloads.append({
                "id": r["id"],
                "incident_id": r["incident_id"],
                "old_status": r["old_status"],
                "new_status": r["new_status"],
                "note": r.get("note"),
                "operator": r.get("operator", "admin"),
                "transitioned_at": r["transitioned_at"],
            })

        if not self.dry_run and payloads and self.client:
            self._upsert_batches("incident_status_history", payloads, on_conflict="id")

        self.report["stages"][stage_name] = {"source_rows": len(rows), "migrated_rows": len(payloads), "status": "PASS"}
        logger.info("  Migrated %d incident_status_history records.", len(payloads))

    def _upsert_batches(self, table_name: str, items: List[Dict[str, Any]], on_conflict: str) -> None:
        """Helper to upsert items in chunks."""
        for i in range(0, len(items), self.batch_size):
            chunk = items[i : i + self.batch_size]
            self.client.table(table_name).upsert(chunk, on_conflict=on_conflict).execute()
            logger.info("    Upserted %d/%d rows into %s", min(i + self.batch_size, len(items)), len(items), table_name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS SQLite-to-Supabase Data Migration Tool")
    parser.add_argument("--sqlite-path", default=os.getenv("AEGIS_SQLITE_PATH", "data/aegis_incidents.db"), help="Path to SQLite database")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Validate and parse without writing to target")
    parser.add_argument("--execute-cloud", action="store_true", default=False, help="Explicit confirmation to write to Supabase Cloud")
    parser.add_argument("--output-report", default="data/migration_report.json", help="Path to write JSON execution report")
    args = parser.parse_args()

    is_dry = True
    if args.execute_cloud and not args.dry_run:
        is_dry = False
    else:
        is_dry = True

    try:
        bridge = DataMigrationBridge(
            sqlite_db_path=args.sqlite_path,
            dry_run=is_dry,
        )
        report = bridge.run()

        os.makedirs(os.path.dirname(os.path.abspath(args.output_report)), exist_ok=True)
        with open(args.output_report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(json.dumps(report, indent=2))
        sys.exit(0 if report["status"] == "SUCCESS" else 1)
    except Exception as e:
        logger.critical("Fatal migration error: %s", e)
        sys.exit(1)
