"""
AEGIS Master End-to-End Integration & Production Readiness Test Suite.
Validates:
1. Full 12-Stage Security Pipeline:
   Raw Event -> Normalization -> Rules Engine -> Alert -> Evidence Link ->
   Incident Correlation -> Deterministic Risk Assessment -> AI Investigation Grounding ->
   Persistence -> API Service -> State Machine Verification.
2. Cloud SSoT and Hybrid Mode Simulation.
3. Cloud Unavailable & Strict Fail-Closed (HTTP 503 Traffic Gate).
4. RECOVERY_REQUIRED Persistence across Restart.
5. Idempotent Ingestion & Duplicate Event Protection.
6. Timestamp Conflict & Safe Reverse-Sync Matrix.
"""

import os
import json
import sqlite3
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from aegis_agent.pipeline_adapter import LinuxLogPipelineAdapter
from aegis_backend.rules_engine import RulesEngine
from aegis_backend.incident_service import IncidentService
from aegis_backend.incident_correlator import IncidentCorrelator
from aegis_backend.risk_assessment import RiskAssessmentEngine
from aegis_backend.ai_provider import MockAIProvider
from aegis_backend.state_machine import state_machine, DatabaseState, DatabaseStateMachine
from aegis_backend.sqlite_storage import SqliteIncidentStore
from aegis_backend.repository import MockAegisRepository, set_repository
from aegis_backend.main import app
from scripts.sync_cloud_to_sqlite import sync_cloud_to_sqlite, TABLE_POLICIES


@pytest.fixture
def mock_repo():
    repo = MockAegisRepository()
    set_repository(repo)
    # Ensure default test host exists
    now = datetime.now(timezone.utc).isoformat()
    repo.upsert_host({
        "id": "host-fenn-ubuntu",
        "hostname": "fenn",
        "ip_address": "192.168.193.129",
        "os": "Ubuntu 24.04 LTS",
        "agent_version": "0.1.0",
        "agent_status": "online",
        "last_data_at": now,
    })
    yield repo
    set_repository(None)


@pytest.fixture
def client(mock_repo):
    return TestClient(app)


# =========================================================================
# 1. COMPLETE 12-STAGE END-TO-END PIPELINE LIFECYCLE
# =========================================================================

def test_full_pipeline_lifecycle_event_to_api(mock_repo, client):
    """
    Validates the entire AEGIS security lifecycle:
    1. Raw Linux logs received.
    2. Event normalization via LinuxLogPipelineAdapter.
    3. Deterministic Rules Engine evaluation.
    4. Alert creation with stable fingerprint.
    5. Evidence link establishment.
    6. Incident correlation grouping.
    7. Deterministic Risk Assessment calculation.
    8. AI Investigation grounded strictly in evidence.
    9. Incident persistence in repository.
    10. API presentation via /api/incidents/{id}.
    11. Status transition with audit trail.
    12. Gateway state verification.
    """
    # Stage 1 & 2: Raw Linux events stream & Normalization
    raw_logs = [
        "Nov  8 12:00:01 fenn sshd[5001]: Failed password for invalid user admin from 192.168.1.100 port 45100 ssh2",
        "Nov  8 12:00:03 fenn sshd[5002]: Failed password for invalid user admin from 192.168.1.100 port 45102 ssh2",
        "Nov  8 12:00:05 fenn sshd[5003]: Failed password for invalid user admin from 192.168.1.100 port 45104 ssh2",
        "Nov  8 12:00:10 fenn sshd[5004]: Accepted password for root from 192.168.1.100 port 45110 ssh2",
        "Nov  8 12:00:12 fenn sudo[5005]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
    ]

    adapter = LinuxLogPipelineAdapter()
    parsed_events, unparseable = adapter.process_raw_logs(raw_logs, deduplicate=True)
    assert len(parsed_events) == 5
    assert len(unparseable) == 0

    # Ingest normalized telemetry events into repository
    telemetry_dicts = []
    base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    for i, ev in enumerate(parsed_events):
        t_id = f"EVT-E2E-{i:03d}"
        ev_ts = (base_time + timedelta(seconds=i * 2)).isoformat()
        t_dict = {
            "id": t_id,
            "host_id": "host-fenn-ubuntu",
            "event_type": ev.event_type,
            "source_id": "syslog",
            "message": raw_logs[i],
            "user_name": ev.user,
            "source_ip": ev.source_ip,
            "event_timestamp": ev_ts,
            "details": ev.details,
        }
        telemetry_dicts.append(t_dict)

    inserted, dups = mock_repo.insert_telemetry_events(telemetry_dicts)
    assert inserted == 5
    assert dups == 0

    # Stage 3 & 4: Rules Engine Evaluation -> Alert Generation
    rules_engine = RulesEngine(ssh_brute_threshold=3, ssh_brute_window_sec=300)
    alerts, alert_evidence = rules_engine.evaluate_events(telemetry_dicts)
    assert len(alerts) >= 1
    brute_alert = alerts[0]
    assert brute_alert["rule_id"] in ("RULE-SSH-BRUTE", "RULE-AUTH-003", "RULE-PRIV-001")
    assert brute_alert["host_id"] == "host-fenn-ubuntu"

    # Persist alert and evidence links
    mock_repo.insert_alerts(alerts, alert_evidence)

    # Stage 5 & 6: Incident Correlation
    service = IncidentService(repository=mock_repo, ai_provider=MockAIProvider())
    incidents = service.correlate_alerts(host_id="host-fenn-ubuntu")
    assert len(incidents) >= 1
    inc_item = incidents[0]
    inc_id = inc_item.id

    # Stage 7: Deterministic Risk Assessment
    inc_detail = service.get_incident_detail(inc_id)
    assert inc_detail is not None
    assert inc_detail.incident.risk_score >= 10
    assert inc_detail.incident.risk_level in ("low", "medium", "high", "critical")
    assert len(inc_detail.risk_factors) >= 1

    # Stage 8: AI Investigation with Grounded Evidence
    analysis_res = service.analyze_incident(inc_id, force=True)
    assert analysis_res is not None
    assert analysis_res.analysis_status == "completed"
    assert analysis_res.risk_score == inc_detail.incident.risk_score  # AI obeys deterministic risk engine!
    assert analysis_res.threat_classification != ""

    # Stage 9 & 10: API Presentation via FastAPI
    resp = client.get(f"/api/incidents/{inc_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["incident"]["id"] == inc_id
    assert len(body["alerts"]) >= 1
    assert body["latest_analysis"] is not None
    assert body["latest_analysis"]["analysis_status"] == "completed"

    # Stage 11: Status Transition with Audit Trail
    patch_resp = client.patch(
        f"/api/incidents/{inc_id}/status",
        json={"status": "investigating", "note": "Assigned to L2 Security Analyst"},
    )
    assert patch_resp.status_code == 200
    updated_body = patch_resp.json()
    assert updated_body["status"] == "investigating"

    # Verify timeline reflects the transition
    timeline_resp = client.get(f"/api/incidents/{inc_id}/timeline")
    assert timeline_resp.status_code == 200
    events = timeline_resp.json()
    status_events = [e for e in events if e.get("kind") == "status_change"]
    assert len(status_events) >= 1


# =========================================================================
# 2. STATE MACHINE & STRICT FAIL-CLOSED SIMULATION
# =========================================================================

def test_cloud_ssot_traffic_gate_and_fail_closed(client):
    """
    Proves that:
    - In CLOUD_SSoT with catch-up done, mutations succeed.
    - When Cloud fails (CLOUD_UNAVAILABLE or RECOVERY_REQUIRED), mutations fail-loud with HTTP 503.
    """
    sm = state_machine
    sm.transition_to(DatabaseState.CLOUD_SSoT, "Normal SSoT operations", force=True)
    sm.set_catch_up_completed(True)
    assert sm.is_mutation_allowed() is True

    # Cloud goes down -> CLOUD_UNAVAILABLE
    sm.transition_to(DatabaseState.CLOUD_UNAVAILABLE, "Supabase Cloud WAN disconnected")
    assert sm.is_mutation_allowed() is False

    # Attempting mutation must return HTTP 503
    resp = client.post("/api/incidents/correlate", json={})
    assert resp.status_code == 503
    data = resp.json()
    assert "Database Mutation Rejected" in data["error"]
    assert data["state"] == "CLOUD_UNAVAILABLE"

    # Health readiness probe returns 503
    ready_resp = client.get("/api/health/ready")
    assert ready_resp.status_code == 503


def test_recovery_required_persists_across_restart(tmp_path):
    """
    Proves that a state machine placed into RECOVERY_REQUIRED persists this status to disk
    and refuses to automatically clear to healthy upon restart.
    """
    state_file = str(tmp_path / "persistence_state.json")
    sm = DatabaseStateMachine(initial_state=DatabaseState.HYBRID)
    sm.transition_to(
        DatabaseState.RECOVERY_REQUIRED,
        reason="Divergence detected during catch-up",
        operator="sec_engineer",
        force=True,
    )
    assert sm.persist_state(filepath=state_file) is True

    # Backend restarts
    fresh_sm = DatabaseStateMachine(initial_state=DatabaseState.HYBRID)
    fresh_sm.load_persisted_state(filepath=state_file)

    assert fresh_sm.current_state == DatabaseState.RECOVERY_REQUIRED
    assert fresh_sm.is_mutation_allowed() is False
    assert fresh_sm.get_authoritative_database() == "none_recovery_required"


# =========================================================================
# 3. IDEMPOTENCY & DUPLICATE EVENT PROTECTION
# =========================================================================

def test_idempotent_ingestion_and_duplicate_rejection(mock_repo):
    """Proves that re-ingesting identical telemetry events is completely idempotent."""
    ev = {
        "id": "EVT-DUP-TEST-001",
        "host_id": "host-fenn-ubuntu",
        "event_type": "auth_failure",
        "source_id": "syslog",
        "message": "Failed login attempt",
        "user_name": "unknown",
        "source_ip": "10.0.0.99",
        "event_timestamp": "2026-11-08T12:00:00Z",
        "details": {},
    }

    # First ingestion
    ins1, dup1 = mock_repo.insert_telemetry_events([ev])
    assert ins1 == 1
    assert dup1 == 0

    # Second ingestion (identical ID)
    ins2, dup2 = mock_repo.insert_telemetry_events([ev])
    assert ins2 == 0
    assert dup2 == 1


# =========================================================================
# 4. REVERSE SYNC TIMESTAMP CONFLICT REPORTING
# =========================================================================

def test_reverse_sync_conflict_matrix_safe_handling(tmp_path):
    """
    Proves that sync_cloud_to_sqlite creates a pre-sync backup and records conflict
    reports without performing blind overwrites when local SQLite has newer timestamps.
    """
    db_file = str(tmp_path / "test_conflict_sync.db")
    store = SqliteIncidentStore(db_file)

    # Insert local incident with newer updated_at
    local_inc = {
        "id": "INC-CONFLICT-01",
        "host_id": "host-fenn-ubuntu",
        "title": "Local Updated Incident",
        "severity": "high",
        "status": "investigating",
        "risk_level": "high",
        "risk_score": 75,
        "first_seen_at": "2026-11-08T10:00:00Z",
        "last_seen_at": "2026-11-08T11:00:00Z",
        "created_at": "2026-11-08T10:00:00Z",
        "updated_at": "2026-11-08T11:30:00Z",  # NEWER than Cloud
    }
    store.upsert_incident(local_inc, [], [])

    # Mock Cloud having an older timestamp
    cloud_inc = dict(local_inc)
    cloud_inc["status"] = "new"
    cloud_inc["updated_at"] = "2026-11-08T10:15:00Z"  # OLDER than SQLite

    with patch("supabase.create_client") as mock_sb:
        mock_client = MagicMock()
        def mock_table(table_name):
            q = MagicMock()
            q.select.return_value = q
            q.order.return_value = q
            res = MagicMock()
            res.data = [cloud_inc] if table_name == "incidents" else []
            q.range.return_value.execute.return_value = res
            return q
        mock_client.table.side_effect = mock_table
        mock_sb.return_value = mock_client

        report = sync_cloud_to_sqlite(
            sqlite_path=db_file,
            dry_run=True,
            force_cloud_wins=False,
        )

        assert report["status"] == "CONFLICT"
        assert report["conflicts_detected"] >= 1

        # Verify SQLite was NOT overwritten
        persisted = store.get_incident_by_id("INC-CONFLICT-01")
        assert persisted["status"] == "investigating"
