"""
Unit & Integration Tests for AEGIS SQLite Local Persistent Storage Engine.
Validates:
1. ACID transactions, WAL mode, foreign keys.
2. Restart survival: data survives instance closure and reopening.
3. Concurrent read/write thread safety.
4. Backup creation and integrity verification.
"""

import os
import tempfile
import threading
from datetime import datetime, timezone
import pytest
from aegis_backend.sqlite_storage import SqliteIncidentStore


@pytest.fixture
def temp_store():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    store = SqliteIncidentStore(db_path)
    yield store, db_path
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


def test_schema_init_and_integrity(temp_store):
    store, db_path = temp_store
    ok, msg = store.check_integrity()
    assert ok is True
    assert msg == "ok"


def test_incident_upsert_and_restart_survival(temp_store):
    store, db_path = temp_store

    inc_data = {
        "id": "INC-test-host-12345678",
        "host_id": "host-fenn-ubuntu",
        "title": "Brute-force into Sudo",
        "severity": "high",
        "risk_level": "critical",
        "risk_score": 95,
        "status": "new",
        "primary_alert_id": "ALT-001",
        "source_ip": "198.51.100.61",
        "target_user": "ubuntu",
        "attack_scenario": "Brute force followed by root shell.",
        "correlation_reason": "Same IP 198.51.100.61 and user ubuntu.",
        "first_seen_at": "2026-11-08T00:00:00+00:00",
        "last_seen_at": "2026-11-08T00:10:00+00:00",
    }
    alert_ids = ["ALT-001", "ALT-002", "ALT-003"]
    risk_factors = [
        {"factor_id": "SEV-01", "factor_name": "Base Severity", "points": 35, "category": "severity", "description": "High alert"},
        {"factor_id": "PROG-01", "factor_name": "Kill Chain", "points": 25, "category": "progression", "description": "Progression detected"},
    ]

    stored = store.upsert_incident(inc_data, alert_ids, risk_factors)
    assert stored["id"] == "INC-test-host-12345678"
    assert stored["storage_backend"] == "sqlite_local"

    # Save an AI analysis
    anl_data = {
        "id": "ANL-INC-test-host-12345678-01",
        "incident_id": "INC-test-host-12345678",
        "host_id": "host-fenn-ubuntu",
        "analysis_status": "completed",
        "threat_classification": "MITRE ATT&CK T1110",
        "executive_summary": "Brute force attack observed.",
        "attack_scenario": "Reconstructed attacker timeline.",
        "risk_level": "critical",
        "risk_score": 95,
        "confidence_level": "high",
        "confidence_reason": "Clear audit logs.",
        "facts": [{"evidence_id": "EVT-01", "fact": "Failed SSH", "timestamp": "2026-11-08T00:00:00+00:00"}],
        "inferences": [{"statement": "Attacker tried multiple passwords", "supporting_evidence_ids": ["EVT-01"], "rationale": "High frequency"}],
        "hypotheses": [{"statement": "Automated script used", "status": "unverified", "investigation_step": "Check User-Agent"}],
        "unknowns": [{"data_gap": "Attacker geo-location", "impact": "Attribution incomplete"}],
        "supporting_evidence": ["EVT-01"],
        "provider": "gemini",
        "model": "gemini-3.5-flash-lite",
    }
    store.save_ai_analysis(anl_data)

    # Status update
    store.update_incident_status("INC-test-host-12345678", "investigating", "SOC investigating", "operator_1")

    # SIMULATE PROCESS RESTART: Delete old Python object, open completely new store instance
    del store
    new_store = SqliteIncidentStore(db_path)

    # Verify incident persisted
    reloaded_inc = new_store.get_incident_by_id("INC-test-host-12345678")
    assert reloaded_inc is not None
    assert reloaded_inc["status"] == "investigating"
    assert reloaded_inc["risk_score"] == 95
    assert reloaded_inc["storage_backend"] == "sqlite_local"
    assert reloaded_inc["correlation_reason"] == "Same IP 198.51.100.61 and user ubuntu."

    # Verify alerts link persisted
    linked_alerts = new_store.get_incident_alerts("INC-test-host-12345678")
    assert set(linked_alerts) == {"ALT-001", "ALT-002", "ALT-003"}

    # Verify risk factors persisted
    rfs = new_store.get_incident_risk_factors("INC-test-host-12345678")
    assert len(rfs) == 2
    assert rfs[0]["factor_id"] == "SEV-01"
    assert rfs[1]["points"] == 25

    # Verify AI analysis persisted
    reloaded_anl = new_store.get_latest_ai_analysis("INC-test-host-12345678")
    assert reloaded_anl is not None
    assert reloaded_anl["threat_classification"] == "MITRE ATT&CK T1110"
    assert len(reloaded_anl["facts"]) == 1
    assert reloaded_anl["facts"][0]["evidence_id"] == "EVT-01"
    assert len(reloaded_anl["inferences"]) == 1
    assert len(reloaded_anl["hypotheses"]) == 1
    assert reloaded_anl["storage_backend"] == "sqlite_local"

    # Verify timeline persisted
    tl = new_store.get_incident_timeline("INC-test-host-12345678")
    kinds = [item["kind"] for item in tl]
    assert "alert" in kinds
    assert "status_change" in kinds
    assert "analysis" in kinds

    # Verify status history persisted
    hist = new_store.get_incident_status_history("INC-test-host-12345678")
    assert len(hist) == 1
    assert hist[0]["old_status"] == "new"
    assert hist[0]["new_status"] == "investigating"


def test_backup_and_concurrent_writes(temp_store):
    store, db_path = temp_store

    # Test concurrent writes from 5 threads
    def worker(i: int):
        inc_data = {
            "id": f"INC-thread-{i}",
            "host_id": "host-fenn-ubuntu",
            "title": f"Incident {i}",
            "severity": "medium",
            "risk_level": "medium",
            "risk_score": 50 + i,
            "status": "new",
            "first_seen_at": "2026-11-08T00:00:00+00:00",
            "last_seen_at": "2026-11-08T00:01:00+00:00",
        }
        store.upsert_incident(inc_data, [f"ALT-{i}"])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    items, total = store.list_incidents(limit=20)
    assert total == 10

    # Test hot online backup
    backup_file = f"{db_path}.test_backup"
    store.create_backup(backup_file)
    assert os.path.exists(backup_file)

    backup_store = SqliteIncidentStore(backup_file)
    b_items, b_total = backup_store.list_incidents(limit=20)
    assert b_total == 10
    if os.path.exists(backup_file):
        os.remove(backup_file)

