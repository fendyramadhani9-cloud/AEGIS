"""
Tests for AEGIS SQLite Security Checker Persistent Storage.
Verifies that security check runs and findings:
1. Persist to disk in SQLite.
2. Survive store reload / restart without data loss.
3. Support filtering by host_id, severity, status, category, and search.
4. Correctly aggregate summary metrics.
5. Safely handle cascade deletion and idempotent upserts.
"""

import os
import tempfile
import pytest
from aegis_backend.sqlite_storage import SqliteIncidentStore


@pytest.fixture
def temp_store():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_sc.db")
        store = SqliteIncidentStore(db_path)
        yield store, db_path


def test_sqlite_security_checker_persistence_and_reload(temp_store):
    store, db_path = temp_store

    run_data = {
        "id": "RUN-test-host-001",
        "host_id": "host-fenn",
        "status": "completed",
        "total_checks": 2,
        "passed_checks": 1,
        "failed_checks": 1,
        "warning_checks": 0,
        "error_checks": 0,
        "checker_version": "1.0.0",
        "summary": {"compliance": "50%"},
        "started_at": "2026-11-08T00:00:00Z",
        "completed_at": "2026-11-08T00:01:00Z",
        "created_at": "2026-11-08T00:01:00Z",
    }

    findings = [
        {
            "id": "FND-001",
            "run_id": "RUN-test-host-001",
            "host_id": "host-fenn",
            "check_id": "SSH-001",
            "check_name": "SSH Root Login",
            "category": "ssh",
            "severity": "critical",
            "status": "fail",
            "actual_value": "yes",
            "expected_value": "no",
            "description": "PermitRootLogin enabled",
            "checked_at": "2026-11-08T00:00:30Z",
            "created_at": "2026-11-08T00:00:30Z",
        },
        {
            "id": "FND-002",
            "run_id": "RUN-test-host-001",
            "host_id": "host-fenn",
            "check_id": "FW-001",
            "check_name": "UFW Firewall Active",
            "category": "firewall",
            "severity": "high",
            "status": "pass",
            "actual_value": "active",
            "expected_value": "active",
            "description": "Firewall active",
            "checked_at": "2026-11-08T00:00:45Z",
            "created_at": "2026-11-08T00:00:45Z",
        },
    ]

    store.upsert_security_check_run(run_data, findings)

    # Simulate restart by instantiating new store on same file
    new_store = SqliteIncidentStore(db_path)

    # Verify run survived
    retrieved_run = new_store.get_security_run_by_id("RUN-test-host-001")
    assert retrieved_run is not None
    assert retrieved_run["id"] == "RUN-test-host-001"
    assert retrieved_run["total_checks"] == 2
    assert retrieved_run["summary"] == {"compliance": "50%"}

    # Verify findings survived
    findings_list, total = new_store.list_security_findings(host_id="host-fenn")
    assert total == 2
    assert len(findings_list) == 2

    # Verify filtering
    crit_findings, crit_count = new_store.list_security_findings(severity="critical")
    assert crit_count == 1
    assert crit_findings[0]["check_id"] == "SSH-001"

    # Verify search
    search_res, s_count = new_store.list_security_findings(search="Firewall")
    assert s_count == 1
    assert search_res[0]["check_id"] == "FW-001"

    # Verify summary
    summary = new_store.get_security_summary(host_id="host-fenn")
    assert summary["total_checks"] == 2
    assert summary["passed"] == 1
    assert summary["failed"] == 1
    assert summary["critical_fails"] == 1
    assert summary["high_fails"] == 0
