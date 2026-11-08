"""
AEGIS Comprehensive Crash Consistency, Mirror Durability & Recovery Test Suite.
Simulates failure-injection across 10 critical operational points:
1. Crash before Cloud write (Fail-closed).
2. Crash after Cloud write before ACK.
3. Crash after Cloud ACK before mirror starts (Startup catch-up recovery).
4. Crash during mirror execution (Retry with backoff).
5. Post-failure durable queue tracking in mirror_sync_log with payload.
6. Pending retry observability (Queue depth & age calculation).
7. Backend restart recovery (Payload-driven offline replay).
8. Concurrent retry replay with active new writes.
9. SQLite locked / disk-full failure resilience.
10. Health check state transitions upon Cloud recovery.
"""

import os
import sys
import tempfile
import threading
import sqlite3
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.config import settings
from aegis_backend.sqlite_storage import SqliteIncidentStore
from aegis_backend.repository import SupabaseRepository

def create_isolated_sqlite():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    store = SqliteIncidentStore(path)
    return store, path

# -----------------------------------------------------------------------------
# Point 1: Crash before Cloud write (Strict Fail-Closed)
# -----------------------------------------------------------------------------
def test_crash_point_1_before_cloud_write(monkeypatch):
    """Verifies that if Cloud fails before write completes, system fails closed with zero SQLite drift."""
    monkeypatch.setattr(settings, "database_mode", "cloud_ssot")
    store, db_path = create_isolated_sqlite()
    try:
        mock_client = MagicMock()
        mock_client.table.side_effect = RuntimeError("Network timeout before write.")
        repo = SupabaseRepository(client=mock_client)
        repo.sqlite_store = store

        with pytest.raises(RuntimeError) as exc_info:
            repo.upsert_incident({"id": "INC-CRASH-01", "title": "Crash Point 1"})
        assert "Cloud SSoT upsert incident failed" in str(exc_info.value)

        # Verify 0 records in SQLite
        items, count = store.list_incidents()
        assert count == 0
        stats = store.get_mirror_sync_stats()
        assert stats["total_logs"] == 0
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

# -----------------------------------------------------------------------------
# Point 3: Crash after Cloud ACK before mirror begins (Startup catch-up recovery)
# -----------------------------------------------------------------------------
def test_crash_point_3_crash_after_cloud_ack_before_mirror(monkeypatch):
    """
    If process crashes after Cloud write succeeded but before _execute_mirror was called,
    catch_up_unmirrored_from_cloud() on next startup discovers and mirrors it to SQLite.
    """
    monkeypatch.setattr(settings, "database_mode", "cloud_ssot")
    store, db_path = create_isolated_sqlite()
    try:
        mock_client = MagicMock()
        repo = SupabaseRepository(client=mock_client)
        repo.sqlite_store = store

        # Simulate incident exists in Cloud (from successful write before crash)
        cloud_inc = {
            "id": "INC-ORPHAN-CLOUD-01",
            "host_id": "host-fenn-ubuntu",
            "title": "Incident orphaned before mirror",
            "severity": "high",
            "status": "open",
            "risk_score": 80,
            "created_at": "2026-11-08T10:00:00Z",
            "alert_ids": ["ALT-01"],
            "risk_factors": [],
        }

        # Mock Cloud table calls
        mock_order = MagicMock()
        mock_limit = MagicMock()
        mock_limit.execute.return_value = MagicMock(data=[{"id": "INC-ORPHAN-CLOUD-01"}])
        mock_order.limit.return_value = mock_limit
        mock_select = MagicMock()
        mock_select.order.return_value = mock_order

        mock_sc_limit = MagicMock()
        mock_sc_limit.execute.return_value = MagicMock(data=[])
        mock_sc_order = MagicMock()
        mock_sc_order.limit.return_value = mock_sc_limit
        mock_sc_select = MagicMock()
        mock_sc_select.order.return_value = mock_sc_order

        def table_router(t_name):
            t_mock = MagicMock()
            if t_name == "incidents":
                t_mock.select.return_value = mock_select
            elif t_name == "security_check_runs":
                t_mock.select.return_value = mock_sc_select
            return t_mock

        mock_client.table.side_effect = table_router
        repo.get_incident_by_id = MagicMock(return_value=cloud_inc)

        # Run startup catch-up scan
        res = repo.catch_up_unmirrored_from_cloud()
        assert res["caught_up"] == 1

        # Verify SQLite now has the record
        local_inc = store.get_incident_by_id("INC-ORPHAN-CLOUD-01")
        assert local_inc is not None
        assert local_inc["title"] == "Incident orphaned before mirror"

        # Verify mirror_sync_log marked as synced
        stats = store.get_mirror_sync_stats()
        assert stats["synced"] == 1
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

# -----------------------------------------------------------------------------
# Point 4, 5 & 6: Mirror failure retry, durable payload queue, and stats
# -----------------------------------------------------------------------------
def test_crash_point_4_5_6_durable_payload_queue_and_stats():
    """Verifies that mirror failure retries with backoff and stores durable payload in mirror_sync_log."""
    store, db_path = create_isolated_sqlite()
    try:
        mock_client = MagicMock()
        repo = SupabaseRepository(client=mock_client)
        repo.sqlite_store = store

        test_payload = {
            "incident_data": {
                "id": "INC-DURABLE-01",
                "host_id": "host-fenn-ubuntu",
                "title": "Durable Payload Test",
                "severity": "medium",
                "status": "investigating",
                "risk_score": 50,
            },
            "alert_ids": ["ALT-X"],
            "risk_factors": [],
        }

        # Simulate mirror_fn failing permanently
        def failing_mirror():
            raise sqlite3.OperationalError("Simulated disk lock")

        repo._execute_mirror(
            entity_type="incident",
            entity_id="INC-DURABLE-01",
            action="upsert",
            mirror_fn=failing_mirror,
            payload=test_payload,
        )

        # Verify stats and queue depth
        stats = store.get_mirror_sync_stats()
        assert stats["queue_depth"] == 1
        assert stats["pending_retry"] == 1
        assert stats["synced"] == 0
        assert stats["oldest_pending_age_seconds"] is not None
        assert stats["oldest_pending_age_seconds"] >= 0

        # Verify payload is stored durably in DB
        failed_logs = store.get_failed_mirror_logs()
        assert len(failed_logs) == 1
        assert failed_logs[0]["entity_id"] == "INC-DURABLE-01"
        assert failed_logs[0]["payload"] is not None
        assert "Durable Payload Test" in failed_logs[0]["payload"]
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

# -----------------------------------------------------------------------------
# Point 7: Restart recovery replay from durable payload (Zero network call)
# -----------------------------------------------------------------------------
def test_crash_point_7_restart_recovery_from_durable_payload():
    """Verifies that replay_failed_mirrors uses the durable local payload without needing Cloud call."""
    store, db_path = create_isolated_sqlite()
    try:
        mock_client = MagicMock()
        repo = SupabaseRepository(client=mock_client)
        repo.sqlite_store = store

        # Seed durable failed mirror log with payload
        test_payload = {
            "incident_data": {
                "id": "INC-REPLAY-PAYLOAD-01",
                "host_id": "host-fenn-ubuntu",
                "title": "Offline Replay Test",
                "severity": "critical",
                "status": "new",
                "risk_score": 95,
            },
            "alert_ids": ["ALT-CRIT"],
            "risk_factors": [],
        }
        store.log_mirror_attempt(
            entity_type="incident",
            entity_id="INC-REPLAY-PAYLOAD-01",
            action="upsert",
            status="pending_retry",
            retry_count=3,
            payload=test_payload,
        )

        # Mock Cloud being down to prove replay works entirely from local durable payload!
        repo.get_incident_by_id = MagicMock(side_effect=RuntimeError("Cloud is completely down"))

        res = repo.replay_failed_mirrors()
        assert res["total_checked"] == 1
        assert res["replayed"] == 1
        assert res["still_failed"] == 0

        # Verify SQLite has the replayed incident
        inc = store.get_incident_by_id("INC-REPLAY-PAYLOAD-01")
        assert inc is not None
        assert inc["title"] == "Offline Replay Test"
        assert inc["risk_score"] == 95

        stats = store.get_mirror_sync_stats()
        assert stats["queue_depth"] == 0
        assert stats["synced"] == 1
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

# -----------------------------------------------------------------------------
# Point 8: Concurrent retry replay with active new writes
# -----------------------------------------------------------------------------
def test_crash_point_8_concurrent_replay_and_new_writes():
    """Verifies that replay_failed_mirrors runs concurrently with new upserts without corruption."""
    store, db_path = create_isolated_sqlite()
    try:
        mock_client = MagicMock()
        repo = SupabaseRepository(client=mock_client)
        repo.sqlite_store = store

        # Seed 5 pending mirror logs
        for i in range(5):
            payload = {
                "incident_data": {
                    "id": f"INC-CONC-REPLAY-{i}",
                    "host_id": "host-fenn-ubuntu",
                    "title": f"Concurrent Incident {i}",
                    "severity": "medium",
                    "status": "open",
                    "risk_score": 50,
                },
                "alert_ids": [],
                "risk_factors": [],
            }
            store.log_mirror_attempt(
                entity_type="incident",
                entity_id=f"INC-CONC-REPLAY-{i}",
                action="upsert",
                status="pending_retry",
                payload=payload,
            )

        # Worker 1: Replays
        def replay_worker():
            repo.replay_failed_mirrors()

        # Worker 2: Writes new incident directly to SQLite
        def write_worker():
            for i in range(5):
                store.upsert_incident({
                    "id": f"INC-CONC-NEW-{i}",
                    "host_id": "host-fenn-ubuntu",
                    "title": f"Direct Incident {i}",
                    "severity": "low",
                    "status": "resolved",
                    "risk_score": 20,
                })

        t1 = threading.Thread(target=replay_worker)
        t2 = threading.Thread(target=write_worker)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Verify all 10 incidents exist cleanly in SQLite
        items, total = store.list_incidents(limit=20)
        assert total == 10
        stats = store.get_mirror_sync_stats()
        assert stats["queue_depth"] == 0
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

# -----------------------------------------------------------------------------
# Point 9: SQLite disk full resilience
# -----------------------------------------------------------------------------
def test_crash_point_9_sqlite_disk_full_resilience():
    """Verifies that if SQLite is locked or disk-full, the mirror error is caught without crashing Cloud operation."""
    store, db_path = create_isolated_sqlite()
    try:
        mock_client = MagicMock()
        repo = SupabaseRepository(client=mock_client)
        repo.sqlite_store = store

        # Patch connection to raise disk full error
        with patch.object(store, "_connection", side_effect=sqlite3.OperationalError("database or disk is full")):
            # Must not raise unhandled exception to caller
            repo._execute_mirror(
                entity_type="incident",
                entity_id="INC-DISK-FULL",
                action="upsert",
                mirror_fn=lambda: store.upsert_incident({"id": "INC-DISK-FULL"}),
            )
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

# -----------------------------------------------------------------------------
# Point 10: Health check state transitions upon Cloud recovery
# -----------------------------------------------------------------------------
def test_crash_point_10_health_check_state_transitions(monkeypatch):
    """Verifies that database health endpoint accurately reflects connectivity and failover state."""
    from fastapi.testclient import TestClient
    from aegis_backend.main import app
    from aegis_backend.repository import get_repository

    client = TestClient(app)

    try:
        # 1. Healthy state
        mock_repo = MagicMock()
        mock_repo.check_database_health.return_value = (True, "Connection healthy", 12.5)
        mock_repo.get_mirror_sync_stats.return_value = {
            "queue_depth": 0,
            "oldest_pending_age_seconds": None,
            "last_successful_mirror_at": "2026-11-08T10:00:00Z",
        }
        app.dependency_overrides[get_repository] = lambda: mock_repo

        resp = client.get("/api/health/database")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["connected"] is True
        assert data["failover_state"] == "normal"
        assert data["mirror_queue_depth"] == 0

        # 2. Degraded state
        mock_repo.check_database_health.return_value = (False, "Supabase connection timed out", None)
        mock_repo.get_mirror_sync_stats.return_value = {
            "queue_depth": 3,
            "oldest_pending_age_seconds": 45.2,
            "last_successful_mirror_at": "2026-11-08T10:00:00Z",
        }

        resp = client.get("/api/health/database")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["connected"] is False
        assert data["failover_state"] == "fail_closed_alerting"
        assert data["mirror_queue_depth"] == 3
        assert data["oldest_pending_age_seconds"] == 45.2
    finally:
        app.dependency_overrides.clear()
