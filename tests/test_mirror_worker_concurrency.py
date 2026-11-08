import os
import sys
import tempfile
import threading
import sqlite3
import pytest
from unittest.mock import MagicMock

# Add root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis_backend.sqlite_storage import SqliteIncidentStore
from aegis_backend.repository import SupabaseRepository


def create_temp_sqlite():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    store = SqliteIncidentStore(path)
    return store, path


def test_concurrent_mirror_replay_no_race_condition():
    """
    Test 1: Concurrency Safety
    Two threads invoke replay_failed_mirrors simultaneously.
    Verifies that idempotency, threading locks, and ON CONFLICT handling prevent duplicates.
    """
    store, db_path = create_temp_sqlite()
    try:
        # Mock SupabaseRepository
        mock_client = MagicMock()
        repo = SupabaseRepository(client=mock_client)
        repo.sqlite_store = store

        # Seed 5 failed/pending mirror records in SQLite
        for i in range(5):
            store.log_mirror_attempt(
                entity_type="incident",
                entity_id=f"INC-CONC-{i}",
                action="upsert",
                status="pending_retry",
                retry_count=3,
                error_message="Simulated initial failure",
            )

        # Mock Cloud returning fresh incident data
        def mock_get_inc(inc_id):
            return {
                "id": inc_id,
                "host_id": "host-fenn-ubuntu",
                "title": f"Incident {inc_id}",
                "severity": "high",
                "status": "open",
                "risk_score": 75,
                "risk_level": "high",
                "created_at": "2026-11-08T08:00:00Z",
                "alert_ids": ["ALT-01"],
                "risk_factors": [{"factor_id": "F1", "factor_name": "Test", "points": 20, "category": "auth"}],
            }

        repo.get_incident_by_id = MagicMock(side_effect=mock_get_inc)

        # Run replay_failed_mirrors concurrently from two threads
        results = []

        def worker():
            res = repo.replay_failed_mirrors()
            results.append(res)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Verify SQLite state
        stats = store.get_mirror_sync_stats()
        assert stats["pending_retry"] == 0
        assert stats["failed"] == 0
        assert stats["synced"] == 5

        # Verify no duplicate incidents created
        items, total_count = store.list_incidents()
        assert total_count == 5, f"Expected exactly 5 unique incidents, got {total_count}"
        assert len(items) == 5

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_sqlite_failure_does_not_create_false_synced_status():
    """
    Test 2: Failure Resilience & False-Sync Prevention
    If SQLite fails during replay, the status MUST NOT become 'synced'.
    """
    store, db_path = create_temp_sqlite()
    try:
        mock_client = MagicMock()
        repo = SupabaseRepository(client=mock_client)
        repo.sqlite_store = store

        store.log_mirror_attempt(
            entity_type="incident",
            entity_id="INC-FAIL-01",
            action="upsert",
            status="pending_retry",
            retry_count=3,
            error_message="Network glitch",
        )

        # Make upsert_incident raise an OperationalError (e.g. disk I/O error)
        repo.get_incident_by_id = MagicMock(return_value={"id": "INC-FAIL-01", "host_id": "host-fenn-ubuntu", "title": "Test", "severity": "high"})
        store.upsert_incident = MagicMock(side_effect=sqlite3.OperationalError("disk I/O error"))

        res = repo.replay_failed_mirrors()

        # Must report still_failed = 1, replayed = 0
        assert res["replayed"] == 0
        assert res["still_failed"] == 1

        # Status in DB must NOT be 'synced'
        with store._connection() as conn:
            cur = conn.execute("SELECT status FROM mirror_sync_log WHERE entity_id = 'INC-FAIL-01';")
            status = cur.fetchone()[0]
            assert status == "pending_retry", f"Status must remain pending_retry, got {status}"

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_restart_recovery_processes_pending_items():
    """
    Test 3: Restart Catch-up
    Pending items from a previous process run are recovered on startup.
    """
    store, db_path = create_temp_sqlite()
    try:
        # Simulate 3 items left pending before restart
        for i in range(3):
            store.log_mirror_attempt(
                entity_type="incident",
                entity_id=f"INC-RESTART-{i}",
                action="upsert",
                status="pending_retry",
                retry_count=3,
            )

        # Simulate fresh process start
        mock_client = MagicMock()
        repo = SupabaseRepository(client=mock_client)
        repo.sqlite_store = store
        repo.get_incident_by_id = MagicMock(return_value={
            "id": "INC-RESTART",
            "host_id": "host-fenn-ubuntu",
            "title": "Recovered",
            "severity": "medium",
            "status": "investigating",
            "risk_score": 55,
            "created_at": "2026-11-08T08:00:00Z",
        })

        res = repo.replay_failed_mirrors()
        assert res["total_checked"] == 3
        assert res["replayed"] == 3
        assert res["still_failed"] == 0

        stats = store.get_mirror_sync_stats()
        assert stats["pending_retry"] == 0
        assert stats["synced"] == 3

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_mirror_replay_never_mutates_cloud():
    """
    Test 4: Strict Flow Direction (Cloud -> SQLite Only)
    Verifies that replay_failed_mirrors NEVER calls insert, update, or delete on Cloud client.
    """
    store, db_path = create_temp_sqlite()
    try:
        mock_client = MagicMock()
        repo = SupabaseRepository(client=mock_client)
        repo.sqlite_store = store

        store.log_mirror_attempt(
            entity_type="incident",
            entity_id="INC-SSOT-01",
            action="upsert",
            status="pending_retry",
        )

        repo.get_incident_by_id = MagicMock(return_value={
            "id": "INC-SSOT-01",
            "host_id": "host-fenn-ubuntu",
            "title": "SSoT Safe",
            "severity": "low",
            "status": "resolved",
            "created_at": "2026-11-08T08:00:00Z",
        })

        repo.replay_failed_mirrors()

        # Ensure mock_client.table was never called with mutating operations
        for call in mock_client.table.mock_calls:
            method_name = str(call)
            assert "insert" not in method_name
            assert "update" not in method_name
            assert "delete" not in method_name
            assert "upsert" not in method_name

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


if __name__ == "__main__":
    pytest.main(["-v", __file__])
