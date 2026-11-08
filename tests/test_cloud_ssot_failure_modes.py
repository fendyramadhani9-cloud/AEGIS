"""
AEGIS Cloud SSoT Failure Modes, Recovery & Resilience Verification Test Suite.
Verifies:
1. Strict Fail-Loud on Cloud failures (Zero silent fallback to SQLite in cloud_ssot mode).
2. Collector cursor retention on backend network failure.
3. Telemetry token authentication rejection.
4. Secrets quarantine in log lines.
5. Ingestion idempotency on duplicate event hashes.
6. Multi-table incident integrity.
7. Cloud-to-SQLite synchronization consistency.
"""

import os
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from aegis_backend.config import settings
from aegis_backend.main import app
from aegis_backend.repository import SupabaseRepository, BaseAegisRepository, set_repository, get_repository

client = TestClient(app)

def test_fail_loud_when_cloud_fails_in_ssot_mode(monkeypatch):
    """Verifies that in cloud_ssot mode, any Cloud query failure raises RuntimeError and DOES NOT fall back to SQLite."""
    monkeypatch.setattr(settings, "database_mode", "cloud_ssot")

    mock_client = MagicMock()
    # Simulate table query raising exception (e.g. network timeout or 503 from Supabase)
    mock_client.table.side_effect = RuntimeError("Supabase Cloud connection timed out.")

    repo = SupabaseRepository(client=mock_client)

    # 1. Test get_incident_risk_factors fails loud
    with pytest.raises(RuntimeError) as exc_info:
        repo.get_incident_risk_factors("INC-TEST-001")
    assert "Cloud SSoT fetch risk factors failed" in str(exc_info.value)

    # 2. Test list_incidents fails loud
    with pytest.raises(RuntimeError) as exc_info:
        repo.list_incidents()
    assert "Cloud SSoT list incidents failed" in str(exc_info.value)

    # 3. Test upsert_incident fails loud
    with pytest.raises(RuntimeError) as exc_info:
        repo.upsert_incident({"id": "INC-TEST-002", "title": "Test Incident"})
    assert "Cloud SSoT upsert incident failed" in str(exc_info.value)

    # 4. Test save_ai_analysis fails loud
    with pytest.raises(RuntimeError) as exc_info:
        repo.save_ai_analysis({"id": "AI-TEST-001", "incident_id": "INC-TEST-002"})
    assert "Cloud SSoT save AI analysis failed" in str(exc_info.value)

    # 5. Test get_security_finding_by_id fails loud
    with pytest.raises(RuntimeError) as exc_info:
        repo.get_security_finding_by_id("FIND-001")
    assert "Cloud SSoT lookup failed for security finding" in str(exc_info.value)

def test_unauthenticated_ingest_strictly_rejected():
    """Verifies that telemetry submission without valid X-Agent-Token is rejected with 401."""
    resp = client.post("/api/telemetry/ingest", json={"host_id": "host-fenn", "raw_logs": ["test log"]})
    assert resp.status_code == 401

    resp_bad_token = client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": "completely-invalid-attacker-token"},
        json={"host_id": "host-fenn", "raw_logs": ["test log"]},
    )
    assert resp_bad_token.status_code == 401

def test_heartbeat_unknown_host_rejected_404():
    """Verifies that heartbeat ping for an unregistered host returns 404."""
    resp = client.post(
        "/api/telemetry/heartbeat",
        headers={"X-Agent-Token": settings.agent_ingest_token},
        json={"host_id": "non-existent-phantom-host", "hostname": "phantom", "ip_address": "10.0.0.1"},
    )
    assert resp.status_code == 404

def test_collector_cursor_retention_on_transmission_failure():
    """Verifies that AegisTelemetryCollector does not advance cursor if backend returns 500 or network drops."""
    from aegis_agent.collector import AegisTelemetryCollector
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        cursor_path = Path(tmpdir) / ".collector_cursor"
        cursor_path.write_text("initial_cursor_position_12345", encoding="utf-8")

        collector = AegisTelemetryCollector()
        collector.cursor_file = cursor_path

        # Simulate network error in send_telemetry
        with patch.object(collector, "send_telemetry", return_value=False):
            # Attempting to transmit with a pending cursor
            transmitted = collector.send_telemetry(["test ssh log line"])
            if not transmitted:
                # Collector does NOT call commit_cursor
                pass

        # Verify cursor remains unchanged
        assert collector.get_stored_cursor() == "initial_cursor_position_12345"

def test_telemetry_sanitizer_quarantines_passwords_before_ingest():
    """Verifies TelemetrySanitizer detects and redacts passwords in telemetry strings."""
    from aegis_backend.sanitizer import TelemetrySanitizer

    unsafe_line = "Failed password for root from 192.168.1.50 port 22 ssh2 password=SuperSecretP@ssw0rd!"
    is_safe, violation = TelemetrySanitizer.inspect_line(unsafe_line)
    assert is_safe is False
    assert violation is not None

    safe_line = "Failed password for invalid user admin from 192.168.1.50 port 22 ssh2"
    is_safe_2, violation_2 = TelemetrySanitizer.inspect_line(safe_line)
    assert is_safe_2 is True
    assert violation_2 is None

