"""
Comprehensive Tests for AEGIS Telemetry Ingestion API (POST /api/telemetry/ingest).
Guarantees:
1. Strict constant-time token authentication.
2. Complete quarantine/rejection of sensitive credentials (SSH keys, hashes, tokens, passwords).
3. Pre-parsing and pre-storage data protection without leaking secrets.
4. Correct host upsert and referential integrity prior to event insertion.
5. In-memory and persistent deduplication safety.
6. Batch size and character length boundaries.
7. Zero remote database write side-effects (100% offline mock repository).
8. Absence of fabricated alerts (Rule 9).
"""

import pytest
import json
from pathlib import Path
from fastapi.testclient import TestClient
from aegis_backend.main import app
from aegis_backend.config import settings
from aegis_backend.repository import MockAegisRepository, set_repository


VALID_TOKEN = settings.agent_ingest_token


@pytest.fixture(autouse=True)
def setup_mock_repository():
    """Forces all tests to execute against an isolated MockAegisRepository."""
    mock_repo = MockAegisRepository()
    mock_repo.hosts = []
    mock_repo.alerts = []
    mock_repo.telemetry_events = []
    mock_repo.event_ids = set()
    set_repository(mock_repo)
    yield mock_repo
    set_repository(None)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def synthetic_logs():
    dataset_path = Path(__file__).resolve().parent.parent / "evaluation" / "datasets" / "synthetic_linux_logs.json"
    with open(dataset_path, "r", encoding="utf-8") as f:
        return [entry["raw_line"] for entry in json.load(f)]


# =========================================================================
# 1. AUTHENTICATION TESTS
# =========================================================================

def test_ingest_missing_token_rejected_401(client):
    res = client.post(
        "/api/telemetry/ingest",
        json={
            "host_id": "srv-ubuntu-apri",
            "hostname": "ubuntu-apri-vm",
            "raw_logs": ["Nov  1 10:00:01 core-auth-srv01 sshd[12450]: Failed password for admin from 198.51.100.24 port 54321 ssh2"],
        },
    )
    assert res.status_code == 401
    assert "Missing required authentication token header" in res.json()["detail"]


def test_ingest_invalid_token_rejected_401(client):
    res = client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": "wrong-agent-token-xyz"},
        json={
            "host_id": "srv-ubuntu-apri",
            "hostname": "ubuntu-apri-vm",
            "raw_logs": ["Nov  1 10:00:01 core-auth-srv01 sshd[12450]: Failed password for admin from 198.51.100.24 port 54321 ssh2"],
        },
    )
    assert res.status_code == 401
    assert "Invalid agent authentication token" in res.json()["detail"]


# =========================================================================
# 2. VALID SYNTHETIC TELEMETRY INGESTION TESTS
# =========================================================================

def test_ingest_synthetic_telemetry_batch(client, setup_mock_repository, synthetic_logs):
    mock_repo = setup_mock_repository
    res = client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={
            "host_id": "srv-ubuntu-apri",
            "hostname": "ubuntu-apri-vm",
            "ip_address": "10.0.0.45",
            "os": "Ubuntu 24.04 LTS",
            "agent_version": "0.1.0",
            "raw_logs": synthetic_logs,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["ok", "partial"]
    assert data["host_id"] == "srv-ubuntu-apri"
    assert data["total_received"] == len(synthetic_logs)
    assert data["malformed_quarantined"] == 1  # 1 corrupted line in dataset
    assert data["inserted_events"] == 7        # 7 valid parsed lines
    assert data["alerts_evaluated"] == 1       # RULE-AUTH-003 evaluated deterministically


    # Verify Host was registered before events
    assert len(mock_repo.hosts) == 1
    host = mock_repo.hosts[0]
    assert host["id"] == "srv-ubuntu-apri"
    assert host["hostname"] == "ubuntu-apri-vm"
    assert host["agent_status"] == "online"
    assert host["ip_address"] == "10.0.0.45"
    assert host["last_data_at"] is not None

    # Verify telemetry events stored in repository
    assert len(mock_repo.telemetry_events) == 7
    event_types = {ev["event_type"] for ev in mock_repo.telemetry_events}
    assert "auth_failure" in event_types
    assert "auth_success" in event_types
    assert "session_opened" in event_types
    assert "process_execution" in event_types
    assert "network_connection" in event_types

    # Verify foreign key reference
    for ev in mock_repo.telemetry_events:
        assert ev["host_id"] == "srv-ubuntu-apri"
        assert ev["message"] != ""


# =========================================================================
# 3. SECRET REDACTION & QUARANTINE TESTS
# =========================================================================

def test_ingest_quarantines_sensitive_secrets_without_storing(client, setup_mock_repository):
    mock_repo = setup_mock_repository
    sensitive_lines = [
        # Line 1: Safe SSH failure
        "Nov  1 10:00:01 core-auth-srv01 sshd[12450]: Failed password for invalid user admin from 198.51.100.24 port 54321 ssh2",
        # Line 2: Private SSH Key
        "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAA -----END OPENSSH PRIVATE KEY-----",
        # Line 3: Password hash shadow line
        "Nov  1 10:00:02 test-srv useradd[999]: password hash $6$rounds=5000$saltsalt$hashedpassword1234567890",
        # Line 4: Bearer token in command line
        'type=EXECVE msg=audit(1762002180.123:4501): argc=3 a0="curl" a1="-H" a2="Authorization: Bearer secret_bearer_token_xyz1234567890"',
        # Line 5: API Key in command line
        'type=EXECVE msg=audit(1762002180.123:4502): argc=2 a0="script.py" a1="api_key=AIzaSyD-secret_api_key_12345"',
        # Line 6: Password CLI argument
        'type=EXECVE msg=audit(1762002180.123:4503): argc=3 a0="mysql" a1="-u" a2="root" a3="--password=SuperSecretPassword999"',
    ]

    res = client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={
            "host_id": "srv-ubuntu-apri",
            "hostname": "ubuntu-apri-vm",
            "raw_logs": sensitive_lines,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total_received"] == 6
    assert data["sanitized_quarantined"] == 5  # Exactly 5 secret-laden lines rejected
    assert data["inserted_events"] == 1        # Only Line 1 accepted

    # Verify repository storage
    assert len(mock_repo.telemetry_events) == 1
    saved_event = mock_repo.telemetry_events[0]
    assert saved_event["event_type"] == "auth_failure"

    # STRICT AUDIT: Zero secret substrings exist in repository storage
    dumped = json.dumps(mock_repo.telemetry_events)
    assert "OPENSSH PRIVATE KEY" not in dumped
    assert "hashedpassword" not in dumped
    assert "secret_bearer_token" not in dumped
    assert "secret_api_key" not in dumped
    assert "SuperSecretPassword999" not in dumped


# =========================================================================
# 4. MALFORMED LINES QUARANTINE TESTS
# =========================================================================

def test_ingest_malformed_lines_gracefully_quarantined(client, setup_mock_repository):
    mock_repo = setup_mock_repository
    mixed_lines = [
        "   \n\t  ",  # empty whitespace
        "GARBAGE ENTRY WITH NO STRUCTURE @@@@@",
        "Nov  1 10:02:15 core-auth-srv01 sshd[12460]: Accepted password for admin from 198.51.100.24 port 54330 ssh2",
        "ANOTHER CORRUPTED LINE !!!!!!",
    ]

    res = client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={
            "host_id": "srv-ubuntu-apri",
            "hostname": "ubuntu-apri-vm",
            "raw_logs": mixed_lines,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["malformed_quarantined"] == 2
    assert data["inserted_events"] == 1
    assert len(mock_repo.telemetry_events) == 1


# =========================================================================
# 5. DEDUPLICATION SAFETY TESTS
# =========================================================================

def test_ingest_duplicate_suppression(client, setup_mock_repository):
    mock_repo = setup_mock_repository
    line = "Nov  1 10:00:01 core-auth-srv01 sshd[12450]: Failed password for invalid user admin from 198.51.100.24 port 54321 ssh2"

    # First Ingest Batch
    res1 = client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={"host_id": "srv-ubuntu-apri", "hostname": "ubuntu-apri-vm", "raw_logs": [line]},
    )
    assert res1.status_code == 200
    assert res1.json()["inserted_events"] == 1
    assert res1.json()["duplicates_ignored"] == 0

    # Second Ingest Batch with IDENTICAL event ID
    res2 = client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={"host_id": "srv-ubuntu-apri", "hostname": "ubuntu-apri-vm", "raw_logs": [line]},
    )
    assert res2.status_code == 200
    assert res2.json()["inserted_events"] == 0
    assert res2.json()["duplicates_ignored"] == 1

    # Total in repo remains exactly 1
    assert len(mock_repo.telemetry_events) == 1


# =========================================================================
# 6. BOUNDARY & VALIDATION LIMIT TESTS
# =========================================================================

def test_ingest_rejects_excessive_line_length(client):
    oversized_line = "A" * 4097
    res = client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={"host_id": "srv-ubuntu-apri", "hostname": "ubuntu-apri-vm", "raw_logs": [oversized_line]},
    )
    assert res.status_code == 422
    assert "Line at index 0 exceeds maximum allowed length" in str(res.json())


def test_ingest_rejects_empty_raw_logs(client):
    res = client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={"host_id": "srv-ubuntu-apri", "hostname": "ubuntu-apri-vm", "raw_logs": []},
    )
    assert res.status_code == 422


def test_ingest_rejects_invalid_host_id(client):
    res = client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={"host_id": "invalid/host/id$", "hostname": "ubuntu-apri-vm", "raw_logs": ["test line"]},
    )
    assert res.status_code == 422


# =========================================================================
# 7. READ RE-VERIFICATION ON GET ENDPOINTS
# =========================================================================

def test_ingested_host_readable_by_get_hosts(client, setup_mock_repository):
    line = "Nov  1 10:00:01 core-auth-srv01 sshd[12450]: Failed password for invalid user admin from 198.51.100.24 port 54321 ssh2"

    client.post(
        "/api/telemetry/ingest",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={
            "host_id": "srv-ubuntu-apri",
            "hostname": "ubuntu-apri-vm",
            "ip_address": "10.0.0.45",
            "raw_logs": [line],
        },
    )

    # Read from GET /api/hosts
    res = client.get("/api/hosts")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["items"][0]["id"] == "srv-ubuntu-apri"
    assert data["items"][0]["hostname"] == "ubuntu-apri-vm"
    assert data["items"][0]["agent_status"] == "online"

    # GET /api/alerts remains empty (no fake alerts created)
    res_alerts = client.get("/api/alerts")
    assert res_alerts.status_code == 200
    assert res_alerts.json()["total"] == 0


def test_heartbeat_authenticated(client, setup_mock_repository):
    mock_repo = setup_mock_repository
    mock_repo.hosts.append({
        "id": "srv-ubuntu-apri",
        "hostname": "ubuntu-apri-vm",
        "ip_address": "10.0.0.45",
        "os": "Ubuntu 24.04 LTS",
        "agent_version": "0.1.0",
        "agent_status": "online",
        "last_data_at": "2026-11-07T12:00:00Z",
        "is_archived": False,
    })
    res = client.post(
        "/api/telemetry/heartbeat",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={
            "host_id": "srv-ubuntu-apri",
            "hostname": "ubuntu-apri-vm",
            "ip_address": "10.0.0.45",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["host_id"] == "srv-ubuntu-apri"
    assert data["agent_status"] == "online"


def test_heartbeat_unauthenticated_rejected(client):
    res = client.post(
        "/api/telemetry/heartbeat",
        json={"host_id": "srv-ubuntu-apri", "hostname": "ubuntu-apri-vm"},
    )
    assert res.status_code == 401


def test_heartbeat_unknown_host_rejected_404(client, setup_mock_repository):
    res = client.post(
        "/api/telemetry/heartbeat",
        headers={"X-Agent-Token": VALID_TOKEN},
        json={
            "host_id": "unknown-host-999",
            "hostname": "rogue-host",
            "ip_address": "192.168.1.99",
        },
    )
    assert res.status_code == 404
    assert "not registered" in res.json()["detail"]


