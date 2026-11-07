"""
Integration tests for AEGIS Security Checker API Router (/api/security-checker/*).
Verifies authentication, payload validation, pagination, filtering, summary stats,
and cross-host isolation against MockAegisRepository.
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from aegis_backend.main import app
from aegis_backend.repository import set_repository, MockAegisRepository
from aegis_backend.config import settings


@pytest.fixture
def client():
    mock_repo = MockAegisRepository()
    set_repository(mock_repo)
    with TestClient(app) as test_client:
        yield test_client
    set_repository(None)


# ------------------------------------------------------------------------------
# 1. HEALTH, CHECKS & HOSTS
# ------------------------------------------------------------------------------

def test_security_checker_health(client):
    res = client.get("/api/security-checker/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["module"] == "security-checker"
    assert data["total_catalog_checks"] >= 20


def test_list_catalog_checks(client):
    res = client.get("/api/security-checker/checks")
    assert res.status_code == 200
    checks = res.json()
    assert len(checks) >= 20
    check_ids = [c["check_id"] for c in checks]
    assert "SSH-001" in check_ids
    assert "FW-001" in check_ids


def test_list_auditable_hosts(client):
    res = client.get("/api/security-checker/hosts")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert any(h["id"] == "srv-prod-auth" for h in data["items"])


# ------------------------------------------------------------------------------
# 2. RUN TRIGGER & HISTORY
# ------------------------------------------------------------------------------

def test_trigger_run_success(client):
    payload = {"host_id": "srv-prod-auth", "force": True}
    res = client.post("/api/security-checker/runs", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "pending"
    assert data["host_id"] == "srv-prod-auth"


def test_trigger_run_unknown_host_returns_404(client):
    payload = {"host_id": "non-existent-host", "force": True}
    res = client.post("/api/security-checker/runs", json=payload)
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 3. AGENT RESULT SUBMISSION & AUTHENTICATION
# ------------------------------------------------------------------------------

def test_agent_submission_missing_token_returns_401(client):
    payload = {"run": {"id": "R1", "host_id": "srv-prod-auth", "status": "completed", "total_checks": 0, "passed_checks": 0, "failed_checks": 0, "warning_checks": 0, "error_checks": 0, "started_at": "2026-11-07T10:00:00Z"}, "findings": []}
    res = client.post("/api/security-checker/agent-results", json=payload)
    assert res.status_code == 401
    assert "X-Agent-Token" in res.json()["detail"]


def test_agent_submission_invalid_token_returns_401(client):
    payload = {"run": {"id": "R1", "host_id": "srv-prod-auth", "status": "completed", "total_checks": 0, "passed_checks": 0, "failed_checks": 0, "warning_checks": 0, "error_checks": 0, "started_at": "2026-11-07T10:00:00Z"}, "findings": []}
    headers = {"X-Agent-Token": "bad-token-value"}
    res = client.post("/api/security-checker/agent-results", json=payload, headers=headers)
    assert res.status_code == 401
    assert "Invalid agent authentication token" in res.json()["detail"]


def test_agent_submission_unknown_host_returns_404(client):
    headers = {"X-Agent-Token": settings.agent_ingest_token}
    payload = {
        "run": {"id": "R1", "host_id": "unknown-host-x", "status": "completed", "total_checks": 0, "passed_checks": 0, "failed_checks": 0, "warning_checks": 0, "error_checks": 0, "started_at": "2026-11-07T10:00:00Z"},
        "findings": []
    }
    res = client.post("/api/security-checker/agent-results", json=payload, headers=headers)
    assert res.status_code == 404
    assert "not registered" in res.json()["detail"]


def test_agent_submission_cross_host_finding_rejected_400(client):
    headers = {"X-Agent-Token": settings.agent_ingest_token}
    payload = {
        "run": {"id": "R1", "host_id": "srv-prod-auth", "status": "completed", "total_checks": 1, "passed_checks": 1, "failed_checks": 0, "warning_checks": 0, "error_checks": 0, "started_at": "2026-11-07T10:00:00Z"},
        "findings": [
            {
                "id": "F1",
                "run_id": "R1",
                "host_id": "srv-db-01",  # MISMATCH!
                "check_id": "SSH-001",
                "check_name": "SSH",
                "category": "ssh",
                "severity": "high",
                "status": "pass",
                "description": "Desc",
                "checked_at": "2026-11-07T10:00:00Z",
            }
        ]
    }
    res = client.post("/api/security-checker/agent-results", json=payload, headers=headers)
    assert res.status_code == 400
    assert "cross-host finding submission rejected" in res.json()["detail"].lower()


def test_agent_submission_happy_path(client):
    headers = {"X-Agent-Token": settings.agent_ingest_token}
    payload = {
        "run": {
            "id": "RUN-HAPPY-01",
            "host_id": "srv-prod-auth",
            "status": "completed",
            "total_checks": 2,
            "passed_checks": 1,
            "failed_checks": 1,
            "warning_checks": 0,
            "error_checks": 0,
            "started_at": "2026-11-07T10:00:00Z",
            "completed_at": "2026-11-07T10:00:05Z",
        },
        "findings": [
            {
                "id": "FND-HAPPY-SSH-001",
                "run_id": "RUN-HAPPY-01",
                "host_id": "srv-prod-auth",
                "check_id": "SSH-001",
                "check_name": "SSH Root Login",
                "category": "ssh",
                "severity": "high",
                "status": "pass",
                "actual_value": "PermitRootLogin no",
                "expected_value": "PermitRootLogin no",
                "description": "SSH check desc",
                "checked_at": "2026-11-07T10:00:05Z",
            },
            {
                "id": "FND-HAPPY-FW-001",
                "run_id": "RUN-HAPPY-01",
                "host_id": "srv-prod-auth",
                "check_id": "FW-001",
                "check_name": "Firewall Active",
                "category": "firewall",
                "severity": "high",
                "status": "fail",
                "actual_value": "inactive",
                "expected_value": "active",
                "description": "FW check desc",
                "checked_at": "2026-11-07T10:00:05Z",
            },
        ]
    }
    res = client.post("/api/security-checker/agent-results", json=payload, headers=headers)
    assert res.status_code == 200
    assert res.json()["stored_findings"] == 2

    # Query findings
    res_f = client.get("/api/security-checker/findings?host_id=srv-prod-auth")
    assert res_f.status_code == 200
    assert res_f.json()["total"] == 2

    # Query single finding
    res_single = client.get("/api/security-checker/findings/FND-HAPPY-SSH-001")
    assert res_single.status_code == 200
    assert res_single.json()["check_id"] == "SSH-001"

    # Query non-existent finding
    res_404 = client.get("/api/security-checker/findings/FND-NOT-FOUND")
    assert res_404.status_code == 404

    # Query summary
    res_sum = client.get("/api/security-checker/summary?host_id=srv-prod-auth")
    assert res_sum.status_code == 200
    s_data = res_sum.json()
    assert s_data["total_checks"] == 2
    assert s_data["passed"] == 1
    assert s_data["failed"] == 1

    # Query latest host run
    res_latest = client.get("/api/security-checker/hosts/srv-prod-auth/latest")
    assert res_latest.status_code == 200
    assert res_latest.json()["latest_run"]["id"] == "RUN-HAPPY-01"
    assert len(res_latest.json()["findings"]) == 2

    # Query history
    res_hist = client.get("/api/security-checker/hosts/srv-prod-auth/history")
    assert res_hist.status_code == 200
    assert res_hist.json()["total"] >= 1

