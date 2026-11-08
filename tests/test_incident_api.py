"""
Integration tests for AEGIS Incident Investigation & AI Security Analysis FastAPI Endpoints.
Covers:
- GET /api/analysis/health
- POST /api/incidents (Correlate alerts into incidents)
- GET /api/incidents (List and filter incidents)
- GET /api/incidents/summary (Incident dashboard metrics)
- GET /api/incidents/{id} (Incident detail with correlated alerts)
- PATCH /api/incidents/{id}/status (Lifecycle status transition)
- GET /api/incidents/{id}/timeline (Unified chronological timeline)
- GET /api/incidents/{id}/evidence (Grounded evidence items)
- POST /api/incidents/{id}/analyze (AI analysis trigger)
- GET /api/incidents/{id}/analysis (Retrieve latest AI analysis)
"""

import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from aegis_backend.main import app
from aegis_backend.repository import get_repository
from aegis_backend.schemas import AlertItem, AlertEvidenceItem, HostItem


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def setup_seed_data():
    """Seeds test data into the repository before tests."""
    repo = get_repository()
    now = datetime.now(timezone.utc)

    # Ensure host exists
    host = {
        "id": "host-fenn-ubuntu",
        "hostname": "fenn",
        "os": "Ubuntu 24.04 LTS",
        "agent_version": "1.0.0",
        "agent_status": "online",
        "last_data_at": now.isoformat(),
    }
    repo.upsert_host(host)

    # Seed 3 alerts for correlation
    alert1 = {
        "id": "ALT-SEED-BRUTE",
        "host_id": "host-fenn-ubuntu",
        "rule_id": "RULE-SSH-BRUTE",
        "rule_version": "1.0",
        "title": "SSH Brute Force Detected",
        "severity": "high",
        "detected_at": (now - timedelta(minutes=20)).isoformat(),
        "reason": "3 failed logins in 5 minutes",
    }
    alert2 = {
        "id": "ALT-SEED-AUTH",
        "host_id": "host-fenn-ubuntu",
        "rule_id": "RULE-AUTH-003",
        "rule_version": "1.0",
        "title": "Failed Login Followed By Success",
        "severity": "high",
        "detected_at": (now - timedelta(minutes=15)).isoformat(),
        "reason": "Login success after previous failures",
    }
    alert3 = {
        "id": "ALT-SEED-SUDO",
        "host_id": "host-fenn-ubuntu",
        "rule_id": "RULE-SUSP-SUDO",
        "rule_version": "1.0",
        "title": "Suspicious Sudo Root Execution",
        "severity": "high",
        "detected_at": (now - timedelta(minutes=10)).isoformat(),
        "reason": "Root shell invoked with chmod 777",
    }

    # Telemetry events
    event1 = {
        "id": "EV-SEED-1",
        "host_id": "host-fenn-ubuntu",
        "source_id": "ssh-auth",
        "event_type": "auth_failure",
        "message": "Failed password for invalid user admin from 192.168.1.50 port 45123",
        "event_timestamp": (now - timedelta(minutes=20)).isoformat(),
    }
    event2 = {
        "id": "EV-SEED-2",
        "host_id": "host-fenn-ubuntu",
        "source_id": "ssh-auth",
        "event_type": "auth_success",
        "message": "Accepted password for ubuntu from 192.168.1.50 port 45124",
        "event_timestamp": (now - timedelta(minutes=15)).isoformat(),
    }
    event3 = {
        "id": "EV-SEED-3",
        "host_id": "host-fenn-ubuntu",
        "source_id": "ssh-auth",
        "event_type": "sudo_command",
        "message": "sudo: ubuntu : TTY=pts/0 ; COMMAND=/bin/bash",
        "event_timestamp": (now - timedelta(minutes=10)).isoformat(),
    }
    repo.insert_telemetry_events([event1, event2, event3])

    # Evidence links (junction table: alert_id, event_id, citation_role)
    ev1 = {
        "alert_id": alert1["id"],
        "event_id": "EV-SEED-1",
        "citation_role": "supporting",
    }
    ev2 = {
        "alert_id": alert2["id"],
        "event_id": "EV-SEED-2",
        "citation_role": "supporting",
    }
    ev3 = {
        "alert_id": alert3["id"],
        "event_id": "EV-SEED-3",
        "citation_role": "supporting",
    }

    repo.insert_alerts([alert1, alert2, alert3], [ev1, ev2, ev3])


def test_ai_health_endpoint(client):
    response = client.get("/api/analysis/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "active_provider" in data
    assert "key_available" in data
    assert "offline_fallback_ready" in data


def test_correlate_incidents_endpoint(client):
    response = client.post("/api/incidents", json={"host_id": "host-fenn-ubuntu"})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["id"].startswith("INC-")


def test_list_and_summary_incidents_endpoint(client):
    # Test summary
    sum_resp = client.get("/api/incidents/summary")
    assert sum_resp.status_code == 200
    summary = sum_resp.json()
    assert summary["total_incidents"] >= 1
    assert "storage_backend" in summary

    # Test list
    list_resp = client.get("/api/incidents?page=1&page_size=10")
    assert list_resp.status_code == 200
    inc_list = list_resp.json()
    assert "items" in inc_list
    assert len(inc_list["items"]) >= 1

    first_incident = inc_list["items"][0]
    assert first_incident["id"].startswith("INC-")
    assert first_incident["host_id"] == "host-fenn-ubuntu"
    assert first_incident["risk_score"] > 0


def test_incident_detail_and_status_transition(client):
    # Get list to pick an ID
    list_resp = client.get("/api/incidents")
    incidents = list_resp.json()["items"]
    assert len(incidents) > 0
    inc_id = incidents[0]["id"]

    # Detail
    detail_resp = client.get(f"/api/incidents/{inc_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["incident"]["id"] == inc_id
    assert len(detail["alerts"]) >= 1

    # Status update: transition to 'investigating'
    patch_resp = client.patch(
        f"/api/incidents/{inc_id}/status",
        json={"status": "investigating", "notes": "SOC Analyst investigating attack progression."}
    )
    assert patch_resp.status_code == 200
    updated = patch_resp.json()
    assert updated["status"] == "investigating"


def test_incident_timeline_and_evidence(client):
    list_resp = client.get("/api/incidents")
    inc_id = list_resp.json()["items"][0]["id"]

    # Timeline
    timeline_resp = client.get(f"/api/incidents/{inc_id}/timeline")
    assert timeline_resp.status_code == 200
    timeline = timeline_resp.json()
    assert isinstance(timeline, list)
    assert len(timeline) >= 1

    # Evidence
    ev_resp = client.get(f"/api/incidents/{inc_id}/evidence")
    assert ev_resp.status_code == 200
    evidence = ev_resp.json()
    assert isinstance(evidence, list)
    assert len(evidence) >= 1


def test_incident_analyze_endpoint(client):
    list_resp = client.get("/api/incidents")
    inc_id = list_resp.json()["items"][0]["id"]

    # Trigger analysis (force=True to bypass cache)
    analyze_resp = client.post(f"/api/incidents/{inc_id}/analyze", json={"force": True})
    assert analyze_resp.status_code == 200
    analysis = analyze_resp.json()
    assert analysis["incident_id"] == inc_id
    assert analysis["analysis_status"] in ("completed", "failed", "unavailable")
    assert "threat_classification" in analysis
    assert "executive_summary" in analysis

    # Retrieve analysis
    get_ana_resp = client.get(f"/api/incidents/{inc_id}/analysis")
    assert get_ana_resp.status_code == 200
    retrieved = get_ana_resp.json()
    assert retrieved["analysis_id"] == analysis["analysis_id"]
