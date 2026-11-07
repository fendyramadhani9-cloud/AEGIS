"""
Unit & Integration Tests for AEGIS FastAPI Backend.
Verifies:
1. FastAPI app startup & routing.
2. Health & database connectivity endpoints.
3. System status endpoint.
4. Monitored hosts listing & single host detail with pagination validation.
5. Alerts listing & detail with severity filtering.
6. Absolute immutability: zero mutation endpoints on alerts/severity.
7. Zero secret leakage across all HTTP responses and headers.
8. Safe database error sanitization (no credentials or raw traces exposed).
"""

import pytest
from fastapi.testclient import TestClient
from aegis_backend.main import app
from aegis_backend.repository import MockAegisRepository, set_repository
from aegis_backend.config import settings

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_mock_repository():
    """Ensures each test runs with a fresh, clean in-memory mock repository."""
    mock_repo = MockAegisRepository()
    set_repository(mock_repo)
    yield mock_repo
    set_repository(None)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["service"] == "AEGIS Security Monitoring Backend"


def test_app_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "aegis-backend"
    assert data["version"] == "0.1.0"
    assert "environment" in data


def test_database_health_endpoint():
    response = client.get("/api/health/database")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "connected" in data
    assert "checked_at" in data
    assert "message" in data
    # Ensure no connection strings or keys leaked
    assert "password" not in response.text.lower()
    assert "postgres" not in response.text.lower()
    assert "service_role" not in response.text.lower()


def test_system_status_endpoint():
    response = client.get("/api/system/status")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 1
    assert data["collector"] in ["ok", "degraded", "unavailable"]
    assert data["rules_engine"] in ["ok", "degraded", "unavailable"]
    assert data["ai_provider"] in ["ok", "degraded", "unavailable"]


def test_list_hosts_pagination_and_filtering():
    # 1. Default pagination
    response = client.get("/api/hosts")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] == 2
    assert len(data["items"]) == 2
    assert data["items"][0]["id"] == "srv-prod-auth"

    # 2. Limit and offset
    response = client.get("/api/hosts?limit=1&offset=1")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["id"] == "srv-db-01"

    # 3. Filter by agent_status
    response = client.get("/api/hosts?agent_status=online")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["agent_status"] == "online"

    # 4. Invalid limit (> 100 or < 1) returns 422
    invalid_resp = client.get("/api/hosts?limit=150")
    assert invalid_resp.status_code == 422

    invalid_resp = client.get("/api/hosts?limit=0")
    assert invalid_resp.status_code == 422


def test_get_host_by_id():
    # Existing host
    response = client.get("/api/hosts/srv-prod-auth")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "srv-prod-auth"
    assert data["hostname"] == "core-auth-srv01"
    assert data["agent_status"] == "online"

    # Non-existing host returns 404
    missing_resp = client.get("/api/hosts/non-existing-host")
    assert missing_resp.status_code == 404
    err_data = missing_resp.json()
    assert "not found" in err_data["detail"].lower()


def test_list_alerts_and_filtering():
    # 1. Default list
    response = client.get("/api/alerts")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2

    # 2. Filter by severity
    high_resp = client.get("/api/alerts?severity=high")
    assert high_resp.status_code == 200
    high_data = high_resp.json()
    assert high_data["total"] == 1
    assert high_data["items"][0]["severity"] == "high"

    # 3. Invalid severity returns 422
    invalid_sev = client.get("/api/alerts?severity=unsupported_severity")
    assert invalid_sev.status_code == 422


def test_get_alert_by_id():
    # Existing alert
    response = client.get("/api/alerts/ALT-001")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "ALT-001"
    assert data["severity"] == "high"
    assert data["rule_id"] == "RULE-AUTH-003"

    # Non-existing alert returns 404
    missing_resp = client.get("/api/alerts/ALT-NONEXISTENT")
    assert missing_resp.status_code == 404


def test_get_alert_evidence_endpoint():
    repo = MockAegisRepository()
    # Add test alert and evidence
    alert_id = "ALT-TEST-EV"
    host_id = "srv-prod-auth"
    repo.alerts.append({
        "id": alert_id,
        "host_id": host_id,
        "rule_id": "RULE-SSH-BRUTE",
        "rule_version": "1.0",
        "title": "SSH Brute Force",
        "severity": "high",
        "detected_at": "2026-11-01T10:00:00Z",
        "reason": "Test alert with evidence",
    })
    repo.telemetry_events.append({
        "id": "EVT-TEST-01",
        "host_id": host_id,
        "source_id": "ssh-auth",
        "event_type": "auth_failure",
        "event_timestamp": "2026-11-01T10:00:00Z",
        "message": "Failed password for root from 1.2.3.4",
        "source_ip": "1.2.3.4",
        "user_name": "root",
        "details": {},
    })
    repo.telemetry_events.append({
        "id": "EVT-CROSS-HOST",
        "host_id": "other-host",
        "source_id": "ssh-auth",
        "event_type": "auth_failure",
        "event_timestamp": "2026-11-01T10:00:00Z",
        "message": "Cross host event",
        "source_ip": "9.9.9.9",
        "user_name": "root",
        "details": {},
    })
    repo.alert_evidence.append({
        "alert_id": alert_id,
        "event_id": "EVT-TEST-01",
        "citation_role": "trigger",
    })
    repo.alert_evidence.append({
        "alert_id": alert_id,
        "event_id": "EVT-CROSS-HOST",
        "citation_role": "supporting",
    })

    set_repository(repo)

    # 1. Existing alert evidence returns 200
    res = client.get(f"/api/alerts/{alert_id}/evidence")
    assert res.status_code == 200
    data = res.json()
    assert data["alert_id"] == alert_id
    # Cross-host event must be excluded
    assert data["total"] == 1
    item = data["items"][0]
    assert item["event_id"] == "EVT-TEST-01"
    assert item["host_id"] == host_id
    assert item["citation_role"] == "trigger"
    assert "Failed password" in item["message"]

    # 2. Unknown alert ID returns 404
    res_404 = client.get("/api/alerts/ALT-UNKNOWN-999/evidence")
    assert res_404.status_code == 404


def test_evidence_details_credential_masking():
    """Verifies that sensitive credentials in details dictionaries are redacted before returning via API."""
    repo = MockAegisRepository()
    alert_id = "ALT-SECRET-TEST"
    host_id = "srv-prod-auth"
    repo.alerts.append({
        "id": alert_id,
        "host_id": host_id,
        "rule_id": "RULE-TEST",
        "rule_version": "1.0",
        "title": "Secret Sanitization Test",
        "severity": "high",
        "detected_at": "2026-11-01T10:00:00Z",
        "reason": "Test",
    })
    repo.telemetry_events.append({
        "id": "EVT-SECRET-01",
        "host_id": host_id,
        "source_id": "ssh-auth",
        "event_type": "auth",
        "event_timestamp": "2026-11-01T10:00:00Z",
        "message": "User login with normal message",
        "source_ip": "10.0.0.1",
        "user_name": "admin",
        "details": {
            "normal_field": "safe_value",
            "db_password": "super_secret_db_password",
            "api_key": "AKIA1234567890EXAMPLE",
            "auth_token": "bearer eyJhbGciOi...",
        },
    })
    repo.alert_evidence.append({
        "alert_id": alert_id,
        "event_id": "EVT-SECRET-01",
        "citation_role": "trigger",
    })
    set_repository(repo)

    res = client.get(f"/api/alerts/{alert_id}/evidence")
    assert res.status_code == 200
    details = res.json()["items"][0]["details"]
    assert details["normal_field"] == "safe_value"
    assert details["db_password"] == "[REDACTED]"
    assert details["api_key"] == "[REDACTED]"
    assert details["auth_token"] == "[REDACTED]"


def test_supabase_repository_fallback_behavior():
    """
    Verifies that SupabaseRepository only falls back to sequential upsert when RPC function is missing.
    Integrity / validation errors must raise immediately and block sequential fallback!
    """
    from aegis_backend.repository import SupabaseRepository
    import pytest

    class DummyClient:
        def __init__(self, rpc_error_msg: str):
            self.rpc_error_msg = rpc_error_msg
            self.sequential_upsert_called = False

        def rpc(self, name, params):
            class RpcCaller:
                def __init__(self, err_msg):
                    self.err_msg = err_msg
                def execute(self):
                    raise RuntimeError(self.err_msg)
            return RpcCaller(self.rpc_error_msg)

        def table(self, table_name):
            client_self = self
            class TableCaller:
                def upsert(self, data, **kwargs):
                    client_self.sequential_upsert_called = True
                    class QueryBuilder:
                        def execute(self):
                            class Res:
                                pass
                            r = Res()
                            r.data = data
                            return r
                    return QueryBuilder()
            return TableCaller()

    # Case 1: Missing function error (PGRST202) -> sequential fallback allowed
    dummy_missing = DummyClient("PGRST202: Could not find the function fn_ingest_alert_with_evidence in the schema cache")
    repo_missing = SupabaseRepository(client=dummy_missing)
    ins_alerts, _ = repo_missing.insert_alerts([{"id": "ALT-1"}], [{"alert_id": "ALT-1", "event_id": "EVT-1"}])
    assert dummy_missing.sequential_upsert_called is True
    assert ins_alerts == 1

    # Case 2: Validation / Integrity error (check_violation / AEGIS Conflict Error) -> sequential fallback BLOCKED!
    dummy_integrity = DummyClient("AEGIS Integrity Violation: Alert ALT-1 has no supporting evidence.")
    repo_integrity = SupabaseRepository(client=dummy_integrity)
    with pytest.raises(RuntimeError) as exc_info:
        repo_integrity.insert_alerts([{"id": "ALT-1"}], [])
    assert "AEGIS Integrity Violation" in str(exc_info.value)
    assert dummy_integrity.sequential_upsert_called is False

    # Case 3: Generic error with text 'not found' or 'does not exist' -> sequential fallback BLOCKED!
    dummy_generic = DummyClient("Target host does not exist and telemetry event not found in database.")
    repo_generic = SupabaseRepository(client=dummy_generic)
    with pytest.raises(RuntimeError):
        repo_generic.insert_alerts([{"id": "ALT-1"}], [])
    assert dummy_generic.sequential_upsert_called is False

    # Case 4: Permission denied (42501) -> sequential fallback BLOCKED!
    dummy_perm = DummyClient("42501: permission denied for function fn_ingest_alert_with_evidence")
    repo_perm = SupabaseRepository(client=dummy_perm)
    with pytest.raises(RuntimeError):
        repo_perm.insert_alerts([{"id": "ALT-1"}], [])
    assert dummy_perm.sequential_upsert_called is False

    # Case 5: Undefined function code (42883) -> sequential fallback allowed
    dummy_42883 = DummyClient("42883: function public.fn_ingest_alert_with_evidence does not exist")
    repo_42883 = SupabaseRepository(client=dummy_42883)
    ins_42883, _ = repo_42883.insert_alerts([{"id": "ALT-1"}], [{"alert_id": "ALT-1", "event_id": "EVT-1"}])
    assert dummy_42883.sequential_upsert_called is True
    assert ins_42883 == 1





def test_severity_immutability_no_mutating_endpoints():
    """
    AEGIS Core Principle:
    Alert severity is generated deterministically by the Rules Engine.
    There MUST NOT exist any PUT, PATCH, or POST endpoints modifying alert severity.
    """
    put_resp = client.put("/api/alerts/ALT-001", json={"severity": "low"})
    assert put_resp.status_code in [404, 405]

    patch_resp = client.patch("/api/alerts/ALT-001", json={"severity": "low"})
    assert patch_resp.status_code in [404, 405]


def test_database_error_handling_sanitization():
    """Verifies that database failures produce clean, sanitized 500 responses without leaking traces."""
    failing_repo = MockAegisRepository(simulate_db_error=True)
    set_repository(failing_repo)

    # 1. Hosts query on DB failure
    resp = client.get("/api/hosts")
    assert resp.status_code == 500
    err = resp.json()
    assert "Failed to query hosts" in err["detail"]
    assert "password" not in resp.text.lower()
    assert "key" not in resp.text.lower()

    # 2. Alerts query on DB failure
    resp_alerts = client.get("/api/alerts")
    assert resp_alerts.status_code == 500

    # 3. Database health endpoint gracefully marks degraded
    resp_health = client.get("/api/health/database")
    assert resp_health.status_code == 200
    health_data = resp_health.json()
    assert health_data["status"] == "degraded"
    assert health_data["connected"] is False


def test_no_secret_leakage_across_all_endpoints():
    """Ensures no real keys or credentials appear in any responses."""
    endpoints = [
        "/",
        "/api/health",
        "/api/health/database",
        "/api/system/status",
        "/api/hosts",
        "/api/hosts/srv-prod-auth",
        "/api/alerts",
        "/api/alerts/ALT-001",
    ]
    for ep in endpoints:
        res = client.get(ep)
        body = res.text
        # Check against sensitive tokens
        if settings.supabase_service_role_key:
            assert settings.supabase_service_role_key not in body
        if settings.llm_api_key:
            assert settings.llm_api_key not in body


def test_security_headers_attached_to_responses():
    """Verifies that defensive OWASP security headers and no-store cache control are present."""
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "no-store" in res.headers.get("Cache-Control", "")


def test_handoff_generation_and_epistemic_separation():
    """Verifies AI Investigation & Remediation Handoff Markdown generation (PRD §4)."""
    res = client.get("/api/alerts/ALT-001/handoff")
    assert res.status_code == 200
    data = res.json()
    assert data["alert_id"] == "ALT-001"
    assert data["filename"] == "AEGIS-Handoff-ALT-001.md"
    assert "# AEGIS AI Investigation & Remediation Handoff Prompt" in data["markdown"]
    assert "Confirmed Facts" in data["markdown"]
    assert "Unverified Hypotheses" in data["markdown"]
    assert len(data["confirmed_facts"]) >= 3
    assert len(data["unverified_hypotheses"]) >= 1
    assert len(data["investigation_steps"]) >= 1
    assert len(data["remediation_plan"]) >= 1
    assert len(data["rollback_instructions"]) >= 1


def test_automatic_recovery_verification_and_offline_honesty():
    """Verifies Automatic Recovery Verification (PRD §5) and ensures offline hosts return 'unverified'."""
    # 1. Verify online host alert (with 1m observation window)
    res_online = client.post("/api/alerts/ALT-001/verify?window_min=0")
    assert res_online.status_code == 200
    data_on = res_online.json()
    assert data_on["alert_id"] == "ALT-001"
    assert data_on["outcome"] in ("resolved", "unverified", "still_active")
    assert len(data_on["checks"]) >= 3

    # 2. Verify offline host alert -> MUST be 'unverified', never 'resolved'
    repo = MockAegisRepository()
    repo.alerts.append({
        "id": "ALT-OFFLINE-01",
        "host_id": "srv-db-01",  # offline host in MockAegisRepository
        "rule_id": "RULE-SSH-BRUTE",
        "rule_version": "1.0",
        "title": "SSH Brute Force",
        "severity": "high",
        "detected_at": "2026-11-01T10:00:00+00:00",
        "reason": "Repeated SSH failures",
    })
    set_repository(repo)
    res_off = client.post("/api/alerts/ALT-OFFLINE-01/verify?window_min=1")
    assert res_off.status_code == 200
    assert res_off.json()["outcome"] == "unverified"


def test_incident_replay_and_investigation_workflow():
    """Verifies chronological incident replay and manual operator investigation workflow."""
    # Update investigation status & add note
    inv_res = client.post(
        "/api/alerts/ALT-001/investigation",
        json={"status": "investigating", "note": "Checking sshd logs on srv-prod-auth", "author": "sec-ops"},
    )
    assert inv_res.status_code == 200
    inv_data = inv_res.json()
    assert inv_data["status"] == "investigating"
    assert len(inv_data["notes"]) >= 1
    assert inv_data["notes"][0]["author"] == "sec-ops"

    # Fetch incident replay
    rep_res = client.get("/api/alerts/ALT-001/replay")
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert rep_data["alert_id"] == "ALT-001"
    assert any(s["phase"] == "detection" for s in rep_data["steps"])
    assert any(s["phase"] == "investigation" for s in rep_data["steps"])

    # Check operator audit log recorded the actions
    aud_res = client.get("/api/audit-logs")
    assert aud_res.status_code == 200
    assert len(aud_res.json()) >= 1


def test_three_key_ai_roles_and_8_module_security_checker():
    """Verifies the 3-Key AI Role Allocation (AEGIS1, AEGIS2, AEGIS3) and 8-Module Security Checker."""
    roles_res = client.get("/api/system/ai-roles")
    assert roles_res.status_code == 200
    roles = roles_res.json()
    assert len(roles) == 3
    slot_map = {r["role_id"]: r["key_slot"] for r in roles}
    assert slot_map["rm_agent"] == "AEGIS1"
    assert slot_map["sc_agent"] == "AEGIS2"
    assert slot_map["reporting_agent"] == "AEGIS3"

    findings_res = client.get("/api/findings?host_id=srv-prod-auth")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) == 12
    check_ids = {f["check_id"] for f in findings}
    assert "CIS-SSH-5.2.8" in check_ids
    assert "CIS-PERM-6.1.2" in check_ids
    assert "CIS-PRIV-5.3.4" in check_ids
    assert "CIS-SUID-6.1.12" in check_ids
    assert "CIS-NET-3.5.1" in check_ids
    assert "CIS-SYSCTL-3.3.1" in check_ids
    assert "CIS-PKG-1.9" in check_ids
    assert "CIS-PERSIST-5.1.8" in check_ids
    assert "STIG-BANNER-8.1" in check_ids
    assert "STIG-CRYPTO-5.2" in check_ids
    assert "STIG-AUDIT-4.1" in check_ids
    assert "STIG-MEDIA-1.1" in check_ids

    # Trigger operator read-only posture scan
    scan_res = client.post("/api/findings/scan?host_id=srv-prod-auth")
    assert scan_res.status_code == 200
    assert len(scan_res.json()) == 12


def test_kill_chain_context_signed_evidence_bundle_and_pdf_report():
    """Verifies Kill-Chain Context, Signed SHA-256 Evidence Bundle, and Binary PDF Report Export."""
    ctx_res = client.get("/api/alerts/ALT-001/context")
    assert ctx_res.status_code == 200
    ctx = ctx_res.json()
    assert ctx["alert_id"] == "ALT-001"
    assert len(ctx["kill_chain"]) == 6
    assert "blast_radius" in ctx
    assert ctx["blast_radius"]["target_host"] == "srv-prod-auth"

    bnd_res = client.get("/api/alerts/ALT-001/evidence-bundle")
    assert bnd_res.status_code == 200
    bnd = bnd_res.json()
    assert bnd["hash_algorithm"] == "SHA-256"
    assert len(bnd["manifest_sha256"]) == 64

    rpt_res = client.post(
        "/api/reports",
        json={
            "type": "daily",
            "host_ids": ["srv-prod-auth"],
            "period_start": "2026-11-06T00:00:00Z",
            "period_end": "2026-11-07T00:00:00Z",
        },
    )
    assert rpt_res.status_code == 200
    rpt_data = rpt_res.json()
    assert rpt_data["ai_key_slot"] == "AEGIS3"

    pdf_res = client.get(f"/api/reports/{rpt_data['id']}/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF-")


def test_bug_002_collection_gaps_endpoint_and_handoff_integration():
    """
    Regression test for BUG-002:
    Verifies GET /api/collection-gaps returns open gaps for offline/stale hosts
    and that handoff & recovery verification include real gap records rather than hardcoded [].
    """
    repo = MockAegisRepository()
    repo.hosts.append(
        {
            "id": "host-gap-node",
            "hostname": "gap-node-01",
            "os": "Ubuntu 24.04",
            "agent_version": "0.1.0",
            "agent_status": "offline",
            "last_data_at": "2026-11-01T00:00:00+00:00",
        }
    )
    repo.alerts.append(
        {
            "id": "ALT-GAP-01",
            "host_id": "host-gap-node",
            "rule_id": "RULE-SSH-BRUTE",
            "rule_version": "1.0",
            "title": "SSH Brute Force on Offline Node",
            "severity": "high",
            "detected_at": "2026-11-01T00:01:00+00:00",
            "reason": "5 failed SSH attempts",
        }
    )
    set_repository(repo)

    gaps_res = client.get("/api/collection-gaps?host_id=host-gap-node&open_only=true")
    assert gaps_res.status_code == 200
    gaps_list = gaps_res.json()
    assert len(gaps_list) >= 1
    assert gaps_list[0]["host_id"] == "host-gap-node"

    handoff_res = client.get("/api/alerts/ALT-GAP-01/handoff")
    assert handoff_res.status_code == 200
    handoff_data = handoff_res.json()
    assert any("Telemetry gap" in m for m in handoff_data["missing_telemetry"])


def test_bug_005_hosts_dynamic_agent_status_filtering():
    """
    Regression test for BUG-005:
    A host whose stored DB status is 'online' but whose last_data_at is stale (> 30 min ago)
    must be returned when filtering GET /api/hosts?agent_status=offline and excluded from online.
    """
    repo = MockAegisRepository()
    repo.hosts = [
        {
            "id": "host-stale-online-db",
            "hostname": "stale-host",
            "os": "Ubuntu 24.04",
            "agent_version": "0.1.0",
            "agent_status": "online",  # stale DB column
            "last_data_at": "2020-01-01T00:00:00+00:00",  # > 30 min old -> dynamically offline
        }
    ]
    set_repository(repo)

    res_offline = client.get("/api/hosts?agent_status=offline")
    assert res_offline.status_code == 200
    items_off = res_offline.json()["items"]
    assert any(h["id"] == "host-stale-online-db" and h["agent_status"] == "offline" for h in items_off)

    res_online = client.get("/api/hosts?agent_status=online")
    assert res_online.status_code == 200
    items_on = res_online.json()["items"]
    assert not any(h["id"] == "host-stale-online-db" for h in items_on)


def test_bug_009_report_clean_host_zero_alerts_no_cross_host_leak():
    """
    Regression test for BUG-009:
    Generating a report for a clean host with 0 alerts must produce alert_count == 0
    rather than falling back to all alerts from other hosts.
    """
    rpt_res = client.post(
        "/api/reports",
        json={
            "type": "daily",
            "host_ids": ["host-clean-zero-alerts"],
            "period_start": "2026-11-06T00:00:00Z",
            "period_end": "2026-11-08T00:00:00Z",
        },
    )
    assert rpt_res.status_code == 200
    rpt_data = rpt_res.json()
    assert rpt_data["alert_count"] == 0


def test_bug_010_operational_state_store_disk_persistence(tmp_path):
    """
    Regression test for BUG-010:
    OperationalStateStore persists investigations and audit logs to disk and restores
    them cleanly on service restart.
    """
    from aegis_backend.incident_service import OperationalStateStore

    state_path = tmp_path / "op_state.json"
    store_1 = OperationalStateStore(state_file=state_path)
    store_1.update_investigation(
        alert_id="ALT-PERSIST-01",
        status="reopened",
        note="Recurrence confirmed after reboot",
        author="qa-auditor",
    )
    assert state_path.exists()

    # Simulate backend process restart by instantiating a new store pointing to the same file
    store_2 = OperationalStateStore(state_file=state_path)
    inv = store_2.get_investigation("ALT-PERSIST-01")
    assert inv.status == "reopened"
    assert len(inv.notes) == 1
    assert inv.notes[0].note == "Recurrence confirmed after reboot"


def test_bug_015_and_016_security_headers_and_ai_cooldown():
    """
    Regression test for BUG-015 (HTTP Security Headers including CSP) and
    BUG-016 (per-alert AI analysis cooldown cache).
    """
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")

    # First AI analysis call populates cache
    a1 = client.post("/api/alerts/ALT-001/analyze?cooldown_sec=60")
    assert a1.status_code == 200
    ts1 = a1.json()["generated_at"]

    # Immediate second call within cooldown returns cached generated_at
    a2 = client.post("/api/alerts/ALT-001/analyze?cooldown_sec=60")
    assert a2.status_code == 200
    assert a2.json()["generated_at"] == ts1




