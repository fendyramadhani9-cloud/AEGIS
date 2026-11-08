"""
Comprehensive Unit & Integration Tests for AEGIS Multi-Tenant Isolation & Authentication.

Verifies:
1. PBKDF2 password hashing & token issuance / decoding / revocation.
2. Login endpoint (/api/auth/login) with credential validation.
3. Brute force rate limiting (429 on >= 5 consecutive failures).
4. Current user session endpoint (/api/auth/me) and logout (/api/auth/logout).
5. Hard tenant data isolation:
   - Tenant A engineer cannot see Tenant B's hosts, alerts, findings, or incidents.
   - Superadmin (Pusat Komando (HQ Command)) sees all tenants' hosts.
6. Anti-enumeration: Cross-tenant lookup by ID returns 404 (never 403).
7. Role-Based Access Control (RBAC):
   - Viewer role blocked from mutating requests (returns 403).
   - Engineer role permitted to perform operational actions within tenant scope.
8. Agent token binding & anti-spoofing:
   - Agent claiming host for Tenant A prevents Tenant B's agent from submitting data for that host.
"""

import json
import pytest
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

from aegis_backend.main import app
from aegis_backend.config import settings
from aegis_backend.repository import MockAegisRepository, set_repository
from aegis_backend.tenancy import (
    SUPERADMIN_TENANT,
    AuthStore,
    AuthUser,
    HostTenantRegistry,
    issue_token,
    decode_token,
    revoke_token,
    reset_login_state_for_tests,
    get_auth_store,
    get_host_registry,
)

client = TestClient(app)


@pytest.fixture
def clean_auth_env(tmp_path, monkeypatch):
    """
    Sets up isolated temporary files for auth_store and host_registry,
    enabling auth enforcement for the duration of the test.
    """
    auth_file = str(tmp_path / "test_auth.json")
    hosts_file = str(tmp_path / "test_hosts.json")

    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_file", auth_file)
    monkeypatch.setattr(settings, "host_tenant_file", hosts_file)

    # Initialize store & registry
    store = AuthStore(auth_file)
    registry = HostTenantRegistry(hosts_file)

    # Seed tenants
    t1_token = store.add_tenant("unit_alpha", "Unit Alpha")
    t2_token = store.add_tenant("unit_bravo", "Unit Bravo")

    # Seed users
    store.add_user("admin", "AdminHQPass1234!", SUPERADMIN_TENANT, "superadmin")
    store.add_user("operator_alpha", "AlphaPass1234!", "unit_alpha", "engineer")
    store.add_user("viewer_alpha", "AlphaViewer1234!", "unit_alpha", "viewer")
    store.add_user("operator_bravo", "BravoPass1234!", "unit_bravo", "engineer")

    # Override singletons in tenancy module
    import aegis_backend.tenancy as t_mod
    monkeypatch.setattr(t_mod, "_auth_store", store)
    monkeypatch.setattr(t_mod, "_registry", registry)

    reset_login_state_for_tests()

    mock_repo = MockAegisRepository()
    set_repository(mock_repo)

    yield {
        "store": store,
        "registry": registry,
        "repo": mock_repo,
        "t1_token": t1_token,
        "t2_token": t2_token,
    }

    reset_login_state_for_tests()
    set_repository(None)


def test_login_success_and_me(clean_auth_env):
    """User logs in successfully, receives token, and gets correct profile from /api/auth/me."""
    resp = client.post("/api/auth/login", json={"username": "operator_alpha", "password": "AlphaPass1234!"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    token = body["access_token"]
    assert body["token_type"] == "bearer"
    assert body["user"]["username"] == "operator_alpha"
    assert body["user"]["role"] == "engineer"
    assert body["user"]["tenant"] == "unit_alpha"
    assert body["user"]["tenant_name"] == "Unit Alpha"

    # Profile lookup
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["username"] == "operator_alpha"
    assert me_data["tenant"] == "unit_alpha"


def test_login_invalid_credentials(clean_auth_env):
    """Invalid password returns 401."""
    resp = client.post("/api/auth/login", json={"username": "operator_alpha", "password": "WrongPassword123!"})
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.json()["detail"]

    # Non-existent username also returns 401 (constant-time, no enumeration)
    resp2 = client.post("/api/auth/login", json={"username": "nonexistent_user", "password": "SomePassword123!"})
    assert resp2.status_code == 401


def test_brute_force_rate_limiter(clean_auth_env):
    """After 5 consecutive failures, the IP is locked out with 429."""
    for i in range(5):
        resp = client.post("/api/auth/login", json={"username": "operator_alpha", "password": f"Wrong_{i}"})
        assert resp.status_code == 401

    # 6th attempt should be blocked by rate limiter
    resp_locked = client.post("/api/auth/login", json={"username": "operator_alpha", "password": "AlphaPass1234!"})
    assert resp_locked.status_code == 429
    assert "Too many failed attempts" in resp_locked.json()["detail"]


def test_logout_and_token_revocation(clean_auth_env):
    """Logging out revokes the session token."""
    login_resp = client.post("/api/auth/login", json={"username": "operator_alpha", "password": "AlphaPass1234!"})
    token = login_resp.json()["access_token"]

    # Authenticated call succeeds
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200

    # Logout
    logout_resp = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "ok"

    # Token should now be rejected
    rejected_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert rejected_resp.status_code == 401


def test_multi_tenant_host_isolation(clean_auth_env):
    """
    Tenant 1 engineer ONLY sees Tenant 1 hosts.
    Tenant 2 engineer ONLY sees Tenant 2 hosts.
    Superadmin sees ALL hosts.
    """
    repo = clean_auth_env["repo"]
    registry = clean_auth_env["registry"]

    # Register hosts in repository and assign to tenants
    host1 = {
        "id": "server-alpha-01",
        "hostname": "bat1-alpha",
        "ip_address": "10.1.1.10",
        "os": "Ubuntu 22.04 LTS",
        "agent_version": "1.0.0",
        "agent_status": "online",
    }
    host2 = {
        "id": "server-bravo-01",
        "hostname": "bat2-bravo",
        "ip_address": "10.2.1.20",
        "os": "Ubuntu 22.04 LTS",
        "agent_version": "1.0.0",
        "agent_status": "online",
    }
    repo.upsert_host(host1)
    repo.upsert_host(host2)
    registry.claim("server-alpha-01", "unit_alpha", exists_in_repo=False)
    registry.claim("server-bravo-01", "unit_bravo", exists_in_repo=False)

    # 1. Login as operator_alpha (Tenant: unit_alpha)
    t1_token = client.post("/api/auth/login", json={"username": "operator_alpha", "password": "AlphaPass1234!"}).json()["access_token"]
    resp1 = client.get("/api/hosts", headers={"Authorization": f"Bearer {t1_token}"})
    assert resp1.status_code == 200
    hosts1 = resp1.json()["items"]
    assert len(hosts1) == 1
    assert hosts1[0]["id"] == "server-alpha-01"

    # 2. Login as operator_bravo (Tenant: unit_bravo)
    t2_token = client.post("/api/auth/login", json={"username": "operator_bravo", "password": "BravoPass1234!"}).json()["access_token"]
    resp2 = client.get("/api/hosts", headers={"Authorization": f"Bearer {t2_token}"})
    assert resp2.status_code == 200
    hosts2 = resp2.json()["items"]
    assert len(hosts2) == 1
    assert hosts2[0]["id"] == "server-bravo-01"

    # 3. Login as admin (Superadmin: *)
    admin_token = client.post("/api/auth/login", json={"username": "admin", "password": "AdminHQPass1234!"}).json()["access_token"]
    resp_admin = client.get("/api/hosts", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp_admin.status_code == 200
    admin_hosts = resp_admin.json()["items"]
    assert len(admin_hosts) >= 2
    admin_ids = {h["id"] for h in admin_hosts}
    assert "server-alpha-01" in admin_ids
    assert "server-bravo-01" in admin_ids


def test_cross_tenant_anti_enumeration_404(clean_auth_env):
    """
    Attempting to access a host from another tenant returns 404 (NOT 403),
    preventing resource enumeration across organizations.
    """
    repo = clean_auth_env["repo"]
    registry = clean_auth_env["registry"]

    repo.upsert_host({
        "id": "server-bravo-secret",
        "hostname": "bat2-secret",
        "ip_address": "10.2.1.99",
        "os": "Ubuntu 22.04 LTS",
        "agent_version": "1.0.0",
        "agent_status": "online",
    })
    registry.claim("server-bravo-secret", "unit_bravo", exists_in_repo=False)

    # Operator from unit_alpha tries to fetch unit_bravo host directly
    t1_token = client.post("/api/auth/login", json={"username": "operator_alpha", "password": "AlphaPass1234!"}).json()["access_token"]
    resp = client.get("/api/hosts/server-bravo-secret", headers={"Authorization": f"Bearer {t1_token}"})
    assert resp.status_code == 404


def test_viewer_role_mutation_denied_403(clean_auth_env):
    """A user with 'viewer' role is forbidden (403) from mutating operational state."""
    v_token = client.post("/api/auth/login", json={"username": "viewer_alpha", "password": "AlphaViewer1234!"}).json()["access_token"]

    # Read operations work
    read_resp = client.get("/api/hosts", headers={"Authorization": f"Bearer {v_token}"})
    assert read_resp.status_code == 200

    # Write / mutation (POST /api/evidence) is rejected with 403 Forbidden
    mutate_resp = client.post(
        "/api/evidence",
        json={"host_id": "server-alpha-01", "reason": "Investigation", "duration_min": 15, "data_types": ["syslog"]},
        headers={"Authorization": f"Bearer {v_token}"},
    )
    assert mutate_resp.status_code == 403
    assert "Read-only account" in mutate_resp.json()["detail"]


def test_agent_token_tenant_claim_and_anti_spoofing(clean_auth_env):
    """
    Agent telemetry ingestion:
    - First ingestion binds host to tenant (first-claim).
    - Another tenant's agent attempting to spoof / report for that host is rejected with 403.
    """
    t1_agent_token = clean_auth_env["t1_token"]
    t2_agent_token = clean_auth_env["t2_token"]

    payload_t1 = {
        "host_id": "srv-alpha-core",
        "hostname": "inf-10",
        "raw_logs": ["Oct 24 10:00:00 server sshd[1234]: Accepted password for ubuntu from 192.168.1.100 port 54321 ssh2"],
    }

    # Ingestion 1: Sent with Battalion 1 agent token -> Success & binds host to unit_alpha
    resp1 = client.post(
        "/api/telemetry/ingest",
        json=payload_t1,
        headers={"X-Agent-Token": t1_agent_token},
    )
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "ok"

    # Verify host registry bound srv-alpha-core to unit_alpha
    registry = clean_auth_env["registry"]
    assert registry.owner("srv-alpha-core") == "unit_alpha"

    # Ingestion 2: Spoof attempt! Battalion 2 agent tries to submit data for srv-alpha-core -> Blocked (403)
    resp_spoof = client.post(
        "/api/telemetry/ingest",
        json={"host_id": "srv-alpha-core", "hostname": "inf-10", "raw_logs": ["Oct 24 10:00:01 server sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2"]},
        headers={"X-Agent-Token": t2_agent_token},
    )
    assert resp_spoof.status_code == 403
    assert "Host is owned by tenant 'unit_alpha'" in resp_spoof.json()["detail"]


def test_unauthenticated_api_request_rejected(clean_auth_env):
    """When auth is enabled, missing Authorization header triggers 401."""
    resp = client.get("/api/hosts")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]


def test_investigation_note_author_spoofing_prevented(clean_auth_env):
    """
    SEC-CRIT-02: Verifies that in authenticated sessions, a client cannot forge
    the investigation note author or operator identity.
    """
    registry = clean_auth_env["registry"]
    registry.claim("srv-alpha-01", "unit_alpha", exists_in_repo=False)

    repo = clean_auth_env["repo"]
    repo.insert_alerts(
        [
            {
                "id": "ALT-SEC-SPOOF",
                "host_id": "srv-alpha-01",
                "rule_id": "RULE-SSH-BRUTE",
                "title": "SSH Brute Force",
                "severity": "high",
                "status": "new",
                "reason": "Test alert for author spoofing verification",
                "detected_at": "2026-11-08T10:00:00Z",
            }
        ],
        [],
    )
    # Login as operator_alpha
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "operator_alpha", "password": "AlphaPass1234!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # Attempt to forge author as 'ciso_admin'
    res = client.post(
        "/api/alerts/ALT-SEC-SPOOF/investigation",
        json={"status": "investigating", "note": "False positive test", "author": "ciso_admin"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert len(data["notes"]) >= 1
    # Author must be the authenticated user, NOT the forged 'ciso_admin'
    assert data["notes"][0]["author"] == "operator_alpha"


def test_persistent_token_revocation_across_sync(clean_auth_env):
    """
    SEC-CRIT-01: Verifies that token revocation is persistently stored and synced,
    guaranteeing multi-worker consistency.
    """
    user = AuthUser(username="test_worker_user", tenant="unit_alpha", role="engineer")
    token, _ = issue_token(user)
    # Token valid initially
    claims = decode_token(token)
    assert claims["sub"] == "test_worker_user"

    # Revoke token
    revoke_token(token)

    # Must be rejected immediately
    with pytest.raises(ValueError, match="revoked"):
        decode_token(token)


def test_client_ip_resolution_from_reverse_proxy_header():
    """
    SEC-HIGH-01: Verifies extract_client_ip prioritizes X-Forwarded-For over proxy client IP.
    """
    from starlette.requests import Request
    from aegis_backend.tenancy import extract_client_ip

    scope = {
        "type": "http",
        "client": ("127.0.0.1", 54321),
        "headers": [(b"x-forwarded-for", b"203.0.113.195, 127.0.0.1")],
    }
    req = Request(scope)
    resolved_ip = extract_client_ip(req)
    assert resolved_ip == "203.0.113.195"


def test_cli_credential_sanitizer_without_space():
    """
    SEC-MED-02: Verifies that command line password flags without space (-pPassword)
    are detected and redacted properly.
    """
    from aegis_backend.sanitizer import TelemetrySanitizer

    raw_cmd = 'type=EXECVE msg=audit(1762002180.123:4503): argc=2 a0="mysql" a1="-pSuperSecretPass123"'
    is_safe, violation = TelemetrySanitizer.inspect_line(raw_cmd)
    assert is_safe is False
    assert violation == "cli_credential_detected"

    sanitized = TelemetrySanitizer.sanitize_text(raw_cmd)
    assert "SuperSecretPass123" not in sanitized
    assert "[REDACTED_CLI_ARG]" in sanitized


def test_rules_engine_naive_datetime_handling():
    """
    SEC-LOW-01: Verifies that naive ISO timestamps are normalized to UTC timezone-aware
    to prevent TypeError during subtraction.
    """
    from aegis_backend.rules_engine import RulesEngine
    from datetime import timezone

    engine = RulesEngine()
    naive_iso = "2026-11-08T18:00:00"
    dt = engine._parse_timestamp(naive_iso)
    assert dt.tzinfo is not None
    assert dt.tzinfo == timezone.utc
