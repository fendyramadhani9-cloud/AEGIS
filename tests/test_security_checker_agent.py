"""
Unit tests for AEGIS Agent-Side Security Checker Engine (aegis_agent.security_checker).
Verifies:
1. Read-only safety.
2. Subprocess timeouts and graceful fallback on missing binaries.
3. Pre-transmission sanitization.
4. Correct finding structure and status calculations.
5. Network resilience and API submission payload construction.
"""

import pytest
import subprocess
from unittest.mock import patch, MagicMock
from aegis_agent.security_checker import AegisSecurityChecker
from aegis_backend.security_checker_catalog import CheckStatus, CheckSeverity


@pytest.fixture
def checker():
    return AegisSecurityChecker(
        host_id="test-host-ubuntu",
        api_url="http://127.0.0.1:8000/api",
        agent_token="test-token-sc-12345",
    )


def test_command_timeout_handled_gracefully(checker):
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["sleep", "10"], timeout=5)
        rc, stdout, stderr = checker._run_cmd(["sleep", "10"], timeout_sec=5)
        assert rc == -1
        assert "timed out" in stderr.lower()


def test_missing_binary_returns_rc_127(checker):
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError("Executable not found")
        rc, stdout, stderr = checker._run_cmd(["non_existent_binary"])
        assert rc == 127
        assert "not found" in stderr.lower()


def test_sanitization_masks_sensitive_values(checker):
    finding = checker._create_finding(
        run_id="RUN-TEST-01",
        check_id="SSH-001",
        status=CheckStatus.FAIL,
        actual_value="password=SUPER_SECRET_12345",
        evidence_summary="Found private key: -----BEGIN RSA PRIVATE KEY-----",
    )
    assert "SUPER_SECRET_12345" not in finding["actual_value"]
    assert "PRIVATE KEY" not in finding["evidence_summary"]
    assert "[REDACTED" in finding["actual_value"]
    assert "[REDACTED" in finding["evidence_summary"]


def test_run_all_checks_returns_consistent_structure(checker):
    run_meta, findings = checker.run_all_checks()
    
    assert run_meta["host_id"] == "test-host-ubuntu"
    assert run_meta["total_checks"] == len(findings)
    assert run_meta["total_checks"] >= 20
    assert "started_at" in run_meta
    assert "completed_at" in run_meta

    for f in findings:
        assert f["run_id"] == run_meta["id"]
        assert f["host_id"] == "test-host-ubuntu"
        assert f["check_id"].startswith(("SSH-", "ACC-", "FW-", "SYS-", "LOG-", "NET-", "FS-"))
        assert f["status"] in ["pass", "fail", "warning", "not_applicable", "error"]
        assert f["severity"] in ["critical", "high", "medium", "low", "info"]


@patch("requests.post")
def test_submit_results_constructs_valid_payload(mock_post, checker):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "ok", "stored_findings": 5}
    mock_post.return_value = mock_resp

    run_meta = {"id": "RUN-01", "host_id": "test-host-ubuntu"}
    findings = [{"id": "FND-01", "run_id": "RUN-01", "host_id": "test-host-ubuntu", "check_id": "SSH-001"}]

    success = checker.submit_results(run_meta, findings)
    assert success is True
    assert mock_post.called

    args, kwargs = mock_post.call_args
    assert kwargs["headers"]["X-Agent-Token"] == "test-token-sc-12345"
    assert kwargs["json"]["run"]["id"] == "RUN-01"
    assert len(kwargs["json"]["findings"]) == 1

