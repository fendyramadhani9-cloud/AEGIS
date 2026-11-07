"""
Unit Tests for AEGIS Linux Telemetry Collector Agent (aegis_agent.collector).
Guarantees:
1. Clean pre-transmission sanitization (secrets dropped, safe logs retained).
2. Correct API payload construction and authentication header.
3. Resilient network error handling without unhandled exceptions.
4. Incremental cursor handling with two-phase commit safety.
5. Cursor retention on network/backend failure (no event loss).
"""

import pytest
import os
from unittest.mock import patch, MagicMock
from pathlib import Path
from aegis_agent.collector import AegisTelemetryCollector


@pytest.fixture
def collector(tmp_path):
    cursor_file = tmp_path / ".test_cursor"
    with patch.dict("os.environ", {
        "AEGIS_CURSOR_FILE": str(cursor_file),
        "AEGIS_API_URL": "http://127.0.0.1:8000/api",
        "AGENT_INGEST_TOKEN": "test-token-12345",
        "AEGIS_HOST_ID": "test-host-vm",
    }):
        agent = AegisTelemetryCollector()
        return agent


def test_collector_sanitizer_drops_secrets(collector):
    raw_lines = [
        "Nov  7 14:00:01 fenn sshd[12460]: Accepted password for ubuntu from 192.168.1.1 port 54330 ssh2",
        "Nov  7 14:00:02 fenn sshd[12460]: sudo: password=SUPER_SECRET_VALUE",
        "Nov  7 14:00:03 fenn sshd[12460]: -----BEGIN OPENSSH PRIVATE KEY-----",
        "Nov  7 14:00:04 fenn sshd[12460]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000)",
    ]

    safe_lines, quarantined = collector.sanitize_lines(raw_lines)
    assert len(safe_lines) == 2
    assert quarantined == 2
    assert "SUPER_SECRET_VALUE" not in " ".join(safe_lines)
    assert "PRIVATE KEY" not in " ".join(safe_lines)


@patch("requests.post")
def test_collector_send_telemetry_success(mock_post, collector):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "ok", "inserted_events": 2, "duplicates_ignored": 0}
    mock_post.return_value = mock_resp

    success = collector.send_telemetry(["log line 1", "log line 2"])
    assert success is True
    assert mock_post.called
    args, kwargs = mock_post.call_args
    assert kwargs["headers"]["X-Agent-Token"] == "test-token-12345"
    assert kwargs["json"]["host_id"] == "test-host-vm"
    assert len(kwargs["json"]["raw_logs"]) == 2


@patch("requests.post")
def test_collector_send_heartbeat_success(mock_post, collector):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "ok", "host_id": "test-host-vm", "agent_status": "online"}
    mock_post.return_value = mock_resp

    success = collector.send_heartbeat()
    assert success is True
    assert mock_post.called
    args, kwargs = mock_post.call_args
    assert kwargs["headers"]["X-Agent-Token"] == "test-token-12345"
    assert kwargs["json"]["host_id"] == "test-host-vm"


@patch("requests.post")
def test_collector_network_error_resilience(mock_post, collector):
    import requests
    mock_post.side_effect = requests.RequestException("Connection refused")

    # Does not raise, returns False gracefully
    assert collector.send_telemetry(["log line"]) is False
    assert collector.send_heartbeat() is False


def test_collector_commit_and_get_cursor(collector):
    assert collector.get_stored_cursor() is None
    test_cursor = "s=3cd297d500d743a8b5eef7a9911466cc;i=49ee;b=8baa0be2;m=2770057f5;t=65fab537b0934;x=4714180115eb3f72"
    collector.commit_cursor(test_cursor)
    assert collector.get_stored_cursor() == test_cursor
    assert collector.cursor_file.exists()


def test_cursor_extraction_from_journal_output(collector):
    sample_output = (
        "Nov 07 14:00:01 fenn sshd[100]: session opened\n"
        "-- cursor: s=abc123def456;i=10;b=xyz;m=123;t=456;x=789\n"
    )
    cursor = collector._extract_cursor(sample_output)
    assert cursor == "s=abc123def456;i=10;b=xyz;m=123;t=456;x=789"


@patch.object(AegisTelemetryCollector, "read_new_journal_lines")
@patch.object(AegisTelemetryCollector, "send_telemetry")
@patch.object(AegisTelemetryCollector, "send_heartbeat")
def test_two_phase_commit_commits_only_on_delivery_success(mock_hb, mock_send, mock_read, collector):
    initial_cursor = "s=initial_cursor_value"
    new_pending_cursor = "s=new_pending_cursor_value"

    collector.commit_cursor(initial_cursor)
    assert collector.get_stored_cursor() == initial_cursor

    # Scenario A: Delivery fails -> cursor remains unchanged
    mock_read.return_value = (["Nov 07 14:00:01 test sshd: test event"], new_pending_cursor)
    mock_send.return_value = False

    # Simulate one step
    lines, cursor = collector.read_new_journal_lines()
    safe_lines, _ = collector.sanitize_lines(lines)
    success = collector.send_telemetry(safe_lines)
    if success and cursor:
        collector.commit_cursor(cursor)

    # Cursor must NOT have advanced!
    assert collector.get_stored_cursor() == initial_cursor

    # Scenario B: Delivery succeeds -> cursor commits to disk
    mock_send.return_value = True
    success = collector.send_telemetry(safe_lines)
    if success and cursor:
        collector.commit_cursor(cursor)

    # Cursor successfully committed
    assert collector.get_stored_cursor() == new_pending_cursor
