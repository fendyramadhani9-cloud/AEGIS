"""
Linux Telemetry Normalization & Parsers for AEGIS.
Parses raw telemetry lines (Auth, Process/Auditd, Network/ss) into standardized
LogEventInput models conforming to AEGIS data contracts.
"""

import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from aegis_agent.schemas import LogEventInput


class LinuxTelemetryParser:
    """
    Normalizes diverse Linux OS telemetry formats into LogEventInput.
    Covers:
    1. SSH / Auth Logs (/var/log/auth.log, /var/log/secure)
    2. Auditd Syscall / Execve Logs (/var/log/audit/audit.log)
    3. Network Connection Snapshots (ss -nt / netstat -nt)
    """

    def __init__(self, default_year: Optional[int] = None):
        self.default_year = default_year or datetime.now(timezone.utc).year

    def parse_line(self, line: str, event_id_prefix: str = "EVT-LINUX") -> Optional[LogEventInput]:
        line = line.strip()
        if not line:
            return None

        # Try parsing in order of specificity
        parsed = self._parse_sshd_log(line, event_id_prefix)
        if parsed:
            return parsed

        parsed = self._parse_sudo_log(line, event_id_prefix)
        if parsed:
            return parsed

        parsed = self._parse_auditd_log(line, event_id_prefix)
        if parsed:
            return parsed

        parsed = self._parse_network_conn(line, event_id_prefix)
        if parsed:
            return parsed

        return None

    def _parse_syslog_timestamp(self, ts_str: str) -> Optional[str]:
        """Converts 'Nov  1 10:00:01' or ISO-8601 into standard ISO-8601 UTC."""
        try:
            # Check ISO format first
            if "T" in ts_str:
                return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).isoformat()
            # Standard syslog format: 'Nov  1 10:00:01'
            dt = datetime.strptime(f"{self.default_year} {ts_str}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            return None

    def _parse_sshd_log(self, line: str, prefix: str) -> Optional[LogEventInput]:
        # Pattern 1: Failed password (matches standard syslog and flexible timestamp formats)
        fail_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+sshd\[(\d+)\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
            line,
        )
        if fail_match:
            ts_raw, host, pid, user, src_ip, port = fail_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            return LogEventInput(
                event_id=f"{prefix}-AUTH-FAIL-{pid}",
                timestamp=ts_iso,
                event_type="auth_failure",
                source_ip=src_ip,
                user=user,
                details={
                    "service": "sshd",
                    "host": host,
                    "pid": int(pid),
                    "source_port": int(port),
                    "reason": "invalid_password",
                },
            )

        # Pattern 2: Accepted password/publickey
        accept_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+sshd\[(\d+)\]:\s+Accepted (password|publickey) for (\S+) from (\S+) port (\d+)",
            line,
        )
        if accept_match:
            ts_raw, host, pid, auth_method, user, src_ip, port = accept_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            return LogEventInput(
                event_id=f"{prefix}-AUTH-SUCCESS-{pid}",
                timestamp=ts_iso,
                event_type="auth_success",
                source_ip=src_ip,
                user=user,
                details={
                    "service": "sshd",
                    "host": host,
                    "pid": int(pid),
                    "source_port": int(port),
                    "auth_method": auth_method,
                },
            )

        # Pattern 3: PAM session opened/closed
        pam_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+sshd\[(\d+)\]:\s+pam_unix\(sshd:session\):\s+session (opened|closed) for user (\S+)",
            line,
        )
        if pam_match:
            ts_raw, host, pid, action, user = pam_match.groups()
            clean_user = re.sub(r"\(.*?\)", "", user)
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            return LogEventInput(
                event_id=f"{prefix}-PAM-{action.upper()}-{pid}",
                timestamp=ts_iso,
                event_type=f"session_{action}",
                user=clean_user,
                details={
                    "service": "pam_unix",
                    "host": host,
                    "pid": int(pid),
                    "action": action,
                },
            )

        return None

    def _parse_sudo_log(self, line: str, prefix: str) -> Optional[LogEventInput]:
        # Pattern 1: Sudo command execution
        # E.g.: Nov 07 15:03:24 fenn sudo[12413]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/journalctl
        sudo_exec_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+sudo(?:\[(\d+)\])?:\s+(\S+)\s*:\s*(?:.*?;\s*)?USER=(\S+)\s*;\s*COMMAND=(.+)$",
            line,
        )
        if sudo_exec_match:
            ts_raw, host, pid, calling_user, target_user, cmd = sudo_exec_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            pid_str = pid if pid else str(abs(hash(line)) % 100000)
            return LogEventInput(
                event_id=f"{prefix}-SUDO-EXEC-{pid_str}",
                timestamp=ts_iso,
                event_type="sudo_execution",
                user=calling_user.strip(),
                details={
                    "service": "sudo",
                    "host": host,
                    "pid": int(pid) if pid else None,
                    "target_user": target_user.strip(),
                    "command": cmd.strip(),
                },
            )

        # Pattern 2: Sudo authentication failure (PAM)
        auth_fail_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+sudo(?:\[(\d+)\])?:\s+pam_unix\(sudo:auth\):\s+authentication failure;\s+.*?\buser=(\S+)",
            line,
        )
        if auth_fail_match:
            ts_raw, host, pid, user = auth_fail_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            pid_str = pid if pid else str(abs(hash(line)) % 100000)
            return LogEventInput(
                event_id=f"{prefix}-SUDO-FAIL-{pid_str}",
                timestamp=ts_iso,
                event_type="sudo_auth_failure",
                user=user.strip(),
                details={
                    "service": "sudo",
                    "host": host,
                    "pid": int(pid) if pid else None,
                    "reason": "authentication_failure",
                },
            )

        # Pattern 3: Sudo PAM session opened/closed
        pam_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+sudo(?:\[(\d+)\])?:\s+pam_unix\(sudo:session\):\s+session (opened|closed) for user (\S+)",
            line,
        )
        if pam_match:
            ts_raw, host, pid, action, user = pam_match.groups()
            clean_user = re.sub(r"\(.*?\)", "", user)
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            pid_str = pid if pid else str(abs(hash(line)) % 100000)
            return LogEventInput(
                event_id=f"{prefix}-SUDO-PAM-{action.upper()}-{pid_str}",
                timestamp=ts_iso,
                event_type=f"session_{action}",
                user=clean_user,
                details={
                    "service": "sudo",
                    "host": host,
                    "pid": int(pid) if pid else None,
                    "action": action,
                },
            )

        return None


    def _parse_auditd_log(self, line: str, prefix: str) -> Optional[LogEventInput]:
        # type=SYSCALL msg=audit(1762002180.123:4501): ... comm="curl" exe="/usr/bin/curl"
        if line.startswith("type=SYSCALL"):
            ts_match = re.search(r"audit\((\d+\.\d+):(\d+)\)", line)
            comm_match = re.search(r'comm="([^"]+)"', line)
            exe_match = re.search(r'exe="([^"]+)"', line)
            pid_match = re.search(r'\bpid=(\d+)', line)
            uid_match = re.search(r'\buid=(\d+)', line)

            epoch_ts = float(ts_match.group(1)) if ts_match else 0.0
            msg_id = ts_match.group(2) if ts_match else "0"
            iso_ts = datetime.fromtimestamp(epoch_ts, tz=timezone.utc).isoformat() if epoch_ts > 0 else None

            process_name = comm_match.group(1) if comm_match else "unknown"
            exe_path = exe_match.group(1) if exe_match else None
            pid = int(pid_match.group(1)) if pid_match else None

            return LogEventInput(
                event_id=f"{prefix}-PROC-SYSCALL-{msg_id}",
                timestamp=iso_ts,
                event_type="process_execution",
                details={
                    "process_name": process_name,
                    "executable": exe_path,
                    "pid": pid,
                    "audit_msg_id": msg_id,
                },
            )

        # type=EXECVE msg=audit(1762002180.123:4501): argc=3 a0="curl" a1="-s" a2="http://..."
        if line.startswith("type=EXECVE"):
            ts_match = re.search(r"audit\((\d+\.\d+):(\d+)\)", line)
            epoch_ts = float(ts_match.group(1)) if ts_match else 0.0
            msg_id = ts_match.group(2) if ts_match else "0"
            iso_ts = datetime.fromtimestamp(epoch_ts, tz=timezone.utc).isoformat() if epoch_ts > 0 else None

            # Collect arguments
            args = re.findall(r'a\d+="([^"]*)"', line)
            cmdline = " ".join(args)

            return LogEventInput(
                event_id=f"{prefix}-PROC-EXECVE-{msg_id}",
                timestamp=iso_ts,
                event_type="process_cmdline",
                details={
                    "command_line": cmdline,
                    "argc": len(args),
                    "audit_msg_id": msg_id,
                },
            )

        return None

    def _parse_network_conn(self, line: str, prefix: str) -> Optional[LogEventInput]:
        # Formats:
        # ESTAB 0 0 10.0.0.15:22 198.51.100.24:54330
        parts = line.split()
        if len(parts) >= 5 and parts[0] in ["ESTAB", "LISTEN", "SYN-SENT", "TIME-WAIT", "CLOSE-WAIT"]:
            state = parts[0]
            local_addr = parts[3]
            remote_addr = parts[4]

            remote_ip = remote_addr.rsplit(":", 1)[0] if ":" in remote_addr else remote_addr
            remote_port = int(remote_addr.rsplit(":", 1)[1]) if ":" in remote_addr and remote_addr.rsplit(":", 1)[1].isdigit() else None

            return LogEventInput(
                event_id=f"{prefix}-NET-{state}-{abs(hash(line)) % 100000}",
                event_type="network_connection",
                source_ip=remote_ip,
                details={
                    "connection_state": state,
                    "local_address": local_addr,
                    "remote_address": remote_addr,
                    "remote_port": remote_port,
                },
            )

        return None

    def parse_batch(self, lines: List[str], prefix: str = "EVT-LINUX") -> List[LogEventInput]:
        """Parses an entire list of raw log lines, ignoring unparseable/corrupted entries."""
        results = []
        for line in lines:
            parsed = self.parse_line(line, prefix)
            if parsed:
                results.append(parsed)
        return results
