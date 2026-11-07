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

        parsed = self._parse_ssh_key_tamper_log(line, event_id_prefix)
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

        parsed = self._parse_account_management_log(line, event_id_prefix)
        if parsed:
            return parsed

        parsed = self._parse_firewall_or_kernel_log(line, event_id_prefix)
        if parsed:
            return parsed

        parsed = self._parse_cron_or_systemd_log(line, event_id_prefix)
        if parsed:
            return parsed

        parsed = self._parse_web_log(line, event_id_prefix)
        if parsed:
            return parsed

        parsed = self._parse_ssh_key_tamper_log(line, event_id_prefix)
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

    def _parse_account_management_log(self, line: str, prefix: str) -> Optional[LogEventInput]:
        """
        Source 2: User & Group Account Management (useradd, usermod, gpasswd, passwd).
        Detects backdoor account creation, UID 0 assignment, and privilege group additions.
        """
        # Pattern 1: useradd new user
        useradd_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+useradd(?:\[(\d+)\])?:\s+new user:\s+name=([^,\s]+)(?:,\s*UID=(\d+))?",
            line,
        )
        if useradd_match:
            ts_raw, host, pid, new_user, uid_str = useradd_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            pid_id = pid or str(abs(hash(line)) % 100000)
            uid_val = str(uid_str) if uid_str is not None else None
            return LogEventInput(
                event_id=f"{prefix}-ACCT-NEW-{pid_id}",
                timestamp=ts_iso,
                event_type="account_created",
                user=new_user.strip(),
                details={
                    "service": "useradd",
                    "host": host,
                    "pid": int(pid) if pid else None,
                    "created_user": new_user.strip(),
                    "uid": uid_val,
                },
            )

        # Pattern 2: usermod / gpasswd adding user to group (e.g., sudo, root, wheel, admin, docker)
        grp_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+(?:usermod|gpasswd)(?:\[(\d+)\])?:\s+add\s+'([^']+)'\s+to\s+(?:shadow\s+)?group\s+'([^']+)'",
            line,
        )
        if grp_match:
            ts_raw, host, pid, target_user, group_name = grp_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            pid_id = pid or str(abs(hash(line)) % 100000)
            return LogEventInput(
                event_id=f"{prefix}-ACCT-GRP-{pid_id}",
                timestamp=ts_iso,
                event_type="privilege_group_added",
                user=target_user.strip(),
                details={
                    "service": "usermod",
                    "host": host,
                    "pid": int(pid) if pid else None,
                    "target_user": target_user.strip(),
                    "group": group_name.strip(),
                },
            )

        # Pattern 3: passwd password changed
        pw_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+passwd(?:\[(\d+)\])?:\s+pam_unix\(passwd:chauthtok\):\s+password changed for\s+(\S+)",
            line,
        )
        if pw_match:
            ts_raw, host, pid, target_user = pw_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            pid_id = pid or str(abs(hash(line)) % 100000)
            return LogEventInput(
                event_id=f"{prefix}-ACCT-PASSWD-{pid_id}",
                timestamp=ts_iso,
                event_type="password_changed",
                user=target_user.strip(),
                details={
                    "service": "passwd",
                    "host": host,
                    "pid": int(pid) if pid else None,
                    "target_user": target_user.strip(),
                },
            )

        return None

    def _parse_firewall_or_kernel_log(self, line: str, prefix: str) -> Optional[LogEventInput]:
        """
        Source 3: Firewall (UFW / iptables) & Kernel Security Logs.
        Detects network port scanning and binary segmentation faults (exploit crashes).
        """
        # Pattern 1: UFW BLOCK
        if "[UFW BLOCK]" in line:
            ts_match = re.match(r"^(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:", line)
            ts_iso = self._parse_syslog_timestamp(ts_match.group(1)) if ts_match else None
            host = ts_match.group(2) if ts_match else "unknown"
            src_m = re.search(r"\bSRC=(\S+)", line)
            dst_m = re.search(r"\bDST=(\S+)", line)
            proto_m = re.search(r"\bPROTO=(\S+)", line)
            dpt_m = re.search(r"\bDPT=(\d+)", line)
            src_ip = src_m.group(1) if src_m else None
            dst_port = int(dpt_m.group(1)) if dpt_m else None
            return LogEventInput(
                event_id=f"{prefix}-FW-BLOCK-{abs(hash(line)) % 100000}",
                timestamp=ts_iso,
                event_type="firewall_block",
                source_ip=src_ip,
                details={
                    "service": "ufw",
                    "host": host,
                    "dest_ip": dst_m.group(1) if dst_m else None,
                    "protocol": proto_m.group(1) if proto_m else "TCP",
                    "dest_port": dst_port,
                },
            )

        # Pattern 2: Kernel segfault
        seg_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+kernel:\s*(?:\[\s*\d+\.\d+\]\s*)?([^\[\s]+)\[(\d+)\]:\s+segfault at\s+(\S+).*?\bin\s+([^\[\s]+)",
            line,
        )
        if seg_match:
            ts_raw, host, proc_name, pid, addr, module_name = seg_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            return LogEventInput(
                event_id=f"{prefix}-KERN-SEGFAULT-{pid}",
                timestamp=ts_iso,
                event_type="kernel_segfault",
                details={
                    "service": "kernel",
                    "host": host,
                    "process_name": proc_name,
                    "pid": int(pid),
                    "fault_address": addr,
                    "library": module_name,
                    "module": module_name,
                },
            )

        return None

    def _parse_cron_or_systemd_log(self, line: str, prefix: str) -> Optional[LogEventInput]:
        """
        Source 4: Systemd Service Lifecycle & Cron Persistence.
        Detects suspicious cron execution and critical security service termination.
        """
        # Pattern 1: Cron execution
        cron_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+CRON\[(\d+)\]:\s+\((\S+)\)\s+CMD\s+\((.+)\)$",
            line,
        )
        if cron_match:
            ts_raw, host, pid, user, cmd = cron_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            return LogEventInput(
                event_id=f"{prefix}-CRON-CMD-{pid}",
                timestamp=ts_iso,
                event_type="cron_execution",
                user=user.strip(),
                command=cmd.strip(),
                details={
                    "service": "cron",
                    "host": host,
                    "pid": int(pid),
                    "command": cmd.strip(),
                },
            )

        # Pattern 2a: Systemd Ubuntu 24.04 unit deactivated: "systemd[1]: ufw.service: Deactivated successfully."
        deact_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+systemd\[1\]:\s+([^\s:]+?\.service):\s+Deactivated successfully",
            line,
            re.IGNORECASE,
        )
        if deact_match:
            ts_raw, host, unit_name = deact_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            return LogEventInput(
                event_id=f"{prefix}-SYSD-STOP-{abs(hash(line)) % 100000}",
                timestamp=ts_iso,
                event_type="service_stopped",
                details={
                    "service": "systemd",
                    "host": host,
                    "action": "deactivated",
                    "unit": unit_name.lower(),
                },
            )

        # Pattern 2b: Systemd Stopped/Stopping message
        sysd_match = re.search(
            r"^(?:(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(\S+)\s+systemd\[1\]:\s+(Stopped|Stopping)\s+([^\s]+?)(?:\.service)?(?:\s+-\s+(.+))?\.?$",
            line,
        )
        if sysd_match:
            ts_raw, host, action, unit_name, desc = sysd_match.groups()
            ts_iso = self._parse_syslog_timestamp(ts_raw) if ts_raw else None
            clean_unit = unit_name.lower().replace(".service", "")
            return LogEventInput(
                event_id=f"{prefix}-SYSD-STOP-{abs(hash(line)) % 100000}",
                timestamp=ts_iso,
                event_type="service_stopped",
                details={
                    "service": "systemd",
                    "host": host,
                    "action": action.lower(),
                    "unit": f"{clean_unit}.service",
                    "unit_description": desc or unit_name,
                    "description": desc,
                },
            )

        return None

    def _parse_web_log(self, line: str, prefix: str) -> Optional[LogEventInput]:
        """
        Source 1: Web Server Access & Error Logs (Nginx & Apache2).
        Applies High-Signal Security Pre-Filtering:
        - Captures path traversal, LFI, sensitive file (.env, .git, /etc/passwd), SQLi/Command Injection probes.
        - Captures HTTP 401/403/404/5xx error responses while dropping benign 200 OK static traffic.
        """
        web_match = re.match(
            r'^(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)\s+HTTP/[\d.]+"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?',
            line,
        )
        if web_match:
            src_ip, ident_user, ts_apache, method, uri, status_str, bytes_sent, referer, user_agent = web_match.groups()
            status_code = int(status_str)
            uri_lower = uri.lower()
            ua_lower = (user_agent or "").lower()

            # Parse Apache/Nginx timestamp: '07/Nov/2026:16:40:12 +0000'
            ts_iso = None
            try:
                dt = datetime.strptime(ts_apache, "%d/%b/%Y:%H:%M:%S %z")
                ts_iso = dt.astimezone(timezone.utc).isoformat()
            except Exception:
                ts_iso = None

            attack_category = None
            if any(p in uri_lower for p in ("../", "..%2f", "..%5c", "/etc/passwd", "/etc/shadow", "/proc/self")):
                attack_category = "path_traversal"
            elif any(p in uri_lower for p in ("/.env", "/.git", "/wp-config", "/phpmyadmin", "/id_rsa", "/backup.sql")):
                attack_category = "sensitive_file_probe"
            elif any(p in uri_lower for p in ("union%20select", "union+select", "'%20or%201=1", "select%20from")):
                attack_category = "sql_injection"
            elif any(p in uri_lower for p in (";cat%20", "|wget", "|curl", "cmd=", "exec=", "/bin/sh", "/bin/bash", "${jndi:")):
                attack_category = "command_injection"
            elif any(s in ua_lower for s in ("sqlmap", "nikto", "nmap", "nuclei", "gobuster", "dirbuster", "hydra", "masscan")):
                attack_category = "scanner_user_agent"

            # Smart Pre-Filtering: drop normal 2xx/3xx requests if no attack indicator is present
            if not attack_category and status_code < 400:
                return None

            evt_type = "web_attack_probe" if attack_category else "web_http_error"
            return LogEventInput(
                event_id=f"{prefix}-WEB-{status_code}-{abs(hash(line)) % 100000}",
                timestamp=ts_iso,
                event_type=evt_type,
                source_ip=src_ip,
                user=ident_user if ident_user != "-" else None,
                details={
                    "service": "nginx",
                    "method": method,
                    "http_method": method,
                    "uri": uri,
                    "status_code": status_code,
                    "user_agent": user_agent or "",
                    "attack_category": attack_category or f"http_{status_code}",
                },
            )

        return None

    def _parse_ssh_key_tamper_log(self, line: str, prefix: str) -> Optional[LogEventInput]:
        """
        Source 5: SSH Authorized Keys & Critical File Integrity Tampering.
        Detects additions/modifications to ~/.ssh/authorized_keys or /etc/ssh/sshd_config.
        """
        if "authorized_keys" in line or "/etc/ssh/sshd_config" in line or "/etc/sudoers" in line:
            if any(k in line.lower() for k in ("echo ", ">>", "tee ", "chmod ", "vim ", "nano ", "cp ", "mv ", "sed ")):
                ts_match = re.match(r"^(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)", line)
                ts_iso = self._parse_syslog_timestamp(ts_match.group(1)) if ts_match else None
                host = ts_match.group(2) if ts_match else "unknown"
                sudo_user_m = re.search(r"sudo(?:\[\d+\])?:\s+(\S+)\s*:", line)
                calling_user = sudo_user_m.group(1) if sudo_user_m else None
                cmd_m = re.search(r"COMMAND=(.+)$", line)
                cmd_str = cmd_m.group(1).strip() if cmd_m else line
                file_m = re.search(r"(\/\S*(?:authorized_keys|sshd_config|sudoers)\S*)", line)
                target_file = (
                    file_m.group(1)
                    if file_m
                    else "authorized_keys"
                    if "authorized_keys" in line
                    else "/etc/ssh/sshd_config"
                    if "sshd_config" in line
                    else "/etc/sudoers"
                )
                return LogEventInput(
                    event_id=f"{prefix}-FIM-TAMPER-{abs(hash(line)) % 100000}",
                    timestamp=ts_iso,
                    event_type="critical_file_modified",
                    user=calling_user,
                    command=cmd_str,
                    details={
                        "service": "auditd",
                        "host": host,
                        "target_file": target_file,
                        "command": cmd_str,
                        "raw_summary": line[:240],
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
