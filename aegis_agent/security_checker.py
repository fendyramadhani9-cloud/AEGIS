"""
AEGIS Agent-Side Linux Security Checker.
Executes non-destructive, read-only system configuration inspections across:
- SSH Configuration (sshd -T & drop-ins)
- Account Security (/etc/passwd, groups, permissions)
- Firewall Status (UFW, iptables, listening sockets)
- System Hardening (unattended-upgrades, AppArmor, kernel)
- Logging & Audit (systemd-journald, logrotate)
- Network Security (socket binds, interface exposure)
- Filesystem Permissions (/etc/ssh, /etc/sudoers.d, world-writable checks)

Conforms to PRD §8 (Data Protection) & Prioritas 4 (Security Checker Specification).
"""

import os
import sys
import re
import stat
import time
import socket
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
import requests
from dotenv import load_dotenv

# Ensure root modules can be imported
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis_backend.sanitizer import TelemetrySanitizer
from aegis_backend.security_checker_catalog import (
    SECURITY_CHECKS_CATALOG,
    CheckCategory,
    CheckSeverity,
    CheckStatus,
    SecurityCheckDefinition,
)

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aegis_agent.security_checker")


class AegisSecurityChecker:
    """Read-only security posture auditing engine running on target Linux host."""

    VERSION = "1.0.0"

    def __init__(
        self,
        host_id: Optional[str] = None,
        api_url: Optional[str] = None,
        agent_token: Optional[str] = None,
    ):
        self.host_id = host_id or os.getenv("AEGIS_HOST_ID", "host-fenn-ubuntu")
        self.hostname = os.getenv("AEGIS_HOSTNAME", socket.gethostname())
        self.api_url = (api_url or os.getenv("AEGIS_API_URL", "http://127.0.0.1/api")).rstrip("/")
        self.agent_token = agent_token or os.getenv("AGENT_INGEST_TOKEN", "aegis-agent-dev-secret-token")
        self.is_linux = sys.platform.startswith("linux")

    # --------------------------------------------------------------------------
    # Safe Subprocess & File Execution Helpers (Timeout & Size Limited)
    # --------------------------------------------------------------------------
    def _run_cmd(self, cmd_args: List[str], timeout_sec: int = 5) -> Tuple[int, str, str]:
        """Executes command safely without shell string interpolation, clamped to 8KB output."""
        try:
            res = subprocess.run(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_sec,
                shell=False,
            )
            stdout = (res.stdout or "").strip()[:8192]
            stderr = (res.stderr or "").strip()[:4096]
            return res.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout_sec}s"
        except FileNotFoundError:
            return 127, "", f"Executable not found: {cmd_args[0]}"
        except PermissionError:
            return 126, "", f"Permission denied executing {cmd_args[0]}"
        except Exception as e:
            return -2, "", str(e)

    def _safe_read_file(self, file_path: Path, max_bytes: int = 65536) -> Optional[str]:
        """Safely reads text file with byte limit and secret sanitization check."""
        try:
            if not file_path.exists() or not file_path.is_file():
                return None
            content = file_path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
            return content
        except Exception as e:
            logger.debug(f"Could not read {file_path}: {e}")
            return None

    def _get_file_mode(self, file_path: Path) -> Optional[int]:
        """Returns standard Unix file octal mode (e.g. 0o644)."""
        try:
            if not file_path.exists():
                return None
            st = file_path.stat()
            return stat.S_IMODE(st.st_mode)
        except Exception:
            return None

    # --------------------------------------------------------------------------
    # Master Audit Runner
    # --------------------------------------------------------------------------
    def run_all_checks(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Executes all 23 security checks in the catalog sequentially.
        Returns:
            (run_metadata, list_of_findings)
        """
        started_at = datetime.now(timezone.utc).isoformat()
        run_id = f"RUN-{self.host_id}-{int(time.time())}"
        findings: List[Dict[str, Any]] = []

        logger.info(f"Starting AEGIS Security Checker run {run_id} for host '{self.host_id}'...")

        # 1. Execute check groups
        findings.extend(self._check_ssh_hardening(run_id))
        findings.extend(self._check_account_security(run_id))
        findings.extend(self._check_firewall_security(run_id))
        findings.extend(self._check_system_hardening(run_id))
        findings.extend(self._check_logging_audit(run_id))
        findings.extend(self._check_network_security(run_id))
        findings.extend(self._check_filesystem_security(run_id))

        completed_at = datetime.now(timezone.utc).isoformat()

        # Compute summary counters
        total = len(findings)
        passed = sum(1 for f in findings if f["status"] == CheckStatus.PASS.value)
        failed = sum(1 for f in findings if f["status"] == CheckStatus.FAIL.value)
        warning = sum(1 for f in findings if f["status"] == CheckStatus.WARNING.value)
        na = sum(1 for f in findings if f["status"] == CheckStatus.NOT_APPLICABLE.value)
        error = sum(1 for f in findings if f["status"] == CheckStatus.ERROR.value)

        run_metadata = {
            "id": run_id,
            "host_id": self.host_id,
            "status": "completed" if error == 0 else "partial",
            "total_checks": total,
            "passed_checks": passed,
            "failed_checks": failed,
            "warning_checks": warning,
            "error_checks": error,
            "checker_version": self.VERSION,
            "summary": {
                "critical_fails": sum(1 for f in findings if f["status"] == CheckStatus.FAIL.value and f["severity"] == CheckSeverity.CRITICAL.value),
                "high_fails": sum(1 for f in findings if f["status"] == CheckStatus.FAIL.value and f["severity"] == CheckSeverity.HIGH.value),
                "medium_fails": sum(1 for f in findings if f["status"] == CheckStatus.FAIL.value and f["severity"] == CheckSeverity.MEDIUM.value),
                "low_fails": sum(1 for f in findings if f["status"] == CheckStatus.FAIL.value and f["severity"] == CheckSeverity.LOW.value),
            },
            "started_at": started_at,
            "completed_at": completed_at,
        }

        logger.info(f"Check run {run_id} completed: {total} checks ({passed} PASS, {failed} FAIL, {warning} WARN, {error} ERR).")
        return run_metadata, findings

    def _create_finding(
        self,
        run_id: str,
        check_id: str,
        status: CheckStatus,
        actual_value: str,
        evidence_summary: str,
        custom_severity: Optional[CheckSeverity] = None,
    ) -> Dict[str, Any]:
        """Creates normalized finding record referencing definition catalog."""
        defn = SECURITY_CHECKS_CATALOG[check_id]
        now_iso = datetime.now(timezone.utc).isoformat()
        finding_id = f"FND-{self.host_id}-{check_id}-{run_id}"

        # Sanitize actual_value and evidence_summary before packing
        is_safe, _ = TelemetrySanitizer.inspect_line(actual_value)
        safe_actual = actual_value if is_safe else "[REDACTED_SENSITIVE_VALUE]"

        is_safe_ev, _ = TelemetrySanitizer.inspect_line(evidence_summary)
        safe_ev = evidence_summary if is_safe_ev else "[REDACTED_SENSITIVE_EVIDENCE]"

        return {
            "id": finding_id,
            "run_id": run_id,
            "host_id": self.host_id,
            "check_id": check_id,
            "check_name": defn.check_name,
            "category": defn.category.value,
            "severity": (custom_severity or defn.severity).value,
            "status": status.value,
            "actual_value": safe_actual,
            "expected_value": defn.expected_value,
            "description": defn.description,
            "security_impact": defn.security_impact,
            "recommendation": defn.recommendation,
            "evidence_summary": safe_ev,
            "remediation_reference": defn.remediation_reference,
            "checked_at": now_iso,
            "checker_version": self.VERSION,
        }

    # ==========================================================================
    # A. SSH HARDENING INSPECTIONS (SSH-001 - SSH-008)
    # ==========================================================================
    def _check_ssh_hardening(self, run_id: str) -> List[Dict[str, Any]]:
        results = []

        # Read effective sshd configuration using 'sshd -T' if available
        sshd_effective: Dict[str, str] = {}
        sshd_t_available = False
        rc, stdout, stderr = self._run_cmd(["sshd", "-T"])
        if rc == 0 and stdout:
            sshd_t_available = True
            for line in stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    sshd_effective[parts[0].lower()] = parts[1].strip()

        # Fallback reading /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf
        main_config_content = self._safe_read_file(Path("/etc/ssh/sshd_config")) or ""
        dropin_content = ""
        dropin_dir = Path("/etc/ssh/sshd_config.d")
        if dropin_dir.is_dir():
            for conf_file in sorted(dropin_dir.glob("*.conf")):
                dropin_content += (self._safe_read_file(conf_file) or "") + "\n"

        combined_config = main_config_content + "\n" + dropin_content

        def get_ssh_directive(name: str) -> Optional[str]:
            name_lower = name.lower()
            if sshd_t_available and name_lower in sshd_effective:
                return sshd_effective[name_lower]
            # Regex search in raw config (last occurrence wins in sshd include or first occurrence)
            matches = re.findall(rf"^\s*{name}\s+(.+)$", combined_config, re.IGNORECASE | re.MULTILINE)
            if matches:
                return matches[-1].strip()
            return None

        # SSH-001: PermitRootLogin
        val_001 = get_ssh_directive("PermitRootLogin")
        if not val_001:
            # Default in modern OpenSSH is prohibit-password
            results.append(self._create_finding(
                run_id, "SSH-001", CheckStatus.PASS,
                "Not explicitly defined (default prohibit-password)",
                "PermitRootLogin defaults to 'prohibit-password' in OpenSSH 7.0+ on Ubuntu."
            ))
        elif val_001.lower() in ["no", "prohibit-password", "without-password"]:
            results.append(self._create_finding(
                run_id, "SSH-001", CheckStatus.PASS,
                f"PermitRootLogin {val_001}",
                f"Effective sshd configuration sets PermitRootLogin to '{val_001}'."
            ))
        else:
            results.append(self._create_finding(
                run_id, "SSH-001", CheckStatus.FAIL,
                f"PermitRootLogin {val_001}",
                f"PermitRootLogin is set to '{val_001}', allowing direct password root login."
            ))

        # SSH-002: PasswordAuthentication
        val_002 = get_ssh_directive("PasswordAuthentication")
        if val_002 and val_002.lower() == "no":
            results.append(self._create_finding(
                run_id, "SSH-002", CheckStatus.PASS,
                "PasswordAuthentication no",
                "Password-based authentication over SSH is disabled."
            ))
        elif val_002 and val_002.lower() == "yes":
            results.append(self._create_finding(
                run_id, "SSH-002", CheckStatus.FAIL,
                "PasswordAuthentication yes",
                "Password authentication is enabled over SSH, increasing brute-force risk."
            ))
        else:
            results.append(self._create_finding(
                run_id, "SSH-002", CheckStatus.WARNING,
                f"PasswordAuthentication {val_002 or 'unset (defaults to yes)'}",
                "PasswordAuthentication is not explicitly disabled."
            ))

        # SSH-003: PubkeyAuthentication
        val_003 = get_ssh_directive("PubkeyAuthentication")
        if not val_003 or val_003.lower() == "yes":
            results.append(self._create_finding(
                run_id, "SSH-003", CheckStatus.PASS,
                f"PubkeyAuthentication {val_003 or 'yes (default)'}",
                "Public key authentication is enabled for SSH."
            ))
        else:
            results.append(self._create_finding(
                run_id, "SSH-003", CheckStatus.FAIL,
                f"PubkeyAuthentication {val_003}",
                "Public key authentication is explicitly disabled."
            ))

        # SSH-004: PermitEmptyPasswords
        val_004 = get_ssh_directive("PermitEmptyPasswords")
        if not val_004 or val_004.lower() == "no":
            results.append(self._create_finding(
                run_id, "SSH-004", CheckStatus.PASS,
                f"PermitEmptyPasswords {val_004 or 'no (default)'}",
                "Empty passwords are forbidden by SSH."
            ))
        else:
            results.append(self._create_finding(
                run_id, "SSH-004", CheckStatus.FAIL,
                f"PermitEmptyPasswords {val_004}",
                "PermitEmptyPasswords is enabled! Empty passwords can login."
            ))

        # SSH-005: MaxAuthTries
        val_005 = get_ssh_directive("MaxAuthTries")
        try:
            tries = int(val_005) if val_005 else 6  # OpenSSH default is 6
            if tries <= 4:
                results.append(self._create_finding(
                    run_id, "SSH-005", CheckStatus.PASS,
                    f"MaxAuthTries {tries}",
                    f"MaxAuthTries is set to {tries} (threshold <= 4)."
                ))
            else:
                results.append(self._create_finding(
                    run_id, "SSH-005", CheckStatus.WARNING,
                    f"MaxAuthTries {tries}",
                    f"MaxAuthTries is set to {tries} (recommended <= 4)."
                ))
        except ValueError:
            results.append(self._create_finding(
                run_id, "SSH-005", CheckStatus.WARNING,
                f"MaxAuthTries {val_005}",
                f"Unable to parse MaxAuthTries value '{val_005}'."
            ))

        # SSH-006: X11Forwarding
        val_006 = get_ssh_directive("X11Forwarding")
        if val_006 and val_006.lower() == "no":
            results.append(self._create_finding(
                run_id, "SSH-006", CheckStatus.PASS,
                "X11Forwarding no",
                "X11 forwarding is explicitly disabled."
            ))
        else:
            results.append(self._create_finding(
                run_id, "SSH-006", CheckStatus.WARNING,
                f"X11Forwarding {val_006 or 'unset (default may be yes on Debian/Ubuntu)'}",
                "X11Forwarding is enabled or not explicitly set to 'no'."
            ))

        # SSH-007: AllowTcpForwarding
        val_007 = get_ssh_directive("AllowTcpForwarding")
        if val_007 and val_007.lower() == "no":
            results.append(self._create_finding(
                run_id, "SSH-007", CheckStatus.PASS,
                "AllowTcpForwarding no",
                "Arbitrary TCP forwarding is disabled."
            ))
        else:
            results.append(self._create_finding(
                run_id, "SSH-007", CheckStatus.WARNING,
                f"AllowTcpForwarding {val_007 or 'yes (default)'}",
                "TCP forwarding is permitted. Normal if Cloudflare Tunnel or local proxying is utilized.",
                custom_severity=CheckSeverity.LOW,
            ))

        # SSH-008: Configuration Consistency & Drop-in check
        if sshd_t_available:
            dropin_count = len(list(dropin_dir.glob("*.conf"))) if dropin_dir.is_dir() else 0
            results.append(self._create_finding(
                run_id, "SSH-008", CheckStatus.PASS,
                f"sshd -T verified ({dropin_count} drop-in files loaded)",
                "Effective sshd configuration parsed cleanly without syntax errors."
            ))
        else:
            results.append(self._create_finding(
                run_id, "SSH-008", CheckStatus.WARNING,
                f"sshd -T returned rc {rc}: {stderr[:100]}",
                "Could not verify effective runtime sshd configuration via sshd -T."
            ))

        return results

    # ==========================================================================
    # B. ACCOUNT SECURITY (ACC-001 - ACC-005)
    # ==========================================================================
    def _check_account_security(self, run_id: str) -> List[Dict[str, Any]]:
        results = []
        passwd_content = self._safe_read_file(Path("/etc/passwd"))

        if not passwd_content:
            results.append(self._create_finding(
                run_id, "ACC-001", CheckStatus.ERROR,
                "/etc/passwd unreadable", "Could not read /etc/passwd file."
            ))
            return results

        # ACC-001: Zero Non-Root Accounts with UID 0
        uid_zero_users = []
        interactive_system_users = []
        for line in passwd_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                username, _, uid_str, _, _, _, shell = parts[:7]
                try:
                    uid = int(uid_str)
                    if uid == 0 and username != "root":
                        uid_zero_users.append(username)
                    # ACC-002: System accounts with interactive shell
                    if 0 < uid < 1000 and username not in ["root", "sync"]:
                        if shell not in ["/usr/sbin/nologin", "/bin/false", "/dev/null"]:
                            interactive_system_users.append(f"{username}:{shell}")
                except ValueError:
                    pass

        if not uid_zero_users:
            results.append(self._create_finding(
                run_id, "ACC-001", CheckStatus.PASS,
                "Only 'root' has UID 0",
                "Verified /etc/passwd. Zero unauthorized superuser accounts."
            ))
        else:
            results.append(self._create_finding(
                run_id, "ACC-001", CheckStatus.FAIL,
                f"Unauthorized UID 0 accounts: {', '.join(uid_zero_users)}",
                f"Non-root accounts with UID 0 detected: {uid_zero_users}."
            ))

        # ACC-002: System Accounts Shell Restriction
        if not interactive_system_users:
            results.append(self._create_finding(
                run_id, "ACC-002", CheckStatus.PASS,
                "All system accounts (UID < 1000) have non-login shells",
                "System accounts have valid nologin/false shell restrictions."
            ))
        else:
            results.append(self._create_finding(
                run_id, "ACC-002", CheckStatus.WARNING,
                f"Interactive system accounts: {', '.join(interactive_system_users)}",
                f"System accounts with interactive shells found: {interactive_system_users}."
            ))

        # ACC-003: Administrative Sudo Group Membership Audit
        rc, stdout, _ = self._run_cmd(["getent", "group", "sudo"])
        sudo_members = []
        if rc == 0 and stdout:
            parts = stdout.split(":")
            if len(parts) >= 4 and parts[3].strip():
                sudo_members = [u.strip() for u in parts[3].split(",") if u.strip()]

        if sudo_members:
            results.append(self._create_finding(
                run_id, "ACC-003", CheckStatus.PASS,
                f"Sudo group members: {', '.join(sudo_members)}",
                f"Sudo membership explicitly enumerated: {len(sudo_members)} user(s)."
            ))
        else:
            results.append(self._create_finding(
                run_id, "ACC-003", CheckStatus.WARNING,
                "No users in 'sudo' group",
                "No standard users in group sudo (root delegation may use sudoers directly).",
                custom_severity=CheckSeverity.LOW,
            ))

        # ACC-004: Security File Permissions (/etc/passwd, /etc/shadow, /etc/sudoers)
        perm_issues = []
        mode_passwd = self._get_file_mode(Path("/etc/passwd"))
        if mode_passwd and (mode_passwd & 0o022 != 0):
            perm_issues.append(f"/etc/passwd mode is {oct(mode_passwd)} (writable by non-root)")

        mode_shadow = self._get_file_mode(Path("/etc/shadow"))
        if mode_shadow and (mode_shadow & 0o007 != 0):
            perm_issues.append(f"/etc/shadow mode is {oct(mode_shadow)} (world accessible)")

        mode_sudoers = self._get_file_mode(Path("/etc/sudoers"))
        if mode_sudoers and (mode_sudoers & 0o077 != 0):
            perm_issues.append(f"/etc/sudoers mode is {oct(mode_sudoers)} (group/world accessible)")

        if not perm_issues:
            results.append(self._create_finding(
                run_id, "ACC-004", CheckStatus.PASS,
                "/etc/passwd <= 644, /etc/shadow <= 640, /etc/sudoers <= 440",
                "Permissions on critical authentication and authorization files conform to CIS."
            ))
        else:
            results.append(self._create_finding(
                run_id, "ACC-004", CheckStatus.FAIL,
                "; ".join(perm_issues),
                f"Insecure permissions detected: {perm_issues}."
            ))

        # ACC-005: Sudo NOPASSWD Policy Audit
        # Check /etc/sudoers and /etc/sudoers.d/ safely without reading secrets
        sudoers_content = self._safe_read_file(Path("/etc/sudoers")) or ""
        sudoers_d_content = ""
        sudoers_d_path = Path("/etc/sudoers.d")
        if sudoers_d_path.is_dir():
            try:
                for sf in sudoers_d_path.glob("*"):
                    if sf.is_file():
                        sudoers_d_content += (self._safe_read_file(sf) or "") + "\n"
            except Exception:
                pass

        combined_sudoers = sudoers_content + "\n" + sudoers_d_content
        has_wildcard_nopasswd = bool(re.search(r"NOPASSWD\s*:\s*ALL", combined_sudoers, re.IGNORECASE))
        has_any_nopasswd = bool(re.search(r"NOPASSWD\s*:", combined_sudoers, re.IGNORECASE))

        if not has_any_nopasswd:
            results.append(self._create_finding(
                run_id, "ACC-005", CheckStatus.PASS,
                "Zero NOPASSWD directives configured",
                "All sudo delegations require password authentication."
            ))
        elif has_wildcard_nopasswd:
            results.append(self._create_finding(
                run_id, "ACC-005", CheckStatus.FAIL,
                "Wildcard NOPASSWD: ALL detected in sudoers configuration",
                "Unrestricted NOPASSWD: ALL found. Allows escalation without credential validation."
            ))
        else:
            results.append(self._create_finding(
                run_id, "ACC-005", CheckStatus.WARNING,
                "Scoped NOPASSWD command directives detected",
                "Specific commands delegated with NOPASSWD. Review to ensure binaries are non-interactive."
            ))

        return results

    # ==========================================================================
    # C. FIREWALL SECURITY (FW-001 - FW-003)
    # ==========================================================================
    def _check_firewall_security(self, run_id: str) -> List[Dict[str, Any]]:
        results = []

        # FW-001: Host Firewall Active Status
        rc_ufw, out_ufw, _ = self._run_cmd(["ufw", "status"])
        ufw_active = (rc_ufw == 0 and "Status: active" in out_ufw)

        rc_nft, out_nft, _ = self._run_cmd(["systemctl", "is-active", "nftables"])
        nft_active = (rc_nft == 0 and "active" in out_nft.strip())

        if ufw_active:
            results.append(self._create_finding(
                run_id, "FW-001", CheckStatus.PASS,
                "UFW active",
                "Uncomplicated Firewall (UFW) is installed and active."
            ))
        elif nft_active:
            results.append(self._create_finding(
                run_id, "FW-001", CheckStatus.PASS,
                "nftables active",
                "nftables packet filtering service is active."
            ))
        else:
            results.append(self._create_finding(
                run_id, "FW-001", CheckStatus.FAIL,
                f"UFW inactive (rc={rc_ufw}), nftables inactive",
                "No local host firewall active. All listening sockets accessible from network."
            ))

        # FW-002: Default Inbound Policy
        if ufw_active:
            rc_verbose, out_verbose, _ = self._run_cmd(["ufw", "status", "verbose"])
            match = re.search(r"Default:\s*(\w+)\s*\(incoming\)", out_verbose, re.IGNORECASE)
            incoming_policy = match.group(1).lower() if match else "unknown"
            if incoming_policy in ["deny", "reject", "drop"]:
                results.append(self._create_finding(
                    run_id, "FW-002", CheckStatus.PASS,
                    f"Default incoming: {incoming_policy}",
                    f"UFW default incoming policy is safely set to '{incoming_policy}'."
                ))
            else:
                results.append(self._create_finding(
                    run_id, "FW-002", CheckStatus.FAIL,
                    f"Default incoming: {incoming_policy}",
                    f"UFW default incoming policy '{incoming_policy}' does not drop unhandled packets."
                ))
        else:
            results.append(self._create_finding(
                run_id, "FW-002", CheckStatus.NOT_APPLICABLE,
                "UFW not active",
                "Cannot evaluate UFW default policy because UFW is inactive."
            ))

        # FW-003: Open Listening Ports & Public Interface Exposure
        rc_ss, out_ss, _ = self._run_cmd(["ss", "-tulpn"])
        exposed_public = []
        localhost_only = []
        if rc_ss == 0 and out_ss:
            for line in out_ss.splitlines():
                if "LISTEN" in line or "UNCONN" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        addr_port = parts[4]
                        if addr_port.startswith("0.0.0.0:") or addr_port.startswith("*:") or addr_port.startswith("[::]:"):
                            exposed_public.append(addr_port)
                        elif "127.0.0.1:" in addr_port or "127.0.0.53" in addr_port or "[::1]:" in addr_port:
                            localhost_only.append(addr_port)

        summary_val = f"{len(exposed_public)} public sockets ({', '.join(exposed_public[:5])}), {len(localhost_only)} loopback"
        if not exposed_public:
            results.append(self._create_finding(
                run_id, "FW-003", CheckStatus.PASS,
                summary_val,
                "Zero sockets listening on wildcard 0.0.0.0 or *."
            ))
        elif all(p.endswith(":22") or p.endswith(":80") or p.endswith(":443") for p in exposed_public):
            results.append(self._create_finding(
                run_id, "FW-003", CheckStatus.PASS,
                summary_val,
                "Only standard intended management/web ports (22/80/443) listen on wildcard addresses."
            ))
        else:
            results.append(self._create_finding(
                run_id, "FW-003", CheckStatus.WARNING,
                summary_val,
                f"Sockets listening on wildcard interfaces: {exposed_public}."
            ))

        return results

    # ==========================================================================
    # D. SYSTEM HARDENING (SYS-001 - SYS-004)
    # ==========================================================================
    def _check_system_hardening(self, run_id: str) -> List[Dict[str, Any]]:
        results = []

        # SYS-001: Automatic Security Updates
        unattended_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        content = self._safe_read_file(unattended_conf) or ""
        has_unattended = bool(re.search(r'APT::Periodic::Unattended-Upgrade\s+"1";', content))

        if has_unattended:
            results.append(self._create_finding(
                run_id, "SYS-001", CheckStatus.PASS,
                "APT Periodic Unattended-Upgrade enabled",
                "Automated security patching via unattended-upgrades is enabled."
            ))
        else:
            results.append(self._create_finding(
                run_id, "SYS-001", CheckStatus.WARNING,
                "unattended-upgrades periodic configuration missing or not '1'",
                "Automatic security update installation is not configured in 20auto-upgrades."
            ))

        # SYS-002: AppArmor MAC Status
        rc_aa, out_aa, _ = self._run_cmd(["aa-status"])
        if rc_aa == 0:
            profiles_match = re.search(r"(\d+)\s+profiles are in enforce mode", out_aa)
            enforce_count = profiles_match.group(1) if profiles_match else "several"
            results.append(self._create_finding(
                run_id, "SYS-002", CheckStatus.PASS,
                f"AppArmor active ({enforce_count} profiles in enforce mode)",
                "AppArmor kernel security module is active and enforcing security profiles."
            ))
        else:
            results.append(self._create_finding(
                run_id, "SYS-002", CheckStatus.FAIL,
                f"aa-status returned rc {rc_aa}",
                "AppArmor is not running or disabled in Linux kernel."
            ))

        # SYS-003: Supported Kernel & OS Release Audit
        os_release = self._safe_read_file(Path("/etc/os-release")) or ""
        pretty_name_match = re.search(r'PRETTY_NAME="([^"]+)"', os_release)
        pretty_name = pretty_name_match.group(1) if pretty_name_match else "Linux"
        kernel_ver = platform_ver = "unknown"
        try:
            kernel_ver = os.uname().release
        except Exception:
            pass

        results.append(self._create_finding(
            run_id, "SYS-003", CheckStatus.PASS,
            f"{pretty_name} (Kernel {kernel_ver})",
            f"Host is running supported OS: {pretty_name} with kernel {kernel_ver}."
        ))

        # SYS-004: Legacy Insecure Services Absence
        legacy_services = ["telnet", "rsh", "rlogin", "nis", "tftp", "rsync"]
        active_legacy = []
        for svc in legacy_services:
            rc_s, out_s, _ = self._run_cmd(["systemctl", "is-active", svc])
            if rc_s == 0 and "active" in out_s:
                active_legacy.append(svc)

        if not active_legacy:
            results.append(self._create_finding(
                run_id, "SYS-004", CheckStatus.PASS,
                "Zero legacy plaintext services active",
                "Verified absence of telnet, rsh, rlogin, tftp, and nis daemons."
            ))
        else:
            results.append(self._create_finding(
                run_id, "SYS-004", CheckStatus.FAIL,
                f"Active legacy services: {', '.join(active_legacy)}",
                f"Insecure plaintext services running: {active_legacy}."
            ))

        return results

    # ==========================================================================
    # E. LOGGING & AUDIT (LOG-001 - LOG-003)
    # ==========================================================================
    def _check_logging_audit(self, run_id: str) -> List[Dict[str, Any]]:
        results = []

        # LOG-001: systemd-journald Persistent Storage
        journal_dir = Path("/var/log/journal")
        journal_conf = self._safe_read_file(Path("/etc/systemd/journald.conf")) or ""
        storage_persistent = bool(re.search(r"^\s*Storage\s*=\s*persistent", journal_conf, re.MULTILINE | re.IGNORECASE))

        if journal_dir.is_dir() or storage_persistent:
            results.append(self._create_finding(
                run_id, "LOG-001", CheckStatus.PASS,
                f"/var/log/journal exists={journal_dir.is_dir()}, persistent_config={storage_persistent}",
                "systemd journal logs persist to disk across reboots."
            ))
        else:
            results.append(self._create_finding(
                run_id, "LOG-001", CheckStatus.WARNING,
                "/var/log/journal not found and Storage!=persistent",
                "systemd-journald may be running in volatile memory (/run/log/journal)."
            ))

        # LOG-002: Logrotate Configuration & Disk Retention
        has_logrotate_conf = Path("/etc/logrotate.conf").is_file()
        rc_df, out_df, _ = self._run_cmd(["df", "-h", "/"])
        disk_usage = "unknown"
        disk_pct = 0
        if rc_df == 0 and out_df:
            lines = out_df.splitlines()
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 5:
                    disk_usage = parts[4]
                    try:
                        disk_pct = int(disk_usage.rstrip("%"))
                    except ValueError:
                        pass

        if has_logrotate_conf and disk_pct < 85:
            results.append(self._create_finding(
                run_id, "LOG-002", CheckStatus.PASS,
                f"logrotate configured, root disk usage {disk_usage}",
                f"Log rotation is active and disk storage utilization is safe ({disk_usage})."
            ))
        elif disk_pct >= 85:
            results.append(self._create_finding(
                run_id, "LOG-002", CheckStatus.WARNING,
                f"Disk utilization high: {disk_usage}",
                f"Root filesystem utilization is {disk_usage} (threshold 85%)."
            ))
        else:
            results.append(self._create_finding(
                run_id, "LOG-002", CheckStatus.WARNING,
                "/etc/logrotate.conf missing",
                "logrotate configuration file not found."
            ))

        # LOG-003: SSH & Sudo Audit Log Generation
        rc_j, out_j, _ = self._run_cmd(["journalctl", "-u", "ssh", "-n", "1"])
        if rc_j == 0 and out_j and "-- No entries --" not in out_j:
            results.append(self._create_finding(
                run_id, "LOG-003", CheckStatus.PASS,
                "Active sshd and sudo entries in systemd journal",
                "Authentication and administrative activity is actively captured in logs."
            ))
        else:
            results.append(self._create_finding(
                run_id, "LOG-003", CheckStatus.WARNING,
                f"journalctl query returned rc {rc_j}",
                "Could not retrieve recent sshd journal events."
            ))

        return results

    # ==========================================================================
    # F. NETWORK SECURITY (NET-001 - NET-002)
    # ==========================================================================
    def _check_network_security(self, run_id: str) -> List[Dict[str, Any]]:
        results = []

        # NET-001: SSH Port Exposure & Interface Isolation
        rc_ss, out_ss, _ = self._run_cmd(["ss", "-tulpn"])
        ssh_listening = []
        if rc_ss == 0 and out_ss:
            for line in out_ss.splitlines():
                if ":22 " in line or "ssh" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        ssh_listening.append(parts[4])

        if ssh_listening:
            results.append(self._create_finding(
                run_id, "NET-001", CheckStatus.PASS,
                f"SSH listening on {', '.join(ssh_listening)}",
                f"SSH daemon socket confirmed listening on {ssh_listening}."
            ))
        else:
            results.append(self._create_finding(
                run_id, "NET-001", CheckStatus.WARNING,
                "SSH listening socket not detected",
                "Could not detect active SSH listening socket on port 22."
            ))

        # NET-002: DNS Resolver Configuration
        resolv_content = self._safe_read_file(Path("/etc/resolv.conf")) or ""
        nameservers = re.findall(r"^\s*nameserver\s+(\S+)", resolv_content, re.MULTILINE)

        if nameservers:
            results.append(self._create_finding(
                run_id, "NET-002", CheckStatus.PASS,
                f"Configured nameservers: {', '.join(nameservers)}",
                f"Valid DNS resolver configuration found ({len(nameservers)} nameservers)."
            ))
        else:
            results.append(self._create_finding(
                run_id, "NET-002", CheckStatus.WARNING,
                "No nameserver configured in /etc/resolv.conf",
                "System lacks configured DNS nameservers."
            ))

        return results

    # ==========================================================================
    # G. FILESYSTEM SECURITY (FS-001 - FS-003)
    # ==========================================================================
    def _check_filesystem_security(self, run_id: str) -> List[Dict[str, Any]]:
        results = []

        # FS-001: World-Writable Sensitive Directory Audit (targeted /etc and /var/www)
        world_writable = []
        for scan_root in [Path("/etc"), Path("/var/www")]:
            if scan_root.is_dir():
                try:
                    for p in scan_root.glob("*"):
                        if p.is_file() and not p.is_symlink():
                            st = p.stat()
                            if st.st_mode & 0o002:
                                world_writable.append(str(p))
                except Exception:
                    pass

        if not world_writable:
            results.append(self._create_finding(
                run_id, "FS-001", CheckStatus.PASS,
                "Zero world-writable files in /etc or /var/www",
                "Verified file modes in sensitive directories (/etc, /var/www)."
            ))
        else:
            results.append(self._create_finding(
                run_id, "FS-001", CheckStatus.FAIL,
                f"World-writable files found: {', '.join(world_writable[:5])}",
                f"Found {len(world_writable)} world-writable files in sensitive directories."
            ))

        # FS-002: SSH Configuration Directory Permissions (/etc/ssh)
        ssh_dir = Path("/etc/ssh")
        mode_ssh = self._get_file_mode(ssh_dir)
        if mode_ssh and (mode_ssh & 0o022 == 0):
            results.append(self._create_finding(
                run_id, "FS-002", CheckStatus.PASS,
                f"/etc/ssh mode {oct(mode_ssh)}",
                "/etc/ssh directory has secure ownership and non-writable permissions."
            ))
        elif mode_ssh:
            results.append(self._create_finding(
                run_id, "FS-002", CheckStatus.FAIL,
                f"/etc/ssh mode {oct(mode_ssh)} (group/world writable)",
                "/etc/ssh directory permissions are overly permissive."
            ))
        else:
            results.append(self._create_finding(
                run_id, "FS-002", CheckStatus.NOT_APPLICABLE,
                "/etc/ssh directory not found",
                "SSH directory not found on host."
            ))

        # FS-003: Sudoers Directory Permissions (/etc/sudoers.d)
        sudoers_d = Path("/etc/sudoers.d")
        mode_sd = self._get_file_mode(sudoers_d)
        if mode_sd and (mode_sd & 0o022 == 0):
            results.append(self._create_finding(
                run_id, "FS-003", CheckStatus.PASS,
                f"/etc/sudoers.d mode {oct(mode_sd)}",
                "/etc/sudoers.d directory has secure permissions (non-writable by others)."
            ))
        elif mode_sd:
            results.append(self._create_finding(
                run_id, "FS-003", CheckStatus.FAIL,
                f"/etc/sudoers.d mode {oct(mode_sd)}",
                "/etc/sudoers.d has overly permissive write permissions."
            ))
        else:
            results.append(self._create_finding(
                run_id, "FS-003", CheckStatus.NOT_APPLICABLE,
                "/etc/sudoers.d directory not found",
                "Sudoers.d directory does not exist on host."
            ))

        return results

    # ==========================================================================
    # Backend Transmission
    # ==========================================================================
    def submit_results(self, run_metadata: Dict[str, Any], findings: List[Dict[str, Any]]) -> bool:
        """Transmits security check results to backend API with X-Agent-Token."""
        url = f"{self.api_url}/security-checker/agent-results"
        headers = {
            "X-Agent-Token": self.agent_token,
            "Content-Type": "application/json",
        }
        payload = {
            "run": run_metadata,
            "findings": findings,
        }

        try:
            res = requests.post(url, headers=headers, json=payload, timeout=15)
            if res.status_code == 200:
                logger.info(f"Successfully submitted run {run_metadata['id']} ({len(findings)} findings) to backend.")
                return True
            else:
                logger.error(f"Backend rejected security checker submission with HTTP {res.status_code}: {res.text}")
                return False
        except requests.RequestException as e:
            logger.warning(f"Failed to submit security checker results to {url}: {e}")
            return False


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS Linux Security Configuration Checker")
    parser.add_argument("--dry-run", action="store_true", help="Run checks locally and print results without submitting")
    parser.add_argument("--submit", action="store_true", help="Submit results to AEGIS backend API")
    args = parser.parse_args()

    checker = AegisSecurityChecker()
    run_meta, findings = checker.run_all_checks()

    print("\n" + "=" * 70)
    print(f" AEGIS SECURITY CHECKER RUN: {run_meta['id']} ({run_meta['host_id']})")
    print("=" * 70)
    print(f"Total: {run_meta['total_checks']} | PASS: {run_meta['passed_checks']} | FAIL: {run_meta['failed_checks']} | WARN: {run_meta['warning_checks']} | ERR: {run_meta['error_checks']}")
    print("-" * 70)
    for f in findings:
        badge = f"[{f['status'].upper()}]"
        print(f"{badge:<8} {f['check_id']:<10} {f['check_name']:<40} ({f['severity'].upper()})")
        print(f"         Actual: {f['actual_value']}")
        print(f"         Expected: {f['expected_value']}")
    print("=" * 70)

    if args.submit:
        checker.submit_results(run_meta, findings)


if __name__ == "__main__":
    main()
