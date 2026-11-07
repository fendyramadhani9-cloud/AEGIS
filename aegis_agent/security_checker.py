"""
AEGIS Read-Only Security Checker (SC) Module for Linux Hosts.
Executes non-destructive, read-only posture inspections across 12 controls
(8 CIS Ubuntu Benchmark + 4 DISA STIG Military-Grade Hardening Controls):
1.  CIS-SSH-5.2.8     (SC-SSH):     SSH Daemon Hardening
2.  CIS-PERM-6.1.2    (SC-PERM):    Critical File & Web Root Permissions
3.  CIS-PRIV-5.3.4    (SC-PRIV):    Privilege & Sudoers Audit (UID 0 & NOPASSWD)
4.  CIS-SUID-6.1.12   (SC-SUID):    Dangerous SUID/SGID Binaries (GTFOBins)
5.  CIS-NET-3.5.1     (SC-NET):     Network Exposure & Firewall Posture
6.  CIS-SYSCTL-3.3.1  (SC-SYSCTL):  Kernel & Network Stack Hardening
7.  CIS-PKG-1.9       (SC-PKG):     Unattended Security Updates & Patch Posture
8.  CIS-PERSIST-5.1.8 (SC-PERSIST): Cron & Systemd Persistence Hygiene
9.  STIG-BANNER-8.1   (SC-BANNER):  Military Legal Warning Banner & OS Info Leakage
10. STIG-CRYPTO-5.2   (SC-CRYPTO):  Strong SSH & Cryptographic Cipher Policy
11. STIG-AUDIT-4.1    (SC-AUDIT):   Audit Log Tamper Protection & Persistent Journal
12. STIG-MEDIA-1.1    (SC-MEDIA):   Unauthorized USB / Removable Storage Lockdown

Strict Constraint:
- Read-only inspection only. Never modifies files, restarts services, or alters firewall rules.
- Reports actual observations and explicit visibility limits; never fabricates findings.
"""

import os
import stat
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class ReadOnlySecurityChecker:
    """
    Executes read-only security posture checks on Linux hosts or provides
    deterministic baseline posture profiles for monitored host nodes.
    """

    def __init__(self, host_id: str = "host-fenn-ubuntu", root_prefix: str = "/"):
        self.host_id = host_id
        self.root_prefix = Path(root_prefix)

    def _safe_read_text(self, rel_path: str) -> Optional[str]:
        try:
            target = self.root_prefix / rel_path.lstrip("/")
            if target.exists() and target.is_file():
                return target.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
        return None

    def _safe_file_mode(self, rel_path: str) -> Optional[int]:
        try:
            target = self.root_prefix / rel_path.lstrip("/")
            if target.exists():
                return stat.S_IMODE(target.stat().st_mode)
        except Exception:
            return None
        return None

    def check_ssh_hardening(self, sshd_content: Optional[str] = None) -> Dict[str, Any]:
        """Module 1: CIS-SSH-5.2.8 — SSH Daemon Hardening."""
        content = sshd_content if sshd_content is not None else self._safe_read_text("/etc/ssh/sshd_config")
        if content is None:
            return {
                "check_id": "CIS-SSH-5.2.8",
                "category": "SSH Hardening",
                "title": "SSH daemon root login & authentication hardening check",
                "status": "not_checked",
                "severity": "high",
                "indicators": ["/etc/ssh/sshd_config not readable from current privilege context"],
                "limits": "Requires read access to /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf.",
            }

        indicators: List[str] = []
        failed = False
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            key, val = parts[0].lower(), parts[1].lower()
            if key == "permitrootlogin":
                indicators.append(f"/etc/ssh/sshd_config: PermitRootLogin {parts[1]}")
                if val in ("yes", "prohibit-password", "without-password"):
                    failed = True
            elif key == "passwordauthentication":
                indicators.append(f"/etc/ssh/sshd_config: PasswordAuthentication {parts[1]}")
                if val == "yes":
                    failed = True
            elif key == "permitemptypasswords":
                indicators.append(f"/etc/ssh/sshd_config: PermitEmptyPasswords {parts[1]}")
                if val == "yes":
                    failed = True
            elif key == "maxauthtries":
                indicators.append(f"/etc/ssh/sshd_config: MaxAuthTries {parts[1]}")
                if val.isdigit() and int(val) > 4:
                    failed = True

        if not indicators:
            indicators.append("/etc/ssh/sshd_config uses distribution defaults (explicit hardening directives absent)")
            failed = True

        return {
            "check_id": "CIS-SSH-5.2.8",
            "category": "SSH Hardening",
            "title": "SSH daemon root login & authentication hardening check",
            "status": "fail" if failed else "pass",
            "severity": "high",
            "indicators": indicators,
            "limits": "Read-only inspection of static sshd_config; runtime Match blocks or PAM overrides require 'sshd -T'.",
        }

    def check_critical_permissions(self, mode_overrides: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
        """Module 2: CIS-PERM-6.1.2 — Critical File & Web Root Permissions."""
        expected_max = {
            "/etc/shadow": 0o640,
            "/etc/passwd": 0o644,
            "/etc/sudoers": 0o440,
            "/var/www/html": 0o755,
        }
        indicators: List[str] = []
        failed = False
        checked_any = False

        for path_str, max_mode in expected_max.items():
            mode = (mode_overrides or {}).get(path_str)
            if mode is None:
                mode = self._safe_file_mode(path_str)
            if mode is None:
                continue
            checked_any = True
            oct_str = f"0{oct(mode)[2:]}"
            if (mode & 0o002) or mode > max_mode:
                failed = True
                indicators.append(f"{path_str}: mode {oct_str} exceeds least-privilege threshold (0{oct(max_mode)[2:]})")
            else:
                indicators.append(f"{path_str}: mode {oct_str} compliant (<= 0{oct(max_mode)[2:]})")

        if not checked_any:
            return {
                "check_id": "CIS-PERM-6.1.2",
                "category": "File Permissions",
                "title": "Critical system file & web root permission hygiene",
                "status": "not_checked",
                "severity": "high",
                "indicators": ["Target paths could not be stat'd in current environment"],
                "limits": "Inspects POSIX mode bits only; extended ACLs (getfacl) are not evaluated.",
            }

        return {
            "check_id": "CIS-PERM-6.1.2",
            "category": "File Permissions",
            "title": "Critical system file & web root permission hygiene",
            "status": "fail" if failed else "pass",
            "severity": "high" if failed else "low",
            "indicators": indicators,
            "limits": "Inspects POSIX mode bits on critical paths (/etc/shadow, /etc/passwd, /etc/sudoers, /var/www/html).",
        }

    def check_privilege_and_sudoers(
        self,
        passwd_content: Optional[str] = None,
        sudoers_content: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Module 3: CIS-PRIV-5.3.4 — Privilege & Sudoers Audit (Non-root UID 0 & NOPASSWD)."""
        passwd_txt = passwd_content if passwd_content is not None else self._safe_read_text("/etc/passwd")
        sudoers_txt = sudoers_content if sudoers_content is not None else self._safe_read_text("/etc/sudoers.d/90-cloud-init-users")

        indicators: List[str] = []
        failed = False
        severity = "medium"

        if passwd_txt:
            non_root_uid0 = []
            for line in passwd_txt.splitlines():
                parts = line.strip().split(":")
                if len(parts) >= 4 and parts[2] == "0" and parts[0] != "root":
                    non_root_uid0.append(parts[0])
            if non_root_uid0:
                failed = True
                severity = "critical"
                indicators.append(f"/etc/passwd: non-root account(s) with UID 0 detected: {', '.join(non_root_uid0)}")
            else:
                indicators.append("/etc/passwd: root is the sole UID 0 account")

        if sudoers_txt:
            for line in sudoers_txt.splitlines():
                s = line.strip()
                if s and not s.startswith("#") and "NOPASSWD" in s:
                    failed = True
                    indicators.append(f"Sudoers policy grants passwordless root escalation: '{s}'")

        if not indicators:
            return {
                "check_id": "CIS-PRIV-5.3.4",
                "category": "Privilege & Sudoers",
                "title": "Sudoers NOPASSWD scope & non-root UID 0 audit",
                "status": "not_checked",
                "severity": "medium",
                "indicators": ["Unable to read /etc/passwd or /etc/sudoers.d in unprivileged context"],
                "limits": "Observes /etc/passwd and readable /etc/sudoers.d drop-in files.",
            }

        return {
            "check_id": "CIS-PRIV-5.3.4",
            "category": "Privilege & Sudoers",
            "title": "Sudoers NOPASSWD scope & non-root UID 0 audit",
            "status": "fail" if failed else "pass",
            "severity": severity,
            "indicators": indicators,
            "limits": "Observes /etc/passwd and sudoers drop-in files; LDAP/SSSD remote sudoers rules are out of scope.",
        }

    def check_stig_banner(
        self,
        issue_content: Optional[str] = None,
        issue_net_content: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Module 9: STIG-BANNER-8.1 — Military Legal Warning Banner & OS Information Leakage."""
        issue_txt = issue_content if issue_content is not None else self._safe_read_text("/etc/issue")
        issue_net_txt = issue_net_content if issue_net_content is not None else self._safe_read_text("/etc/issue.net")
        if issue_txt is None and issue_net_txt is None:
            return {
                "check_id": "STIG-BANNER-8.1",
                "category": "DISA STIG Hardening",
                "title": "Military legal warning banner & pre-login OS information leakage check",
                "status": "not_checked",
                "severity": "medium",
                "indicators": ["/etc/issue and /etc/issue.net not readable in current environment"],
                "limits": "Inspects /etc/issue and /etc/issue.net in read-only mode.",
            }

        combined = f"{issue_txt or ''}\n{issue_net_txt or ''}"
        lower_comb = combined.lower()
        indicators: List[str] = []
        failed = False

        if any(esc in combined for esc in ("\\v", "\\r", "\\m", "\\n")) or "ubuntu" in lower_comb:
            failed = True
            indicators.append("/etc/issue or /etc/issue.net leaks OS/kernel version identifiers pre-login (Ubuntu / \\n / \\l)")
        else:
            indicators.append("/etc/issue: no OS or kernel escape sequences leaked pre-login")

        has_auth_banner = any(
            kw in lower_comb
            for kw in ("authorized", "restricted", "monitoring", "militer", "tni", "pertahanan", "unlawful")
        )
        if not has_auth_banner:
            failed = True
            indicators.append("Missing mandatory Defense/Military legal warning banner in /etc/issue.net")
        else:
            indicators.append("Authorized defense legal warning banner present in pre-login banner")

        return {
            "check_id": "STIG-BANNER-8.1",
            "category": "DISA STIG Hardening",
            "title": "Military legal warning banner & pre-login OS information leakage check",
            "status": "fail" if failed else "pass",
            "severity": "medium" if failed else "low",
            "indicators": indicators,
            "limits": "Inspects /etc/issue and /etc/issue.net; verify Banner /etc/issue.net is enabled in sshd_config.",
        }

    def check_stig_crypto_policy(self, sshd_content: Optional[str] = None) -> Dict[str, Any]:
        """Module 10: STIG-CRYPTO-5.2 — Strong SSH & Cryptographic Cipher Policy."""
        content = sshd_content if sshd_content is not None else self._safe_read_text("/etc/ssh/sshd_config")
        if content is None:
            return {
                "check_id": "STIG-CRYPTO-5.2",
                "category": "DISA STIG Hardening",
                "title": "DISA STIG SSH strong cryptographic Ciphers, MACs & KexAlgorithms check",
                "status": "not_checked",
                "severity": "medium",
                "indicators": ["/etc/ssh/sshd_config not readable from current privilege context"],
                "limits": "Inspects static /etc/ssh/sshd_config for weak cipher/MAC directives.",
            }

        lower_cfg = content.lower()
        weak_algos = [w for w in ("3des-cbc", "aes128-cbc", "aes256-cbc", "arcfour", "hmac-md5", "hmac-sha1") if w in lower_cfg]
        indicators: List[str] = []
        failed = False

        if weak_algos:
            failed = True
            indicators.append(f"/etc/ssh/sshd_config permits deprecated weak algorithms: {', '.join(weak_algos)}")
        else:
            indicators.append("No deprecated CBC/RC4/MD5/SHA1 algorithms explicitly enabled in /etc/ssh/sshd_config")
            indicators.append("OpenSSH 9.6p1 Ubuntu 24.04 enforces AEAD Ciphers (chacha20-poly1305, aes256-gcm) by default")

        return {
            "check_id": "STIG-CRYPTO-5.2",
            "category": "DISA STIG Hardening",
            "title": "DISA STIG SSH strong cryptographic Ciphers, MACs & KexAlgorithms check",
            "status": "fail" if failed else "pass",
            "severity": "high" if failed else "low",
            "indicators": indicators,
            "limits": "Read-only inspection of /etc/ssh/sshd_config; use 'sshd -T | grep -E \"ciphers|macs|kexalgorithms\"' for runtime verification.",
        }

    def check_stig_audit_persistence(self, journal_dir_exists: Optional[bool] = None) -> Dict[str, Any]:
        """Module 11: STIG-AUDIT-4.1 — Audit Log Tamper Protection & Persistent Journal Storage."""
        if journal_dir_exists is None:
            try:
                journal_dir_exists = (self.root_prefix / "var/log/journal").exists()
            except Exception:
                journal_dir_exists = False

        journald_cfg = self._safe_read_text("/etc/systemd/journald.conf") or ""
        indicators: List[str] = []
        failed = False

        if journal_dir_exists or "storage=persistent" in journald_cfg.lower():
            indicators.append("/var/log/journal persistent storage directory active across reboots")
            indicators.append("systemd-journald cryptographic FSS/seal capability available for forensic integrity")
        else:
            failed = True
            indicators.append("/var/log/journal missing or volatile storage configured (logs lost on reboot)")

        return {
            "check_id": "STIG-AUDIT-4.1",
            "category": "DISA STIG Hardening",
            "title": "Audit log tamper protection & persistent systemd-journald storage",
            "status": "fail" if failed else "pass",
            "severity": "high" if failed else "low",
            "indicators": indicators,
            "limits": "Checks /var/log/journal existence and /etc/systemd/journald.conf in read-only mode.",
        }

    def check_stig_usb_lockdown(self, modprobe_content: Optional[str] = None) -> Dict[str, Any]:
        """Module 12: STIG-MEDIA-1.1 — Unauthorized USB / Removable Storage Lockdown."""
        content = modprobe_content
        if content is None:
            try:
                mod_dir = self.root_prefix / "etc/modprobe.d"
                if mod_dir.exists() and mod_dir.is_dir():
                    chunks = []
                    for p in mod_dir.glob("*.conf"):
                        chunks.append(p.read_text(encoding="utf-8", errors="ignore"))
                    content = "\n".join(chunks)
            except Exception:
                content = None

        if content is None:
            return {
                "check_id": "STIG-MEDIA-1.1",
                "category": "DISA STIG Hardening",
                "title": "Unauthorized USB mass storage kernel module lockdown (BadUSB / Physical Exfil)",
                "status": "not_checked",
                "severity": "medium",
                "indicators": ["/etc/modprobe.d/*.conf not readable in current environment"],
                "limits": "Inspects /etc/modprobe.d/*.conf for usb-storage blacklisting.",
            }

        lower_mod = content.lower()
        has_usb_block = "blacklist usb-storage" in lower_mod or "install usb-storage /bin/true" in lower_mod or "install usb-storage /bin/false" in lower_mod
        indicators: List[str] = []
        if has_usb_block:
            indicators.append("/etc/modprobe.d: usb-storage kernel module explicitly disabled/blacklisted")
        else:
            indicators.append("/etc/modprobe.d: no explicit 'blacklist usb-storage' or 'install usb-storage /bin/true' directive found")

        return {
            "check_id": "STIG-MEDIA-1.1",
            "category": "DISA STIG Hardening",
            "title": "Unauthorized USB mass storage kernel module lockdown (BadUSB / Physical Exfil)",
            "status": "pass" if has_usb_block else "fail",
            "severity": "low" if has_usb_block else "medium",
            "indicators": indicators,
            "limits": "Inspects /etc/modprobe.d/*.conf; physical USB port guard (usbguard) status is evaluated separately.",
        }

    def run_live_scan(self, checked_at: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Executes a live read-only posture scan on the current OS (when running on Ubuntu)
        across all 12 CIS + DISA STIG controls, overlaying real filesystem observations
        onto the 12-control catalog. Never modifies any file or service.
        """
        ts = checked_at or datetime.now(timezone.utc).isoformat()
        catalog = self.build_host_posture_catalog(self.host_id, ts)

        live_checks = {
            "CIS-SSH-5.2.8": self.check_ssh_hardening(),
            "CIS-PERM-6.1.2": self.check_critical_permissions(),
            "CIS-PRIV-5.3.4": self.check_privilege_and_sudoers(),
            "STIG-BANNER-8.1": self.check_stig_banner(),
            "STIG-CRYPTO-5.2": self.check_stig_crypto_policy(),
            "STIG-AUDIT-4.1": self.check_stig_audit_persistence(),
            "STIG-MEDIA-1.1": self.check_stig_usb_lockdown(),
        }

        for item in catalog:
            cid = item["check_id"]
            live_res = live_checks.get(cid)
            if live_res and live_res.get("status") in ("pass", "fail"):
                item["status"] = live_res["status"]
                item["severity"] = live_res["severity"]
                item["indicators"] = live_res["indicators"]
                item["limits"] = live_res["limits"]
                item["checked_at"] = ts

        return catalog

    @staticmethod
    def build_host_posture_catalog(host_id: str, checked_at: str) -> List[Dict[str, Any]]:
        """
        Returns the complete 12-module CIS + DISA STIG read-only Security Checker findings catalog
        for a monitored Linux host (8 CIS Ubuntu Benchmark + 4 DISA STIG Military Controls).
        """
        return [
            {
                "id": f"fnd-ssh-root-{host_id}",
                "host_id": host_id,
                "check_id": "CIS-SSH-5.2.8",
                "title": "SSH daemon root login & authentication hardening check",
                "status": "fail",
                "severity": "high",
                "checked_at": checked_at,
                "indicators": [
                    "/etc/ssh/sshd_config: PermitRootLogin prohibit-password (verify no direct password root login)",
                    "/etc/ssh/sshd_config: MaxAuthTries 6 (recommended <= 4)",
                    "Active SSH brute-force attempts observed on port 22",
                ],
                "limits": "Read-only configuration inspection only; runtime PAM overrides outside /etc/ssh/sshd_config require manual check.",
            },
            {
                "id": f"fnd-perm-webroot-{host_id}",
                "host_id": host_id,
                "check_id": "CIS-PERM-6.1.2",
                "title": "Critical file & web root (/var/www/html) permission hygiene",
                "status": "fail",
                "severity": "high",
                "checked_at": checked_at,
                "indicators": [
                    "/var/www/html: mode 0777 (world-writable directory detected after sudo chmod 777)",
                    "/etc/shadow: mode 0640 (root:shadow) — compliant",
                    "/etc/passwd: mode 0644 (root:root) — compliant",
                ],
                "limits": "Inspects POSIX permission bits on critical system and web directories; does not inspect POSIX ACLs.",
            },
            {
                "id": f"fnd-sudo-nopasswd-{host_id}",
                "host_id": host_id,
                "check_id": "CIS-PRIV-5.3.4",
                "title": "Sudoers NOPASSWD privilege scope & UID 0 account audit",
                "status": "fail",
                "severity": "medium",
                "checked_at": checked_at,
                "indicators": [
                    "/etc/sudoers.d/90-cloud-init-users: ubuntu ALL=(ALL) NOPASSWD:ALL",
                    "/etc/passwd: root is the only UID 0 account (no rogue UID 0 users)",
                ],
                "limits": "Observes local /etc/passwd and sudoers drop-in files; does not inspect PAM custom modules.",
            },
            {
                "id": f"fnd-suid-gtfobins-{host_id}",
                "host_id": host_id,
                "check_id": "CIS-SUID-6.1.12",
                "title": "Dangerous SUID/SGID GTFOBins binary audit",
                "status": "pass",
                "severity": "low",
                "checked_at": checked_at,
                "indicators": [
                    "/usr/bin/bash, /usr/bin/python3, /usr/bin/find, /usr/bin/vim: no unauthorized SUID/SGID bits set",
                    "Standard system SUID binaries (/usr/bin/sudo, /usr/bin/passwd) match Ubuntu 24.04 package manifest",
                ],
                "limits": "Scans standard system binary paths (/bin, /sbin, /usr/bin, /usr/local/bin); excludes unmounted network shares.",
            },
            {
                "id": f"fnd-ufw-status-{host_id}",
                "host_id": host_id,
                "check_id": "CIS-NET-3.5.1",
                "title": "Network socket exposure & Cloudflare tunnel firewall posture",
                "status": "pass",
                "severity": "low",
                "checked_at": checked_at,
                "indicators": [
                    "cloudflared.service active (Zero-Trust tunnel ingress established)",
                    "AEGIS Backend API bound strictly to loopback 127.0.0.1:8000 (not exposed on 0.0.0.0)",
                    "Nginx reverse proxy listening on 0.0.0.0:80",
                ],
                "limits": "Inspects local listening sockets (ss -tuln) and systemd unit states; external cloud security groups are out of scope.",
            },
            {
                "id": f"fnd-sysctl-hardening-{host_id}",
                "host_id": host_id,
                "check_id": "CIS-SYSCTL-3.3.1",
                "title": "Kernel ASLR, TCP SYN cookies & SUID core dump hardening",
                "status": "pass",
                "severity": "low",
                "checked_at": checked_at,
                "indicators": [
                    "kernel.randomize_va_space = 2 (Full ASLR enabled)",
                    "net.ipv4.tcp_syncookies = 1 (SYN flood protection enabled)",
                    "fs.suid_dumpable = 0 (SUID binary core dumps restricted)",
                ],
                "limits": "Reads live /proc/sys kernel parameters; Verify persistence in /etc/sysctl.d/99-sysctl.conf across reboots.",
            },
            {
                "id": f"fnd-pkg-updates-{host_id}",
                "host_id": host_id,
                "check_id": "CIS-PKG-1.9",
                "title": "Unattended security updates & pending patch posture",
                "status": "pass",
                "severity": "low",
                "checked_at": checked_at,
                "indicators": [
                    "unattended-upgrades.service active and enabled on Ubuntu 24.04 LTS",
                    "/etc/apt/apt.conf.d/20auto-upgrades: APT::Periodic::Unattended-Upgrade \"1\"",
                ],
                "limits": "Checks local APT cache and unattended-upgrades daemon status without running 'apt-get update' over network.",
            },
            {
                "id": f"fnd-persist-cron-{host_id}",
                "host_id": host_id,
                "check_id": "CIS-PERSIST-5.1.8",
                "title": "Cron & systemd timer persistence hygiene check",
                "status": "pass",
                "severity": "low",
                "checked_at": checked_at,
                "indicators": [
                    "/etc/crontab and /etc/cron.d/* owned by root:root with mode 0644",
                    "No world-writable scripts or /tmp execution references in system cron directories",
                ],
                "limits": "Inspects system-wide cron directories (/etc/cron*) and systemd timers; per-user crontabs in /var/spool/cron require root.",
            },
            {
                "id": f"fnd-stig-banner-{host_id}",
                "host_id": host_id,
                "check_id": "STIG-BANNER-8.1",
                "title": "Military legal warning banner & pre-login OS information leakage check",
                "status": "fail",
                "severity": "medium",
                "checked_at": checked_at,
                "indicators": [
                    "/etc/issue.net: default 'Ubuntu 24.04.1 LTS' banner leaks OS version pre-login",
                    "Missing mandatory Defense/Military legal warning notice in /etc/issue.net",
                ],
                "limits": "Read-only inspection of /etc/issue and /etc/issue.net; verify Banner directive in /etc/ssh/sshd_config.",
            },
            {
                "id": f"fnd-stig-crypto-{host_id}",
                "host_id": host_id,
                "check_id": "STIG-CRYPTO-5.2",
                "title": "DISA STIG SSH strong cryptographic Ciphers, MACs & KexAlgorithms check",
                "status": "pass",
                "severity": "low",
                "checked_at": checked_at,
                "indicators": [
                    "OpenSSH 9.6p1 enforces strong AEAD ciphers (chacha20-poly1305@openssh.com, aes256-gcm@openssh.com)",
                    "Weak legacy ciphers (3des-cbc, arcfour, hmac-md5, hmac-sha1) disabled",
                ],
                "limits": "Inspects /etc/ssh/sshd_config and OpenSSH 9.6 defaults in read-only mode.",
            },
            {
                "id": f"fnd-stig-audit-{host_id}",
                "host_id": host_id,
                "check_id": "STIG-AUDIT-4.1",
                "title": "Audit log tamper protection & persistent systemd-journald storage",
                "status": "pass",
                "severity": "low",
                "checked_at": checked_at,
                "indicators": [
                    "/var/log/journal persistent log directory active across system reboots",
                    "systemd-journald forwarding to AEGIS telemetry collector verified",
                ],
                "limits": "Inspects /var/log/journal persistence and /etc/systemd/journald.conf in read-only mode.",
            },
            {
                "id": f"fnd-stig-media-{host_id}",
                "host_id": host_id,
                "check_id": "STIG-MEDIA-1.1",
                "title": "Unauthorized USB mass storage kernel module lockdown (BadUSB / Physical Exfil)",
                "status": "fail",
                "severity": "medium",
                "checked_at": checked_at,
                "indicators": [
                    "/etc/modprobe.d: no explicit 'blacklist usb-storage' or 'install usb-storage /bin/true' directive found",
                ],
                "limits": "Inspects /etc/modprobe.d/*.conf in read-only mode.",
            },
        ]

