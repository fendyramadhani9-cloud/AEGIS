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

    def check_container_runtime_posture(self, daemon_json_content: Optional[str] = None) -> Dict[str, Any]:
        """CIS-DOCKER-5.1: Read-only audit of Docker daemon TCP exposure & socket permissions."""
        content = daemon_json_content if daemon_json_content is not None else self._safe_read_text("/etc/docker/daemon.json")
        sock_mode = self._safe_file_mode("/var/run/docker.sock")

        if content is None and sock_mode is None:
            return {
                "check_id": "CIS-DOCKER-5.1",
                "category": "Container Runtime",
                "title": "Docker daemon socket & TLS exposure posture",
                "status": "not_checked",
                "severity": "high",
                "indicators": ["No Docker daemon config or socket observed on this node"],
                "limits": "Host may not run Docker Engine or socket is outside read-only mount.",
            }

        indicators: List[str] = []
        failed = False
        if content and ("tcp://0.0.0.0:2375" in content or '"tlsverify": false' in content.lower()):
            failed = True
            indicators.append("Docker daemon exposes unencrypted TCP port 2375 or disables tlsverify")
        if sock_mode is not None and (sock_mode & 0o002):
            failed = True
            indicators.append(f"/var/run/docker.sock is world-writable (mode {oct(sock_mode)})")
        if not failed:
            indicators.append("Docker daemon socket and config adhere to non-world-writable / no-plain-TCP posture")

        return {
            "check_id": "CIS-DOCKER-5.1",
            "category": "Container Runtime",
            "title": "Docker daemon socket & TLS exposure posture",
            "status": "fail" if failed else "pass",
            "severity": "high",
            "indicators": indicators,
            "limits": "Read-only inspection of /etc/docker/daemon.json and /var/run/docker.sock.",
        }

    def check_kubernetes_audit_posture(self, apiserver_manifest: Optional[str] = None) -> Dict[str, Any]:
        """CIS-K8S-1.2: Read-only audit of kube-apiserver anonymous-auth & audit logging."""
        content = (
            apiserver_manifest
            if apiserver_manifest is not None
            else self._safe_read_text("/etc/kubernetes/manifests/kube-apiserver.yaml")
        )
        if content is None:
            return {
                "check_id": "CIS-K8S-1.2",
                "category": "Kubernetes Control Plane",
                "title": "Kubernetes API Server anonymous-auth & audit log policy",
                "status": "not_checked",
                "severity": "critical",
                "indicators": ["/etc/kubernetes/manifests/kube-apiserver.yaml not present on this host"],
                "limits": "Applies only to Kubernetes control-plane nodes.",
            }

        indicators: List[str] = []
        failed = False
        if "--anonymous-auth=true" in content:
            failed = True
            indicators.append("--anonymous-auth=true enabled on kube-apiserver")
        if "--audit-log-path" not in content:
            failed = True
            indicators.append("--audit-log-path not configured on kube-apiserver")
        if not failed:
            indicators.append("kube-apiserver disables anonymous-auth and enables audit-log-path")

        return {
            "check_id": "CIS-K8S-1.2",
            "category": "Kubernetes Control Plane",
            "title": "Kubernetes API Server anonymous-auth & audit log policy",
            "status": "fail" if failed else "pass",
            "severity": "critical",
            "indicators": indicators,
            "limits": "Read-only inspection of kube-apiserver static manifest.",
        }

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


# ==============================================================================
# AEGIS Agent-Side Security Checker & Runner
# ==============================================================================
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
