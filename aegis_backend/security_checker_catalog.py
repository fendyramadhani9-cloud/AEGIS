"""
AEGIS Security Checker Catalog & Definition Registry.
Defines all standardized Linux security configuration checks, risk baselines,
severity levels, and remediation guidance conforming to CIS Benchmarks and AEGIS specifications.
"""

from typing import Dict, Any, List, Optional
from enum import Enum
from pydantic import BaseModel, Field


class CheckCategory(str, Enum):
    SSH = "ssh"
    ACCOUNT = "account"
    FIREWALL = "firewall"
    SYSTEM = "system"
    LOGGING = "logging"
    NETWORK = "network"
    FILESYSTEM = "filesystem"


class CheckSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class SecurityCheckDefinition(BaseModel):
    check_id: str
    check_name: str
    category: CheckCategory
    severity: CheckSeverity
    expected_value: str
    description: str
    security_impact: str
    recommendation: str
    remediation_reference: str


# ==============================================================================
# MASTER CATALOG OF SECURITY CHECKS
# ==============================================================================
SECURITY_CHECKS_CATALOG: Dict[str, SecurityCheckDefinition] = {
    # --------------------------------------------------------------------------
    # A. SSH HARDENING (SSH-xxx)
    # --------------------------------------------------------------------------
    "SSH-001": SecurityCheckDefinition(
        check_id="SSH-001",
        check_name="SSH PermitRootLogin Enforcement",
        category=CheckCategory.SSH,
        severity=CheckSeverity.HIGH,
        expected_value="PermitRootLogin no OR prohibit-password",
        description="Verifies that direct SSH login as root is disabled or restricted to public key authentication only.",
        security_impact="Allowing direct root login over SSH facilitates brute-force attacks against the highest privileged account and removes non-repudiation.",
        recommendation="Edit /etc/ssh/sshd_config or drop-in in /etc/ssh/sshd_config.d/ to set 'PermitRootLogin no' (or 'prohibit-password'), then test syntax with 'sshd -t' and reload sshd.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.2.8",
    ),
    "SSH-002": SecurityCheckDefinition(
        check_id="SSH-002",
        check_name="SSH PasswordAuthentication Disablement",
        category=CheckCategory.SSH,
        severity=CheckSeverity.HIGH,
        expected_value="PasswordAuthentication no",
        description="Verifies whether password-based authentication over SSH is disabled in favor of cryptographic public keys.",
        security_impact="Password authentication exposes the host to dictionary, credential stuffing, and brute-force attacks.",
        recommendation="Ensure all authorized users have valid SSH public keys installed in ~/.ssh/authorized_keys, then set 'PasswordAuthentication no' in /etc/ssh/sshd_config.d/01-hardening.conf and restart sshd.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.2.11",
    ),
    "SSH-003": SecurityCheckDefinition(
        check_id="SSH-003",
        check_name="SSH PubkeyAuthentication Enablement",
        category=CheckCategory.SSH,
        severity=CheckSeverity.HIGH,
        expected_value="PubkeyAuthentication yes",
        description="Verifies that public key authentication is enabled for SSH.",
        security_impact="If public key authentication is disabled while password authentication is also off, administrative access may be blocked; if password auth is on, security is compromised.",
        recommendation="Set 'PubkeyAuthentication yes' in /etc/ssh/sshd_config and verify user keys have correct permissions (0600).",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.2.12",
    ),
    "SSH-004": SecurityCheckDefinition(
        check_id="SSH-004",
        check_name="SSH PermitEmptyPasswords Disablement",
        category=CheckCategory.SSH,
        severity=CheckSeverity.CRITICAL,
        expected_value="PermitEmptyPasswords no",
        description="Verifies that accounts with empty password fields cannot authenticate over SSH.",
        security_impact="Enabling empty passwords allows immediate unauthenticated access to any account configured without a password.",
        recommendation="Ensure 'PermitEmptyPasswords no' is explicitly configured in sshd_config.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.2.9",
    ),
    "SSH-005": SecurityCheckDefinition(
        check_id="SSH-005",
        check_name="SSH MaxAuthTries Limitation",
        category=CheckCategory.SSH,
        severity=CheckSeverity.MEDIUM,
        expected_value="MaxAuthTries <= 4",
        description="Verifies that the maximum number of authentication attempts per connection is limited to 4 or fewer.",
        security_impact="High authentication attempt limits facilitate online brute-force attacks within a single TCP session.",
        recommendation="Set 'MaxAuthTries 3' or 'MaxAuthTries 4' in sshd_config.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.2.5",
    ),
    "SSH-006": SecurityCheckDefinition(
        check_id="SSH-006",
        check_name="SSH X11Forwarding Disablement",
        category=CheckCategory.SSH,
        severity=CheckSeverity.LOW,
        expected_value="X11Forwarding no",
        description="Verifies that SSH graphical X11 forwarding is disabled on headless servers.",
        security_impact="X11 forwarding can allow an attacker on the server to snoop keystrokes or manipulate user windows on the client machine.",
        recommendation="Set 'X11Forwarding no' in /etc/ssh/sshd_config.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.2.4",
    ),
    "SSH-007": SecurityCheckDefinition(
        check_id="SSH-007",
        check_name="SSH AllowTcpForwarding Review",
        category=CheckCategory.SSH,
        severity=CheckSeverity.LOW,
        expected_value="AllowTcpForwarding no OR explicit bastion policy",
        description="Audits whether arbitrary TCP port forwarding through SSH sessions is permitted.",
        security_impact="Arbitrary port forwarding can be leveraged for unauthorized network tunneling or bypassing local firewall boundaries.",
        recommendation="Set 'AllowTcpForwarding no' unless the host is a designated bastion or proxy host.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.2.14",
    ),
    "SSH-008": SecurityCheckDefinition(
        check_id="SSH-008",
        check_name="SSH Configuration Consistency & Drop-in Check",
        category=CheckCategory.SSH,
        severity=CheckSeverity.MEDIUM,
        expected_value="Valid effective syntax via 'sshd -T' without syntax conflicts",
        description="Evaluates whether drop-in configs in /etc/ssh/sshd_config.d/ parse cleanly without overriding hardening rules or causing daemon startup failure.",
        security_impact="Conflicting drop-in directives can silently negate security settings defined in the main configuration file.",
        recommendation="Review all files in /etc/ssh/sshd_config.d/ using 'sshd -T' to verify the combined effective runtime configuration.",
        remediation_reference="OpenSSH Configuration Guidelines & CIS §5.2",
    ),

    # --------------------------------------------------------------------------
    # B. ACCOUNT SECURITY (ACC-xxx)
    # --------------------------------------------------------------------------
    "ACC-001": SecurityCheckDefinition(
        check_id="ACC-001",
        check_name="Zero Non-Root Accounts with UID 0",
        category=CheckCategory.ACCOUNT,
        severity=CheckSeverity.CRITICAL,
        expected_value="Only 'root' has UID 0 in /etc/passwd",
        description="Audits /etc/passwd to ensure that no account other than 'root' is assigned UID 0.",
        security_impact="Any account with UID 0 possesses full superuser privileges, bypassing individual accountability and audit logs.",
        recommendation="Audit /etc/passwd. Remove or reassign UID to any unauthorized account possessing UID 0.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.4.3",
    ),
    "ACC-002": SecurityCheckDefinition(
        check_id="ACC-002",
        check_name="System Accounts Shell Restriction",
        category=CheckCategory.ACCOUNT,
        severity=CheckSeverity.HIGH,
        expected_value="All system accounts (UID < 1000, except root/sync) have /usr/sbin/nologin or /bin/false",
        description="Ensures system and daemon accounts cannot be used to establish interactive login shells.",
        security_impact="Compromised daemons with interactive shells allow immediate local shell access to an attacker.",
        recommendation="Run 'usermod -s /usr/sbin/nologin <username>' for any system accounts with interactive shells.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.4.2",
    ),
    "ACC-003": SecurityCheckDefinition(
        check_id="ACC-003",
        check_name="Administrative Sudo Group Membership Audit",
        category=CheckCategory.ACCOUNT,
        severity=CheckSeverity.MEDIUM,
        expected_value="Only authorized administrators in 'sudo' or 'wheel' group",
        description="Audits the list of users with sudo membership to verify that administrative privileges are strictly controlled.",
        security_impact="Overly broad sudo group membership expands the attack surface for privilege escalation.",
        recommendation="Review group members using 'getent group sudo' and remove users who no longer require root delegation.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.3.1",
    ),
    "ACC-004": SecurityCheckDefinition(
        check_id="ACC-004",
        check_name="Security File Permissions (/etc/passwd, /etc/shadow, /etc/sudoers)",
        category=CheckCategory.ACCOUNT,
        severity=CheckSeverity.CRITICAL,
        expected_value="/etc/passwd <= 644, /etc/shadow <= 640 (root:shadow), /etc/sudoers <= 440",
        description="Validates ownership and permission modes on core authentication and authorization files.",
        security_impact="Loose permissions on shadow allow password hash harvesting; writable passwd or sudoers allows instant root compromise.",
        recommendation="Run 'chmod 644 /etc/passwd; chmod 640 /etc/shadow; chown root:shadow /etc/shadow; chmod 440 /etc/sudoers'.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §6.1.2 - §6.1.9",
    ),
    "ACC-005": SecurityCheckDefinition(
        check_id="ACC-005",
        check_name="Sudo NOPASSWD Policy Audit",
        category=CheckCategory.ACCOUNT,
        severity=CheckSeverity.HIGH,
        expected_value="No global or wildcard NOPASSWD entries in sudoers",
        description="Audits /etc/sudoers and /etc/sudoers.d/ for unrestricted 'NOPASSWD: ALL' delegations.",
        security_impact="Wildcard NOPASSWD allows anyone with standard user compromise to escalate to root without password verification.",
        recommendation="Remove wildcard NOPASSWD entries or restrict them strictly to specific required administrative binaries.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.3.4",
    ),

    # --------------------------------------------------------------------------
    # C. FIREWALL SECURITY (FW-xxx)
    # --------------------------------------------------------------------------
    "FW-001": SecurityCheckDefinition(
        check_id="FW-001",
        check_name="Host Firewall (UFW / nftables) Active Status",
        category=CheckCategory.FIREWALL,
        severity=CheckSeverity.HIGH,
        expected_value="UFW active OR nftables service active",
        description="Verifies that a local packet-filtering firewall is installed and actively enforcing rules.",
        security_impact="Without an active host firewall, all listening ports are directly reachable from adjacent network segments.",
        recommendation="Before activating UFW, ensure SSH is allowed ('ufw allow ssh' or 'ufw allow 22/tcp'), then run 'ufw enable'.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §3.5.1",
    ),
    "FW-002": SecurityCheckDefinition(
        check_id="FW-002",
        check_name="Firewall Default Inbound Policy",
        category=CheckCategory.FIREWALL,
        severity=CheckSeverity.MEDIUM,
        expected_value="Default incoming policy: DROP or REJECT",
        description="Verifies that the default incoming policy drops or rejects packets that do not match explicit allow rules.",
        security_impact="An open default incoming policy permits unintended exposure of newly spawned listening services.",
        recommendation="Configure default incoming policy: 'ufw default deny incoming'. Ensure SSH access rule is in place first.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §3.5.2",
    ),
    "FW-003": SecurityCheckDefinition(
        check_id="FW-003",
        check_name="Open Listening Ports & Public Interface Exposure",
        category=CheckCategory.FIREWALL,
        severity=CheckSeverity.MEDIUM,
        expected_value="Services bind strictly to localhost (127.0.0.1) unless intentionally public",
        description="Audits all listening TCP/UDP sockets to identify services listening on 0.0.0.0 or external IPs.",
        security_impact="Services unintentionally bound to all interfaces (e.g. backend APIs, debug endpoints) can be probed from external networks.",
        recommendation="Reconfigure internal daemon binding addresses from 0.0.0.0 to 127.0.0.1 or utilize firewall ingress filters.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §3.4",
    ),

    # --------------------------------------------------------------------------
    # D. SYSTEM HARDENING (SYS-xxx)
    # --------------------------------------------------------------------------
    "SYS-001": SecurityCheckDefinition(
        check_id="SYS-001",
        check_name="Automatic Security Updates (unattended-upgrades)",
        category=CheckCategory.SYSTEM,
        severity=CheckSeverity.MEDIUM,
        expected_value="unattended-upgrades package installed and active",
        description="Verifies that unattended-upgrades is enabled to automatically patch known security vulnerabilities.",
        security_impact="Unpatched systems accumulate public CVE vulnerabilities over time, leading to remote or local exploitation.",
        recommendation="Install and enable: 'apt-get install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades'.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §1.8",
    ),
    "SYS-002": SecurityCheckDefinition(
        check_id="SYS-002",
        check_name="AppArmor Mandatory Access Control Status",
        category=CheckCategory.SYSTEM,
        severity=CheckSeverity.HIGH,
        expected_value="AppArmor enabled and enforcing profiles",
        description="Verifies that AppArmor is installed, enabled in the Linux kernel, and actively enforcing security profiles.",
        security_impact="Without MAC, compromised processes have full discretionary access to all resources owned by their UID.",
        recommendation="Ensure AppArmor is installed ('apt-get install apparmor apparmor-utils') and active ('aa-status').",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §1.6.1",
    ),
    "SYS-003": SecurityCheckDefinition(
        check_id="SYS-003",
        check_name="Supported Kernel & OS Release Audit",
        category=CheckCategory.SYSTEM,
        severity=CheckSeverity.INFO,
        expected_value="Supported LTS kernel and distribution release (Ubuntu 22.04 / 24.04 LTS)",
        description="Identifies the operating system distribution, release status, and active Linux kernel version.",
        security_impact="End-of-life operating systems or unmaintained kernel branches cease receiving critical security patches.",
        recommendation="Keep system on supported Ubuntu LTS release and apply routine kernel updates via apt.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §1.1",
    ),
    "SYS-004": SecurityCheckDefinition(
        check_id="SYS-004",
        check_name="Legacy Insecure Services Absence",
        category=CheckCategory.SYSTEM,
        severity=CheckSeverity.HIGH,
        expected_value="telnet, rsh, rsync daemon, and ftp inactive or not installed",
        description="Verifies that legacy plaintext services (telnet, rsh, inetd, vsftpd) are not active on the host.",
        security_impact="Legacy plaintext services transmit authentication credentials and session data without encryption.",
        recommendation="Disable and purge legacy services: 'systemctl stop <svc>; apt-get purge telnetd rsh-server'.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §2.1",
    ),

    # --------------------------------------------------------------------------
    # E. LOGGING & AUDIT (LOG-xxx)
    # --------------------------------------------------------------------------
    "LOG-001": SecurityCheckDefinition(
        check_id="LOG-001",
        check_name="systemd-journald Persistent Storage Status",
        category=CheckCategory.LOGGING,
        severity=CheckSeverity.MEDIUM,
        expected_value="Storage=persistent in /etc/systemd/journald.conf and /var/log/journal exists",
        description="Verifies that systemd journal logs persist across host reboots.",
        security_impact="Volatile logging loses forensic audit trails across unexpected system restarts or kernel crashes.",
        recommendation="Create /var/log/journal and ensure 'Storage=persistent' in /etc/systemd/journald.conf.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §4.1.1",
    ),
    "LOG-002": SecurityCheckDefinition(
        check_id="LOG-002",
        check_name="Logrotate Configuration & Disk Retention",
        category=CheckCategory.LOGGING,
        severity=CheckSeverity.LOW,
        expected_value="logrotate.service or timer active, disk utilization < 85%",
        description="Verifies that log rotation is configured to prevent log directory disk exhaustion.",
        security_impact="Uncontrolled log growth can fill root partitions, resulting in denial of service and loss of telemetry.",
        recommendation="Ensure logrotate is installed and configured in /etc/logrotate.conf.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §4.2",
    ),
    "LOG-003": SecurityCheckDefinition(
        check_id="LOG-003",
        check_name="SSH & Sudo Audit Log Generation",
        category=CheckCategory.LOGGING,
        severity=CheckSeverity.HIGH,
        expected_value="sshd and sudo logs actively recorded in systemd journal",
        description="Verifies that authentication and privileged execution events are actively recorded in system logs.",
        security_impact="Absence of auth/sudo logging blinds detection systems and eliminates forensic audit trails.",
        recommendation="Verify pam_unix and sudoers logging configurations in /etc/pam.d/ and /etc/sudoers.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §4.1.2",
    ),

    # --------------------------------------------------------------------------
    # F. NETWORK SECURITY (NET-xxx)
    # --------------------------------------------------------------------------
    "NET-001": SecurityCheckDefinition(
        check_id="NET-001",
        check_name="SSH Port Exposure & Interface Isolation",
        category=CheckCategory.NETWORK,
        severity=CheckSeverity.MEDIUM,
        expected_value="SSH protected by local firewall or private interface",
        description="Audits how the SSH port is exposed across host network interfaces.",
        security_impact="Direct exposure of SSH on unsegmented public IP interfaces increases attack vulnerability.",
        recommendation="Restrict SSH access via Cloudflare Tunnel, VPN, or firewall rules limited to trusted management IPs.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §3.5",
    ),
    "NET-002": SecurityCheckDefinition(
        check_id="NET-002",
        check_name="DNS Resolver Configuration & Security",
        category=CheckCategory.NETWORK,
        severity=CheckSeverity.LOW,
        expected_value="Valid systemd-resolved or local nameserver configured in /etc/resolv.conf",
        description="Verifies that DNS resolution is directed to valid, trusted nameservers.",
        security_impact="Misconfigured nameservers can cause query timeouts, DNS spoofing, or telemetry delivery failure.",
        recommendation="Ensure systemd-resolved or trusted upstream DNS servers are configured.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §3.3",
    ),

    # --------------------------------------------------------------------------
    # G. FILESYSTEM SECURITY (FS-xxx)
    # --------------------------------------------------------------------------
    "FS-001": SecurityCheckDefinition(
        check_id="FS-001",
        check_name="World-Writable Sensitive Directory Audit",
        category=CheckCategory.FILESYSTEM,
        severity=CheckSeverity.CRITICAL,
        expected_value="Zero world-writable files in /etc or /var/www",
        description="Scans targeted critical directories (/etc, /var/www) to ensure no unauthorized world-writable files exist.",
        security_impact="World-writable configuration files allow any local user or unprivileged service to compromise the system.",
        recommendation="Run 'chmod o-w <file>' on any identified world-writable configuration files.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §6.1.10",
    ),
    "FS-002": SecurityCheckDefinition(
        check_id="FS-002",
        check_name="SSH Configuration Directory Ownership & Permissions",
        category=CheckCategory.FILESYSTEM,
        severity=CheckSeverity.HIGH,
        expected_value="/etc/ssh directory owned by root:root with permissions <= 755",
        description="Validates ownership and access permissions of /etc/ssh and its configuration files.",
        security_impact="Non-root ownership or write permissions on /etc/ssh allows unauthorized modification of sshd parameters.",
        recommendation="Run 'chown -R root:root /etc/ssh && chmod 755 /etc/ssh && chmod 644 /etc/ssh/*.pub'.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.2.1",
    ),
    "FS-003": SecurityCheckDefinition(
        check_id="FS-003",
        check_name="Sudoers Directory Permissions (/etc/sudoers.d)",
        category=CheckCategory.FILESYSTEM,
        severity=CheckSeverity.HIGH,
        expected_value="/etc/sudoers.d owned by root:root with mode 750 or 755",
        description="Validates that /etc/sudoers.d is strictly owned by root with no group/world write permissions.",
        security_impact="A writable /etc/sudoers.d directory allows any unprivileged user to drop a sudoers file and become root.",
        recommendation="Run 'chown -R root:root /etc/sudoers.d && chmod 750 /etc/sudoers.d'.",
        remediation_reference="CIS Ubuntu Linux Benchmark 24.04 §5.3.3",
    ),
}

