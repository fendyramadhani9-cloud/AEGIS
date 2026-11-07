# AEGIS Security Checker: Master Rules & Checks Catalog

AEGIS Security Checker incorporates **28 standardized security checks** across 7 primary categories, benchmarked against **CIS Ubuntu Linux 24.04 LTS Benchmark** and **NIST SP 800-53**.

---

## 1. Category Summary Matrix

| Category | Checks Count | Severity Range | Key Focus |
| :--- | :---: | :---: | :--- |
| **SSH** | 8 | Low – Critical | Root login, password auth, keys, algorithms, timeouts, configuration drop-in integrity |
| **Account** | 5 | Medium – Critical | Non-root UID 0, system account login shells, sudo membership, shadow file permissions, NOPASSWD |
| **Firewall** | 3 | Medium – High | Host firewall active status (UFW/nftables), default incoming policy, public listening sockets |
| **System** | 4 | Info – High | Automatic security updates, AppArmor MAC status, supported LTS kernel, legacy insecure services |
| **Logging** | 3 | Low – High | Persistent journald storage, log retention, audit log generation for SSH/sudo |
| **Network** | 2 | Low – Medium | SSH interface binding/exposure, secure DNS resolvers |
| **Filesystem** | 3 | High – Critical | World-writable sensitive directories, SSH config directory permissions, sudoers directory permissions |

---

## 2. Detailed Checks Catalog

### A. SSH Hardening (`ssh`)

#### 1. `SSH-001`: SSH PermitRootLogin Enforcement
- **Severity**: High | **CIS**: §5.2.8 | **MITRE**: T1078.003
- **Description**: Verifies that direct SSH login as root is disabled (`no`) or limited to public keys (`prohibit-password`).
- **Expected**: `PermitRootLogin no` OR `PermitRootLogin prohibit-password`.
- **Security Impact**: Direct root login facilitates brute-force credential attacks and prevents non-repudiation of administrative actions.
- **Remediation**:
  ```bash
  echo "PermitRootLogin prohibit-password" | sudo tee /etc/ssh/sshd_config.d/01-sshd-hardening.conf
  sudo sshd -t && sudo systemctl reload sshd
  ```

#### 2. `SSH-002`: SSH PasswordAuthentication Disablement
- **Severity**: High | **CIS**: §5.2.11 | **MITRE**: T1110.001
- **Description**: Verifies whether password-based authentication over SSH is disabled in favor of cryptographic public keys.
- **Expected**: `PasswordAuthentication no`.
- **Security Impact**: Password authentication exposes hosts to brute-force and credential stuffing attacks.
- **Remediation**:
  ```bash
  echo "PasswordAuthentication no" | sudo tee -a /etc/ssh/sshd_config.d/01-sshd-hardening.conf
  sudo sshd -t && sudo systemctl reload sshd
  ```

#### 3. `SSH-003`: SSH PubkeyAuthentication Enablement
- **Severity**: High | **CIS**: §5.2.12 | **MITRE**: T1078.004
- **Description**: Verifies that cryptographic public key authentication is enabled.
- **Expected**: `PubkeyAuthentication yes`.
- **Remediation**:
  ```bash
  echo "PubkeyAuthentication yes" | sudo tee -a /etc/ssh/sshd_config.d/01-sshd-hardening.conf
  sudo sshd -t && sudo systemctl reload sshd
  ```

#### 4. `SSH-004`: SSH PermitEmptyPasswords Disablement
- **Severity**: Critical | **CIS**: §5.2.9 | **MITRE**: T1078.001
- **Description**: Verifies that accounts with empty password strings are forbidden from authenticating.
- **Expected**: `PermitEmptyPasswords no`.
- **Remediation**:
  ```bash
  echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_config.d/01-sshd-hardening.conf
  sudo sshd -t && sudo systemctl reload sshd
  ```

#### 5. `SSH-005`: SSH MaxAuthTries Limitation
- **Severity**: Medium | **CIS**: §5.2.5 | **MITRE**: T1110
- **Description**: Verifies that authentication attempts per connection are limited to 4 or fewer.
- **Expected**: `MaxAuthTries <= 4`.
- **Remediation**:
  ```bash
  echo "MaxAuthTries 3" | sudo tee -a /etc/ssh/sshd_config.d/01-sshd-hardening.conf
  sudo sshd -t && sudo systemctl reload sshd
  ```

#### 6. `SSH-006`: SSH X11Forwarding Disablement
- **Severity**: Low | **CIS**: §5.2.6 | **MITRE**: T1021.004
- **Description**: Verifies that X11 graphic forwarding is disabled to prevent display interception on headless servers.
- **Expected**: `X11Forwarding no`.
- **Remediation**:
  ```bash
  echo "X11Forwarding no" | sudo tee -a /etc/ssh/sshd_config.d/01-sshd-hardening.conf
  sudo sshd -t && sudo systemctl reload sshd
  ```

#### 7. `SSH-007`: SSH AllowTcpForwarding Review
- **Severity**: Low | **CIS**: §5.2.10 | **MITRE**: T1090
- **Description**: Reviews whether TCP port forwarding is disabled or restricted to designated bastion hosts.
- **Expected**: `AllowTcpForwarding no` (or explicit gateway configuration).

#### 8. `SSH-008`: SSH Configuration Consistency & Drop-in Check
- **Severity**: Medium | **CIS**: §5.2.1 | **MITRE**: T1562.001
- **Description**: Verifies that effective SSH daemon configuration compiles cleanly without conflicting drop-ins via `sshd -t`.
- **Expected**: Zero syntax errors or conflicting directives.

---

### B. Account & Privilege Security (`account`)

#### 9. `ACC-001`: Zero Non-Root Accounts with UID 0
- **Severity**: Critical | **CIS**: §5.4.2.1 | **MITRE**: T1078.003
- **Description**: Ensures that the `root` account is the sole account with UID 0 in `/etc/passwd`.
- **Expected**: Exactly 1 account with UID 0.
- **Remediation**: Immediately investigate and delete or reassign rogue UID 0 accounts.

#### 10. `ACC-002`: System Accounts Shell Restriction
- **Severity**: High | **CIS**: §5.4.2.2 | **MITRE**: T1078.001
- **Description**: Verifies that system service accounts (UID < 1000) have non-login shells (`/usr/sbin/nologin` or `/bin/false`).
- **Expected**: Zero system accounts with interactive login shells (excluding root/sync).

#### 11. `ACC-003`: Administrative Sudo Group Membership Audit
- **Severity**: Medium | **CIS**: §5.3.1 | **MITRE**: T1078
- **Description**: Audits users in the `sudo` and `wheel` groups against authorized baseline administrators.
- **Expected**: Only designated administrators in administrative groups.

#### 12. `ACC-004`: Security File Permissions (/etc/passwd, /etc/shadow, /etc/sudoers)
- **Severity**: Critical | **CIS**: §6.1.2–§6.1.5 | **MITRE**: T1003.008
- **Description**: Verifies file modes and ownership: `/etc/passwd <= 644`, `/etc/shadow <= 640` (root:shadow), `/etc/sudoers <= 440` (root:root).
- **Remediation**:
  ```bash
  sudo chmod 644 /etc/passwd
  sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow
  sudo chmod 440 /etc/sudoers && sudo chown root:root /etc/sudoers
  ```

#### 13. `ACC-005`: Sudo NOPASSWD Policy Audit
- **Severity**: High | **CIS**: §5.3.3 | **MITRE**: T1548.003
- **Description**: Inspects sudoers configuration for hazardous `NOPASSWD: ALL` directives.
- **Expected**: Zero unrestricted `NOPASSWD: ALL` directives.

---

### C. Firewall & Network Exposure (`firewall`)

#### 14. `FW-001`: Host Firewall (UFW / nftables) Active Status
- **Severity**: High | **CIS**: §3.5.1.1 | **MITRE**: T1562.004
- **Description**: Verifies that an active host firewall (UFW or nftables) is running.
- **Remediation**:
  ```bash
  sudo apt-get install -y ufw
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow 22/tcp
  sudo ufw --force enable
  ```

#### 15. `FW-002`: Firewall Default Inbound Policy
- **Severity**: Medium | **CIS**: §3.5.1.2 | **MITRE**: T1562.004
- **Description**: Verifies default inbound traffic is dropped or rejected.
- **Expected**: Default incoming policy: DROP or REJECT.

#### 16. `FW-003`: Open Listening Ports & Public Interface Exposure
- **Severity**: Medium | **CIS**: §3.5.3 | **MITRE**: T1046
- **Description**: Identifies non-loopback listening sockets bound to `0.0.0.0` or `*`.
- **Expected**: Services bind strictly to `127.0.0.1` unless intentionally exposed through reverse proxy.

---

### D. System Hardening & Maintenance (`system`)

#### 17. `SYS-001`: Automatic Security Updates (unattended-upgrades)
- **Severity**: Medium | **CIS**: §1.8 | **MITRE**: T1190
- **Description**: Verifies that `unattended-upgrades` is installed and active for automatic security patching.

#### 18. `SYS-002`: AppArmor Mandatory Access Control Status
- **Severity**: High | **CIS**: §1.6.1.1 | **MITRE**: T1562.001
- **Description**: Checks whether AppArmor is enabled and enforcing profiles (`aa-status`).
- **Remediation**:
  ```bash
  sudo systemctl enable --now apparmor
  ```

#### 19. `SYS-003`: Supported Kernel & OS Release Audit
- **Severity**: Info | **CIS**: §1.1 | **MITRE**: T1082
- **Description**: Confirms the host is running a currently supported LTS kernel and distribution release.

#### 20. `SYS-004`: Legacy Insecure Services Absence
- **Severity**: High | **CIS**: §2.2.1–§2.2.7 | **MITRE**: T1040
- **Description**: Ensures legacy plaintext daemons (`telnet`, `rsh`, `rsync daemon`, `ftp`) are absent and inactive.

---

### E. Logging & Audit Readiness (`logging`)

#### 21. `LOG-001`: systemd-journald Persistent Storage Status
- **Severity**: Medium | **CIS**: §4.2.2.1 | **MITRE**: T1562.002
- **Description**: Verifies `Storage=persistent` in `/etc/systemd/journald.conf` and `/var/log/journal` exists.

#### 22. `LOG-002`: Logrotate Configuration & Disk Retention
- **Severity**: Low | **CIS**: §4.3 | **MITRE**: T1499
- **Description**: Verifies logrotate timer is active and partition disk utilization is below 85%.

#### 23. `LOG-003`: SSH & Sudo Audit Log Generation
- **Severity**: High | **CIS**: §4.1.3 | **MITRE**: T1078
- **Description**: Verifies that SSH authentication and sudo invocation logs are actively captured in systemd journal.

---

### F. Network Isolation (`network`)

#### 24. `NET-001`: SSH Port Exposure & Interface Isolation
- **Severity**: Medium | **CIS**: §5.2.2 | **MITRE**: T1021.004
- **Description**: Audits the interface binding and exposure of the SSH listening port.

#### 25. `NET-002`: DNS Resolver Configuration & Security
- **Severity**: Low | **CIS**: §1.7 | **MITRE**: T1071.004
- **Description**: Validates configured DNS nameservers in `/etc/resolv.conf`.

---

### G. Filesystem Integrity (`filesystem`)

#### 26. `FS-001`: World-Writable Sensitive Directory Audit
- **Severity**: Critical | **CIS**: §6.1.10 | **MITRE**: T1222.002
- **Description**: Scans `/etc` and `/var/www` for insecure world-writable files (`mode & 0o002`).

#### 27. `FS-002`: SSH Configuration Directory Ownership & Permissions
- **Severity**: High | **CIS**: §5.2.1 | **MITRE**: T1222.002
- **Description**: Ensures `/etc/ssh` is owned by `root:root` with permissions `<= 755`.

#### 28. `FS-003`: Sudoers Directory Permissions (/etc/sudoers.d)
- **Severity**: High | **CIS**: §5.3.4 | **MITRE**: T1222.002
- **Description**: Ensures `/etc/sudoers.d` is owned by `root:root` with permissions `<= 755`.
