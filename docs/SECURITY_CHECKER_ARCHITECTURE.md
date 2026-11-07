# AEGIS Security Checker: Architecture & System Design

## 1. Executive Overview

The AEGIS Security Checker is a read-only host configuration auditing subsystem integrated into the AEGIS Security Operations Platform. Designed for Ubuntu LTS production environments, it regularly assesses host security posture against standardized benchmarks (CIS Ubuntu Linux Benchmark, NIST SP 800-53, MITRE ATT&CK) without modifying host state.

```
+-----------------------------------------------------------------------------------+
|                                 UBUNTU LTS HOST                                   |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   |                      AEGIS SECURITY CHECKER AGENT                         |   |
|   |  - Non-root execution (adm group)                                         |   |
|   |  - Safe subprocess invocations (argument lists, shell=False)               |   |
|   |  - Strict command timeout (5s per check, 30s run ceiling)                 |   |
|   |  - Output buffer truncation (8 KB max per command)                        |   |
|   |  - 28 Standardized checks (7 categories)                                  |   |
|   +---------------------------------------------------------------------------+   |
|                                     |                                             |
|                                     v                                             |
|   +---------------------------------------------------------------------------+   |
|   |                           TELEMETRY SANITIZER                             |   |
|   |  - Pre-transmission redaction of API keys, passwords, tokens, auth headers|   |
|   |  - Preserves standard security values (e.g. 'prohibit-password')           |   |
|   +---------------------------------------------------------------------------+   |
+-------------------------------------|---------------------------------------------+
                                      | HTTP POST /api/security-checker/agent-results
                                      | Headers: X-Agent-Token
                                      v
+-----------------------------------------------------------------------------------+
|                             AEGIS BACKEND GATEWAY                                 |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   |                       AUTHENTICATION & VALIDATION                         |   |
|   |  - Token verification (constant-time compare)                             |   |
|   |  - Host registration lookup                                               |   |
|   |  - Cross-host payload mismatch rejection (400 Bad Request)                |   |
|   +---------------------------------------------------------------------------+   |
|                                     |                                             |
|                                     v                                             |
|   +---------------------------------------------------------------------------+   |
|   |                        AEGIS STORAGE REPOSITORY                           |   |
|   |  - Atomic ingestion of Run metadata & Findings                            |   |
|   |  - Automatic host posture timestamp update (last_sc_run_at)                |   |
|   |  - Graceful fallback buffering if cloud migrations are pending            |   |
|   +---------------------------------------------------------------------------+   |
|                                     |                                             |
|                                     v                                             |
|   +---------------------------------------------------------------------------+   |
|   |                              REST API & UI                                |   |
|   |  - Reverse-proxied via Apache on port 80                                  |   |
|   |  - Live findings, metrics, and remediation guides in React Dashboard      |   |
|   +---------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Design Principles

### A. Non-Destructive, Read-Only Auditing
- The Security Checker **never modifies host configuration**.
- It does not rewrite `/etc/ssh/sshd_config`, change file permissions, or alter firewall rules.
- Remediation guidance is provided for administrators to execute deliberately.

### B. Least Privilege Execution Boundary
- The scanner runs unprivileged under standard service accounts (`ubuntu` or `aegis-agent` in the `adm` group).
- It reads files like `/etc/passwd`, `/etc/resolv.conf`, `/etc/ssh/sshd_config` using standard file permissions.
- Where elevated inspection is required (e.g., `/etc/shadow` mode), the agent inspects file metadata (`os.stat().st_mode`) without reading confidential password hashes.

### C. Resource & Bounded Execution Guarantees
- **CPU & Memory**: Maximum process memory consumption < 40 MB. Minimal CPU footprint during scans (< 2% CPU burst).
- **Subprocess Timeout**: Every subprocess call is strictly capped at 5 seconds. Total scan time for all 28 checks typically executes in < 300 ms.
- **Buffer Truncation**: Output streams from command execution are capped at 8,192 bytes (8 KB) to prevent memory exhaustion or logging explosion from rogue output.

### D. Zero Secret Leakage Pre-Transmission Boundary
- All command outputs and actual configuration values pass through `TelemetrySanitizer` before network transmission.
- Patterns matching Bearer tokens, private keys, API keys, passwords, and authorization headers are masked to `[REDACTED]`.
- Regex boundaries ensure legitimate configuration strings like `prohibit-password` or `nopasswd` are preserved for accurate compliance evaluation.

### E. Idempotency & Database Integrity
- Each scan run is assigned an immutable ID: `RUN-<host_id>-<timestamp_hash>`.
- Findings are identified uniquely by `(run_id, check_id)` with database-level uniqueness constraints (`uq_run_check`).
- Submissions for unknown hosts or cross-host payload mismatches (where a finding's `host_id` does not match the run's `host_id`) are rejected with `400 Bad Request`.

