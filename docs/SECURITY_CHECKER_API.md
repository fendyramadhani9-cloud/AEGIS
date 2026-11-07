# AEGIS Security Checker: REST API Specification

## 1. Base Endpoint & Protocol

- **Base URL**: `/api/security-checker`
- **Protocol**: HTTP/1.1 & HTTP/2 over TLS
- **Public Domain**: `https://aegis.diazz.web.id/api/security-checker`
- **Internal Reverse Proxy**: `http://127.0.0.1/api/security-checker`
- **Direct FastAPI Port**: `http://127.0.0.1:8000/api/security-checker`

---

## 2. Authentication & Authorization

All agent ingestion endpoints require the `X-Agent-Token` header.
Unauthenticated requests or requests with invalid tokens return `401 Unauthorized`.

```http
POST /api/security-checker/agent-results HTTP/1.1
Host: 127.0.0.1:8000
X-Agent-Token: aegis-agent-dev-secret-token
Content-Type: application/json
```

Public query endpoints (`/health`, `/checks`, `/hosts`, `/summary`, `/findings`, `/runs`) are read-only and available to authorized internal dashboard sessions.

---

## 3. Endpoints Catalog

### `GET /api/security-checker/health`
Checks the operational health of the Security Checker subsystem.

- **Response `200 OK`**:
```json
{
  "status": "ok",
  "module": "security-checker",
  "version": "1.0.0",
  "total_catalog_checks": 28
}
```

---

### `GET /api/security-checker/checks`
Lists the complete catalog of 28 standardized security checks supported by AEGIS.

- **Query Parameters**:
  - `category` *(optional)*: Filter by category (`ssh`, `account`, `firewall`, `system`, `logging`, `network`, `filesystem`).
  - `severity` *(optional)*: Filter by severity (`critical`, `high`, `medium`, `low`, `info`).

- **Response `200 OK`**:
```json
[
  {
    "id": "SSH-001",
    "name": "SSH PermitRootLogin Enforcement",
    "category": "ssh",
    "severity": "high",
    "description": "Verifies that direct SSH login as root is disabled or restricted to public key authentication only.",
    "expected_value": "PermitRootLogin no OR prohibit-password",
    "security_impact": "Allowing direct root login over SSH facilitates brute-force attacks against the highest privileged account.",
    "cis_reference": "CIS Ubuntu Linux Benchmark 24.04 §5.2.8",
    "mitre_reference": "T1078.003",
    "remediation_summary": "Edit /etc/ssh/sshd_config or drop-in in /etc/ssh/sshd_config.d/ to set 'PermitRootLogin no'...",
    "remediation_steps": [
      "echo 'PermitRootLogin prohibit-password' | sudo tee /etc/ssh/sshd_config.d/01-sshd-hardening.conf",
      "sudo sshd -t",
      "sudo systemctl reload sshd"
    ]
  }
]
```

---

### `GET /api/security-checker/summary`
Retrieves aggregated security posture metrics across all registered hosts or for a specific host.

- **Query Parameters**:
  - `host_id` *(optional)*: Host identifier (e.g. `host-fenn-ubuntu`).

- **Response `200 OK`**:
```json
{
  "total_checks": 28,
  "passed": 17,
  "failed": 3,
  "warning": 7,
  "not_applicable": 1,
  "error": 0,
  "total_hosts": 1,
  "last_checked_at": "2026-11-07T13:51:03.772305+00:00",
  "critical_fails": 1,
  "high_fails": 2,
  "medium_fails": 0,
  "low_fails": 0
}
```

---

### `GET /api/security-checker/findings`
Retrieves paginated, filtered findings from the latest security scan runs.

- **Query Parameters**:
  - `host_id` *(optional)*: Filter by target host.
  - `category` *(optional)*: Filter by check category.
  - `severity` *(optional)*: Filter by severity.
  - `status` *(optional)*: Filter by status (`pass`, `fail`, `warning`, `not_applicable`, `error`).
  - `search` *(optional)*: Search term matching Check ID, title, or category.
  - `limit` *(optional, default 50, max 200)*: Result limit.
  - `offset` *(optional, default 0)*: Pagination offset.

- **Response `200 OK`**:
```json
{
  "total": 28,
  "limit": 50,
  "offset": 0,
  "items": [
    {
      "id": "FND-host-fenn-ubuntu-FW-001-RUN-host-fenn-ubuntu-1794059463",
      "run_id": "RUN-host-fenn-ubuntu-1794059463",
      "host_id": "host-fenn-ubuntu",
      "check_id": "FW-001",
      "check_name": "Host Firewall (UFW / nftables) Active Status",
      "category": "firewall",
      "severity": "high",
      "status": "fail",
      "actual_value": "UFW inactive (rc=127), nftables inactive",
      "expected_value": "UFW active OR nftables service active",
      "description": "Verifies that an active host firewall (UFW or nftables) is running and enforcing inbound network filtering.",
      "security_impact": "Without an active host firewall, all unauthenticated listening network ports are exposed to the network.",
      "recommendation": "Install and enable ufw with 'sudo apt-get install -y ufw && sudo ufw default deny incoming && sudo ufw allow 22/tcp && sudo ufw --force enable'.",
      "remediation_reference": "CIS Ubuntu Linux Benchmark 24.04 §3.5.1.1",
      "checked_at": "2026-11-07T13:51:03.652100+00:00",
      "checker_version": "1.0.0"
    }
  ]
}
```

---

### `GET /api/security-checker/findings/{finding_id}`
Retrieves complete details for a specific security finding, including Actual vs Expected comparison and remediation code blocks.

- **Response `200 OK`**: Returns individual finding object.
- **Response `404 Not Found`**: If finding ID is not found.

---

### `POST /api/security-checker/agent-results`
Submits a complete Security Checker scan run and its associated findings from an agent.

- **Headers**:
  - `X-Agent-Token`: Valid agent ingestion token.
  - `Content-Type`: `application/json`

- **Request Body**:
```json
{
  "host_id": "host-fenn-ubuntu",
  "run_id": "RUN-host-fenn-ubuntu-1794059463",
  "status": "completed",
  "total_checks": 28,
  "passed_checks": 17,
  "failed_checks": 3,
  "warning_checks": 7,
  "error_checks": 0,
  "checker_version": "1.0.0",
  "started_at": "2026-11-07T13:51:03.622000Z",
  "completed_at": "2026-11-07T13:51:03.772000Z",
  "summary": {
    "hostname": "fenn",
    "os_version": "Ubuntu 24.04.4 LTS",
    "kernel": "6.8.0-100-generic"
  },
  "findings": [
    {
      "check_id": "SSH-001",
      "host_id": "host-fenn-ubuntu",
      "category": "ssh",
      "severity": "high",
      "status": "pass",
      "title": "SSH PermitRootLogin Enforcement",
      "actual_value": "Not explicitly defined (default prohibit-password)",
      "expected_value": "PermitRootLogin no OR prohibit-password",
      "security_impact": "Direct root login enables brute force.",
      "remediation_summary": "Configure PermitRootLogin prohibit-password.",
      "remediation_steps": ["sudo sshd -t", "sudo systemctl reload sshd"],
      "cis_reference": "CIS Ubuntu Linux Benchmark 24.04 §5.2.8",
      "execution_time_ms": 12,
      "evidence": { "method": "sshd_config" },
      "checked_at": "2026-11-07T13:51:03.642346Z"
    }
  ]
}
```

- **Validation Rules**:
  - `X-Agent-Token` must match configured token.
  - `host_id` must match a registered host in `hosts`.
  - Every finding in `findings` must have `host_id == payload.host_id` (cross-host finding injection rejected with 400).
  - All findings must have valid status: `pass`, `fail`, `warning`, `not_applicable`, `error`.
