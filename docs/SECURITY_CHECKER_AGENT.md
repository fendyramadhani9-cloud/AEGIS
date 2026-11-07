# AEGIS Security Checker: Linux Agent Implementation

## 1. Scanner Architecture

The Linux Security Checker Agent (`aegis_agent.security_checker`) is implemented in Python as a lightweight, zero-dependency read-only audit engine. It can be executed interactively via CLI, invoked as a one-shot scheduled job, or queried programmatically.

```
+-----------------------------------------------------------------------------+
|                           AegisSecurityChecker                              |
|                                                                             |
|  1. Configuration Discovery (/etc/os-release, uname, host identity)        |
|  2. Parallel / Sequential Subprocess Audits (safe argument lists)           |
|  3. Safe File State Inspection (os.stat, mode masks, owner checks)          |
|  4. Pre-transmission Credential Sanitization (TelemetrySanitizer)           |
|  5. Result Payload Assembly & Submission (HTTP POST with X-Agent-Token)     |
+-----------------------------------------------------------------------------+
```

---

## 2. Hardening & Safety Controls

1. **Strictly Read-Only**: The agent executes inspection commands only (`sshd -T`, `ufw status`, `ss -tulpn`, `aa-status`, `stat`). It never issues write, reconfigure, or restart commands.
2. **Subprocess Isolation**: Commands are invoked using `subprocess.run(args, capture_output=True, text=True, timeout=5)`. Shell execution (`shell=True`) is prohibited to prevent shell injection vulnerabilities.
3. **Buffer Truncation**: All stdout and stderr streams are truncated to `8,192` characters.
4. **Timeout Handling**: Any command exceeding 5 seconds is killed immediately via `TimeoutExpired` and recorded as `CheckStatus.WARNING` with an informative error indicator.
5. **Missing Binary Resilience**: If a command-line tool is not installed (e.g. `ufw` on minimal installations), the agent catches `FileNotFoundError` and assigns return code `127`, reporting the exact configuration status gracefully without crashing.
6. **Credential Masking**: All output strings and indicator arrays pass through `TelemetrySanitizer` before sending to the backend or writing to logs.

---

## 3. Command-Line Usage

### Dry-Run Mode (Local Audit Only, No Network Submission)
```bash
python3 -m aegis_agent.security_checker --dry-run
```
Outputs formatted ASCII report to terminal with pass/fail/warn totals and detailed actual vs expected values.

### Scan and Submit to Backend
```bash
python3 -m aegis_agent.security_checker --submit
```
Runs the full audit and submits the results to the configured `AEGIS_API_URL` using `X-Agent-Token`.

### Custom Target Host and API
```bash
python3 -m aegis_agent.security_checker \
  --submit \
  --api-url http://127.0.0.1:8000 \
  --token aegis-agent-dev-secret-token \
  --host-id host-fenn-ubuntu
```

---

## 4. Configuration Variables

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `AEGIS_API_URL` | `http://127.0.0.1:8000` | Backend API gateway URL |
| `AEGIS_AGENT_TOKEN` | `aegis-agent-dev-secret-token` | Ingestion authentication token |
| `AEGIS_HOST_ID` | `host-fenn-ubuntu` | Host identifier matching registered host |
| `AEGIS_HOSTNAME` | `socket.gethostname()` | Hostname reported in metadata |
