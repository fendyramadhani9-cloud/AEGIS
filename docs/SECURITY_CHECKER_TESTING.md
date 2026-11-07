# AEGIS Security Checker: Testing Strategy & Verification Report

## 1. Overview & Test Suites

The Security Checker implementation is covered by a multi-layered test pyramid encompassing catalog integrity, agent safety, API authorization, and database transaction contracts.

| Test Suite | File | Tests Count | Status |
| :--- | :--- | :---: | :---: |
| **Catalog Verification** | `tests/test_security_checker_catalog.py` | 3 | **PASS** |
| **Agent Robustness & Safety** | `tests/test_security_checker_agent.py` | 5 | **PASS** |
| **API Endpoints & Auth** | `tests/test_security_checker_api.py` | 10 | **PASS** |
| **Database Migration 003** | `tests/verify_security_checker_migration.cjs` | 7 | **PASS** |
| **PG Migration Engine** | `tests/test_postgres_migration.py` | 3 | **PASS** |
| **Core Regression Suites** | `tests/test_rules_engine.py`, `tests/test_collector.py`, etc. | 61 | **PASS** |
| **TOTAL** | | **89** | **100% PASS** |

---

## 2. Key Test Scenarios & Guarantees

### A. Subprocess Command Timeout Simulation
- **Scenario**: A system inspection command hangs (e.g. NFS mount freeze).
- **Assertion**: Subprocess is forcefully terminated at 5 seconds; agent does not hang; finding records `WARNING` with timeout explanation.

### B. Missing Binary Resilience
- **Scenario**: Inspection binary (e.g. `ufw`, `aa-status`) is not present on target host.
- **Assertion**: Agent catches `FileNotFoundError`, records return code `127`, and continues remaining 27 checks without aborting the scan.

### C. Pre-Transmission Sanitization
- **Scenario**: Command output or configuration value contains credentials, API keys, or private keys.
- **Assertion**: All secrets are replaced with `[REDACTED]`; legitimate security tokens like `prohibit-password` are preserved.

### D. Cross-Host Payload Rejection
- **Scenario**: An agent submits a scan payload for `host-fenn-ubuntu` containing a finding labeled with `host-rogue`.
- **Assertion**: Backend returns `400 Bad Request` with detail `"Finding host_id mismatch"`.

### E. Database Isolation & Foreign Key Enforcement
- **Scenario**: Submitting a scan run for an un-registered host ID in PostgreSQL.
- **Assertion**: PostgreSQL rejects run insertion with foreign key constraint violation.

### F. Idempotency & Unique Constraints
- **Scenario**: Duplicate check findings inserted into the same run ID.
- **Assertion**: PostgreSQL unique constraint `uq_run_check` blocks duplicate insertion.

---

## 3. Test Execution Commands

```bash
# Run Security Checker specific unit & integration tests
pytest tests/test_security_checker_catalog.py tests/test_security_checker_agent.py tests/test_security_checker_api.py -v

# Run PostgreSQL engine migration verification in PGlite
node tests/verify_security_checker_migration.cjs

# Run full AEGIS regression suite
pytest tests/ -v
```
