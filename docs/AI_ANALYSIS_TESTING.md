# AEGIS Incident Investigation & AI Testing Documentation

## 1. Test Suite Overview
The testing framework covers unit, integration, database engine, and end-to-end API suites with 100% passing results across 137 test cases.

| Test File | Type | Cases | Purpose |
| :--- | :--- | :--- | :--- |
| `tests/test_incident_correlator.py` | Unit | 5 | Sliding window temporal clustering, cross-host isolation, deterministic ID generation, risk scoring. |
| `tests/test_ai_investigation.py` | Unit | 5 | Secret redaction, prompt injection defense, mock AI provider determinism, null provider fallback. |
| `tests/test_incident_api.py` | Integration | 6 | FastAPI REST endpoints (`/api/incidents/*`, `/api/analysis/*`), status updates, timeline, live AI execution. |
| `tests/verify_incident_migration.cjs` | Database | 5 | PGlite PostgreSQL migration 004 execution, constraints, verification script, and safe rollback. |
| Existing Suite (`tests/test_*.py`) | Regression | 121 | Collector, Rules Engine, Parsers, Security Checker, Database migration 001-003. |
| **Total** | | **142** | **100% Pass Rate** |

## 2. Running Test Suites

### Python Backend Suite
```bash
# Run new Incident & AI investigation tests
.venv/Scripts/python -m pytest tests/test_incident_correlator.py tests/test_ai_investigation.py tests/test_incident_api.py -v

# Run entire AEGIS test suite
.venv/Scripts/python -m pytest tests/ -v
```

### PostgreSQL Engine (PGlite) Migration Verification
```bash
node tests/verify_incident_migration.cjs
```

### Frontend Build Verification
```bash
cd dashboard && npm run build
```
