# AEGIS CLOUD SSoT TEST EVIDENCE & COMPREHENSIVE VERIFICATION MATRIX

**Dokumen:** `docs/cloud-ssot-test-evidence.md`  
**Sistem:** AEGIS — AI-Powered Linux Security Monitoring and Incident Investigation  
**Status:** Unified Cloud SSoT Verification Evidence  
**Tanggal:** 8 November 2026  
**Penulis:** Apri (QA Lead, Senior Software Engineer, DevSecOps Lead)

---

## 1. Ringkasan Eksekutif Pengujian

Seluruh rangkaian pengujian perangkat lunak, simulasi kegagalan, verifikasi privilege live cloud, dan pemeriksaan build frontend telah dieksekusi dengan hasil **100% LULUS (ZERO DEFECTS)**.

| Kategori Pengujian | Lingkungan | Command Eksekusi | Exit Code | Hasil Pengujian | Status Klaim |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Backend Full Test Suite** | Workstation Python 3.13 | `.venv\Scripts\python -m pytest` | `0` | **195 / 195 PASSED** | **TESTED** |
| **Frontend TypeScript & Vite Build** | Workstation Node.js | `npm run build` (in `dashboard/`) | `0` | **Built in 7.33s (0 errors)** | **TESTED** |
| **Cloud RLS & Privilege Verification** | Live Supabase Cloud | `python scripts/verify_supabase_privileges_live.py` | `0` | **12/12 tables + RPC verified** | **VERIFIED** |
| **Deep Delta Reconciliation Audit** | SQLite vs Supabase | `python scripts/reconcile_delta_cutover.py` | `0` | **0 FK violations, 136 records matched** | **VERIFIED** |
| **Reverse Sync Drill (Cloud -> SQLite)** | SQLite vs Supabase | `python scripts/sync_cloud_to_sqlite.py` | `0` | **136 records processed dry-run** | **TESTED** |
| **Collector Two-Phase Commit Test** | Simulation Suite | `pytest tests/test_collector.py` | `0` | **Cursor retained on 500/network drop** | **TESTED** |
| **AI Adversarial Grounding Suite** | Simulation Suite | `pytest tests/test_ai_adversarial_validation.py` | `0` | **13 / 13 adversarial tests passed** | **TESTED** |
| **VM Fenn Operational Baseline** | Host Ubuntu 24.04 | `systemctl is-active aegis-backend aegis-collector` | `0` | **Both services ACTIVE** | **VERIFIED** |

---

## 2. Rincian Pengujian Backend (Pytest 195/195 Passed)

### 2.1 AI Investigation & Adversarial Grounding (tests/test_ai_adversarial_validation.py & test_ai_quality_evaluation.py)
- **test_adversarial_negation_not_falsely_demoted:** Memastikan kalimat negasi seperti *"tidak ditemukan exfiltrasi"* tidak didemosi secara keliru. [PASSED]
- **test_adversarial_affirmative_threat_concept_properly_quarantined:** Klaim serangan tanpa bukti langsung dikarantina ke hipotesis unverified. [PASSED]
- **test_adversarial_extreme_risk_score_tampering:** Risk score SSoT dari engine tidak dapat dimutasi secara bebas oleh model AI. [PASSED]
- **test_adversarial_prompt_injection_in_telemetry_payload:** Injeksi prompt dari log telemetri disanitasi sebelum masuk context window LLM. [PASSED]
- **test_quantitative_fidelity_single_failure_not_multiple:** Klaim kuantitas jamak pada event tunggal dikoreksi secara matematis. [PASSED]

### 2.2 Telemetry Ingestion & Rules Engine (tests/test_telemetry_ingest.py & test_collector.py)
- **test_ingest_missing_token_rejected_401:** Token ingestion wajib disertakan. [PASSED]
- **test_ingest_invalid_token_rejected_401:** Timing-attack resistant HMAC comparison menolak token palsu. [PASSED]
- **test_ingest_quarantines_sensitive_secrets_without_storing:** Password dan private key disanitasi sebelum persistensi. [PASSED]
- **test_collector_commit_and_get_cursor:** Cursor tersimpan secara atomik dengan izin 0600. [PASSED]
- **test_two_phase_commit_commits_only_on_delivery_success:** Cursor tidak bergerak jika backend mengembalikan error. [PASSED]

### 2.3 PostgreSQL & Database Migration (tests/test_postgres_migration.py)
- **test_postgresql_migration_and_constraints_engine:** Validasi skema DDL migration 001-004. [PASSED]
- **test_postgresql_atomic_alert_evidence_rpc:** Validasi fungsi atomik `fn_ingest_alert_with_evidence`. [PASSED]
- **test_postgresql_security_checker_migration:** Validasi skema security checker. [PASSED]

### 2.4 Cloud SSoT Failure Modes (tests/test_cloud_ssot_failure_modes.py)
- **test_fail_loud_when_cloud_fails_in_ssot_mode:** Memastikan seluruh metode repository melempar `RuntimeError` saat Cloud gagal, tanpa silent fallback ke SQLite. [PASSED]
- **test_collector_cursor_retention_on_transmission_failure:** Memastikan collector tidak memajukan kursor saat transmisi gagal. [PASSED]

---

## 3. Bukti Verifikasi Akses & Hak Akses Supabase Cloud (Live)

Eksekusi script `scripts/verify_supabase_privileges_live.py` terhadap instance produksi Supabase Cloud (`hiwfbmwgnpnwaszltqwb.supabase.co`):
```text
=== Testing Unauthenticated Access (Should be BLOCKED) ===
 [PASS] Anon read on 'hosts': Blocked with HTTP 401
 [PASS] Anon read on 'alerts': Blocked with HTTP 401
 [PASS] Anon read on 'alert_evidence': Blocked with HTTP 401
 [PASS] Anon read on 'telemetry_events': Blocked with HTTP 401
 [PASS] Anon read on 'security_check_runs': Blocked with HTTP 401
 [PASS] Anon read on 'security_findings': Blocked with HTTP 401
 [PASS] Anon read on 'incidents': Blocked with HTTP 401
 [PASS] Anon read on 'incident_alerts': Blocked with HTTP 401
 [PASS] Anon read on 'incident_risk_factors': Blocked with HTTP 401
 [PASS] Anon read on 'incident_timeline': Blocked with HTTP 401
 [PASS] Anon read on 'ai_analyses': Blocked with HTTP 401
 [PASS] Anon read on 'incident_status_history': Blocked with HTTP 401
 [PASS] Anon RPC on fn_ingest_alert_with_evidence: Blocked with HTTP 401

=== Testing service_role Authorized Access (Should SUCCEED) ===
 [PASS] service_role read on 'hosts': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'alerts': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'alert_evidence': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'telemetry_events': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'security_check_runs': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'security_findings': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'incidents': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'incident_alerts': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'incident_risk_factors': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'incident_timeline': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'ai_analyses': HTTP 200 OK (rows: 1)
 [PASS] service_role read on 'incident_status_history': HTTP 200 OK (rows: 0)
 [PASS] service_role INSERT on 'incidents': Success (id: TEST-SSOT-VERIFY-9142e967)
 [PASS] service_role UPDATE on 'incidents': Success (status -> investigating)
 [PASS] service_role DELETE on 'incidents': Success (cleaned up)
 [PASS] service_role RPC fn_ingest_alert_with_evidence: Success (success: True)

>>> ALL CLOUD ACCESS & PRIVILEGE VERIFICATIONS PASSED 100% <<<
```

---

## 4. Bukti Kompilasi Frontend Dashboard (React + TypeScript + Vite)

Eksekusi `npm run build` di direktori `dashboard/`:
```text
> aegis-dashboard@0.1.0 build
> tsc -b && vite build

vite v5.4.21 building for production...
transforming...
✓ 1608 modules transformed.
rendering chunks...
computing gzip size...
dist/index.html                                                   1.24 kB │ gzip:   0.65 kB
dist/assets/index-uh1l_bCE.css                                   60.31 kB │ gzip:  16.41 kB
dist/assets/index-BjOhj6Ac.js                                   356.22 kB │ gzip: 100.60 kB
✓ built in 7.33s
```
*Hasil:* 0 kesalahan tipe TypeScript, bundle aset produksi terbuat secara optimal.
