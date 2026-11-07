# AEGIS AI Incident Investigation Agent & Backend — Prototype v0.9

Prototipe mandiri (*standalone prototype*) dan server backend untuk sistem **AEGIS (AI Incident Investigation Agent)**.

Komponen ini mencakup:
1. **FastAPI Backend Gateway (`aegis_backend/`):** REST API server-side terintegrasi dengan PostgreSQL Supabase `AEGIS-dev` (project `hiwfbmwgnpnwaszltqwb`), mengisolasi akses database hanya melalui `service_role` tanpa membuka akses langsung ke client publik (`anon`).
2. **Runtime Monitor (RM):** Investigasi alert dinamis berbasis Hybrid A+B dengan **Evidence Grounding & Quantitative Fidelity Checks**.
3. **Security Checker (SC):** Evaluasi postur keamanan berbasis Enriched Context A+ (audit snapshot tanpa scanning aktif).
4. **Reporting Agent:** Agregator dan synthesizer murni dari temuan SC dan RM yang tersimpan.
5. **Linux Telemetry Normalization & Parser:** Parser deterministik untuk mentransformasi raw syslog SSH (`/var/log/auth.log`), auditd process logs (`audit.log`), dan network socket snapshots (`ss`) menjadi standardized model `LogEventInput`.
6. **Linux Log Pipeline Adapter:** Adapter jembatan antara raw stream telemetry dengan pipeline investigasi `IncidentInvestigationInput`.
7. **AI Evaluation Harness:** Suite benchmarking offline otomatis yang mengukur akurasi status, preservasi severity, validitas sitasi bukti, dan tingkat klaim tanpa dasar.
8. **Frontend Dashboard (`dashboard/`):** Aplikasi React 18 + TypeScript + Vite.

---

## 1. Arsitektur Komponen & Backend Gateway

- **`aegis_backend/`**:
  - `main.py`: Entrypoint aplikasi FastAPI, konfigurasi CORS, dan global exception handling tersanitasi (tanpa kebocoran kredensial/stack trace).
  - `config.py`: Pengelolaan konfigurasi environment server-side (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `API_HOST`, `API_PORT`) dengan fungsi masking secret otomatis.
  - `repository.py`: Abstraksi repository database (`BaseAegisRepository`, `SupabaseRepository`, `MockAegisRepository`) yang memungkinkan pengujian 100% offline dan live query ke Supabase secara aman.
  - `schemas.py`: Kontrak data Pydantic HTTP API yang selaras dengan skema 13 tabel Supabase.
  - `routers/`:
    - `health.py`: `GET /api/health` dan `GET /api/health/database`.
    - `system.py`: `GET /api/system/status`.
    - `hosts.py`: `GET /api/hosts` dan `GET /api/hosts/{host_id}` (dengan validasi pagination).
    - `alerts.py`: `GET /api/alerts` dan `GET /api/alerts/{alert_id}` (read-only, severity terkunci).
- **`aegis_agent/`**: Core AI components (services, providers, validator, investigator, parser, adapter).
- **`supabase/migrations/001_initial_schema.sql`**: Skema 13 tabel ternormalisasi dengan database-level triggers (severity lock, cross-host evidence guard, automatic `clock_timestamp()` updated_at, dan RLS revocation).

---

## 2. Cara Menjalankan Backend Lokal

### A. Menjalankan FastAPI Server
```powershell
& "D:\AEGIS\.venv\Scripts\python.exe" -m uvicorn aegis_backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Buka dokumentasi Swagger interaktif di: `http://127.0.0.1:8000/docs`

### B. Konfigurasi Environment (`.env`)
Salin berkas `.env.example` ke `.env` dan lengkapi variabel berikut:
```env
AEGIS_ENV=development
API_HOST=127.0.0.1
API_PORT=8000
SUPABASE_URL=https://hiwfbmwgnpnwaszltqwb.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<service_role_secret_key>
```
*(Catatan: Jangan pernah memasukkan `SUPABASE_SERVICE_ROLE_KEY` ke kode frontend atau Git).*

---

## 3. Cara Menjalankan Pengujian

### A. Seluruh Test Suite Otomatis (60 Tests — 100% Offline Tanpa Butuh API Key)
```powershell
& "D:\AEGIS\.venv\Scripts\python.exe" -m pytest "D:\AEGIS\tests" -v
```

### B. Menjalankan AI Evaluation Harness (8 Skenario)
```powershell
$env:PYTHONPATH="D:\AEGIS"
& "D:\AEGIS\.venv\Scripts\python.exe" "D:\AEGIS\evaluation\run_evaluation.py"
```

### C. Build Frontend React
```powershell
cd dashboard
npm run build
```
