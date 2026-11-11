# AEGIS — STAGE 2 DATA RECONCILIATION EVIDENCE
## Comprehensive Parity & Foreign Key Audit Between SQLite and Supabase Cloud

**Execution Timestamp:** 2026-11-11 06:59:12 WIB / 2026-11-10 23:59:12 UTC  
**Target Database (Authoritative SSoT):** Supabase Cloud PostgreSQL 15.8 (`https://hiwfbmwgnpnwaszltqwb.supabase.co`)  
**Target Local Database (Replica/Mirror):** `/home/ubuntu/aegis/data/aegis_incidents.db` on host `fenn`  
**Audit Tool:** `scripts/audit_post_stage1_reconciliation.py`  
**Overall Reconciliation Status:** **100% PARITY — ZERO DATA DRIFT — ZERO ORPHANS** `[VERIFIED]`  

---

### 1. Rekonsiliasi Delapan Tabel Operasional Inti

Audit mencocokkan setiap record secara deterministik berdasarkan Primary Key, foreign key traversal, serta validasi field-level:

| Tabel Operasional | Cloud PostgreSQL | SQLite Lokal | Selisih Record | Missing in SQLite | Status Paritas |
|:---|:---:|:---:|:---:|:---:|:---:|
| `security_check_runs` | 1 | 1 | 0 | 0 | **100% MATCH** `[VERIFIED]` |
| `security_findings` | 28 | 28 | 0 | 0 | **100% MATCH** `[VERIFIED]` |
| `incidents` | 14 | 14 | 0 | 0 | **100% MATCH** `[VERIFIED]` |
| `incident_alerts` | 23 | 23 | 0 | 0 | **100% MATCH** `[VERIFIED]` |
| `incident_risk_factors` | 42 | 42 | 0 | 0 | **100% MATCH** `[VERIFIED]` |
| `incident_timeline` | 21 | 21 | 0 | 0 | **100% MATCH** `[VERIFIED]` |
| `ai_analyses` | 7 | 7 | 0 | 0 | **100% MATCH** `[VERIFIED]` |
| `incident_status_history` | 0 | 0 | 0 | 0 | **100% MATCH** `[VERIFIED]` |
| **Total Operasional Inti** | **136** | **136** | **0** | **0** | **PERFECT PARITY** `[VERIFIED]` |

---

### 2. Validasi Foreign Key & Pencegahan Orphan Record

Pemeriksaan referensial dieksekusi langsung pada database Cloud PostgreSQL:

1. **`incident_alerts` ➔ `incidents`:**
   - Evaluasi relasi `incident_id`: 23 relasi dipetakan.
   - Orphan records terdeteksi: `0` `[PASS]` `[VERIFIED]`.
2. **`incident_risk_factors` ➔ `incidents`:**
   - Evaluasi relasi `incident_id`: 42 faktor risiko dipetakan.
   - Orphan records terdeteksi: `0` `[PASS]` `[VERIFIED]`.
3. **`incident_timeline` ➔ `incidents`:**
   - Evaluasi relasi `incident_id`: 21 tonggak kronologi dipetakan.
   - Orphan records terdeteksi: `0` `[PASS]` `[VERIFIED]`.
4. **`ai_analyses` ➔ `incidents`:**
   - Evaluasi relasi `incident_id`: 7 analisis forensik AI dipetakan.
   - Orphan records terdeteksi: `0` `[PASS]` `[VERIFIED]`.
5. **`security_findings` ➔ `security_check_runs`:**
   - Evaluasi relasi `run_id`: 28 temuan pemeriksaan CIS dipetakan.
   - Orphan records terdeteksi: `0` `[PASS]` `[VERIFIED]`.

---

### 3. Validasi Field-Level dan Konsistensi Nilai Kritis

Audit memvalidasi keselarasan nilai field-level pada data sampel kritis:
1. **Primary Key Coverage:** 100% record Cloud memiliki padanan ID unik di SQLite.
2. **Status & Severity:** Seluruh 14 insiden mempertahankan nilai `status` (`new`) dan `severity` (`high`/`critical`) yang identik.
3. **Risk Scoring Engine:** Nilai `risk_score` (misal 97 pada insiden utama `INC-host-fenn-ubuntu-771f6d1f7346`) dan `risk_level` (`critical`) tersimpan konsisten antara Cloud dan SQLite.
4. **AI Investigation Findings:**
   - Record `ANL-INC-host-fenn-ubuntu-771f6d1f7346-17940` mempertahankan seluruh array JSON: 8 facts, 6 timeline events, 13 supporting evidence links, dan 3 rekomendasi containment.
   - Nullability dan default value terbukti identik.

---

### 4. Status Tabel Baseline Cloud (Ingestion & Stream)

Tabel berikut beroperasi sebagai sumber data telemetri real-time yang dialirkan langsung dari collector ke Cloud:

| Tabel Baseline Cloud | Total Record Aktif di Cloud | Fungsi Operasional | Status Aliran Data |
|:---|:---:|:---|:---:|
| `hosts` | 1 | Inventaris host Linux (`host-fenn-ubuntu`) | Aktif & Online `[VERIFIED]` |
| `system_status` | 1 | Status singleton backend & heartbeat | Terupdate otomatis `[VERIFIED]` |
| `alerts` | 13 | Deteksi aturan keamanan hasil normalisasi | Tersedia di API `[VERIFIED]` |
| `alert_evidence` | 23 | Bukti telemetri pendukung alert | Terhubung ke insiden `[VERIFIED]` |
| `telemetry_events` | 1,785+ | Log streaming Linux host (auth, sudo, audit) | Mengalir real-time `[VERIFIED]` |

*Catatan: Sesuai arsitektur sistem, tabel telemetri streaming di Cloud tidak diduplikasi secara menyeluruh ke SQLite lokal untuk menjaga efisiensi I/O dan storage VM.*

---

### 5. Laporan Konflik Data (Conflict Report)

- **Total Konflik Terdeteksi:** `0` (Nol).
- **Unresolved Data Drift:** `0`.
- **Rekomendasi Penanganan:** Tidak ada rekonsiliasi destruktif atau penimpaan data yang diperlukan. Integritas data operasional telah mencapai status 100% sinkron.
