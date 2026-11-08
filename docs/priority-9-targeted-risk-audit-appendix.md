# LAMPIRAN AUDIT RISIKO TERARAH (TARGETED RISK AUDIT APPENDIX)
**AEGIS Enterprise Cyber Defense Platform**
**Prioritas:** 9 — Final Cloud Migration Review & Production Cutover Preparation
**Dokumen Induk:** `docs/priority-9-final-cloud-migration-review.md`
**Tanggal Pembaruan:** 8 November 2026 (Final Readiness Review)
**Pelaksana:** Apri (Senior Cybersecurity Engineer & Full-Stack Platform Architect)
**Status Operasional:** **HYBRID MODE DIPERTAHANKAN — CUTOVER BELUM DISETUJUI (NO-GO)**

---

## 1. Pendahuluan & Batasan Pembuktian Epistemologis

Lampiran ini menyajikan hasil penelaahan terarah dan evaluasi batas pembuktian (*epistemological boundaries*) atas **empat risiko residual** sebelum ada keputusan produksi. 

Sesuai arahan Project Owner, seluruh klaim teknis diklasifikasikan secara ketat ke dalam 4 kategori:
1. `VERIFIED LIVE (READ-ONLY)`: Terbukti langsung pada VM `fenn` atau Supabase Cloud tanpa mutasi.
2. `VERIFIED IN SIMULATION / LOCAL TEST`: Terbukti pada lingkungan pengujian lokal (PGlite / SQLite in-memory / unit tests).
3. `UNTESTED ON PRODUCTION CLOUD SCHEMA`: Belum dapat dibuktikan pada Supabase Cloud karena DDL 002–004 belum pernah diterapkan di Cloud.
4. `THEORETICAL ESTIMATE / KNOWN LIMITATION`: Estimasi berbasis model perhitungan atau batasan arsitektural yang diakui secara sadar.

---

## 2. Audit Risiko 1 — RLS & Production Role Access

### 2.1. Hardening DDL & Konsistensi Hak Akses (`REVOKE` / `GRANT`)
- **Status Bukti:** `VERIFIED IN SIMULATION / LOCAL TEST` & `STATIC CATALOG AUDIT`.
- **Implementasi:**
  Pada file individual `004_incident_investigation.sql` dan `unified_migration_002_to_004.sql`, telah ditambahkan instruksi pencabutan hak akses eksplisit sebelum pemberian hak akses backend:
  ```sql
  -- Least Privilege Access Control: Explicitly revoke public, anon, authenticated
  REVOKE ALL ON TABLE public.incidents FROM PUBLIC, anon, authenticated;
  REVOKE ALL ON TABLE public.incident_alerts FROM PUBLIC, anon, authenticated;
  REVOKE ALL ON TABLE public.incident_risk_factors FROM PUBLIC, anon, authenticated;
  REVOKE ALL ON TABLE public.incident_timeline FROM PUBLIC, anon, authenticated;
  REVOKE ALL ON TABLE public.ai_analyses FROM PUBLIC, anon, authenticated;
  REVOKE ALL ON TABLE public.incident_status_history FROM PUBLIC, anon, authenticated;

  -- Grant backend service_role and postgres permissions
  GRANT ALL ON TABLE public.incidents TO service_role, postgres;
  GRANT ALL ON TABLE public.incident_alerts TO service_role, postgres;
  GRANT ALL ON TABLE public.incident_risk_factors TO service_role, postgres;
  GRANT ALL ON TABLE public.incident_timeline TO service_role, postgres;
  GRANT ALL ON TABLE public.ai_analyses TO service_role, postgres;
  GRANT ALL ON TABLE public.incident_status_history TO service_role, postgres;
  ```

### 2.2. Hasil Pengujian Simulasi Role (`tests/test_targeted_rls_and_roles.cjs`):
- **Role `service_role`:**
  - `INSERT` dan `SELECT` pada `incidents`: **LULUS (Akses Penuh)**.
  - `INSERT` dan `SELECT` pada `security_check_runs` & `security_findings`: **LULUS**.
  - Eksekusi RPC `fn_ingest_alert_with_evidence`: **LULUS**.
- **Role `anon` (Public API Key):**
  - `SELECT` pada `incidents`: **DITOLAK (0 baris / RLS Deny-All)**.
  - `INSERT` pada `incidents`: **DITOLAK (`permission denied for table incidents`)**.
  - `SELECT` pada `security_findings`: **DITOLAK (`permission denied for table security_findings`)**.
  - Eksekusi RPC Ingest: **DITOLAK (`permission denied for function fn_ingest_alert_with_evidence`)**.
- **Role `authenticated` (Login User):**
  - `INSERT` pada `incidents`: **DITOLAK (`permission denied`)**.
  - Eksekusi RPC Ingest: **DITOLAK (`permission denied`)**.

### 2.3. Batasan Pembuktian (Caveat):
> [!IMPORTANT]
> **Batasan Produksi (`UNTESTED ON PRODUCTION CLOUD SCHEMA`):**
> Pengujian di atas membuktikan bahwa konfigurasi DDL dan logika PostgreSQL sudah benar pada engine PGlite. Namun, **karena Supabase Cloud belum menerima migrasi 002–004, perilaku autentikasi JWT gateway PostgREST produksi pada skema baru belum pernah diuji secara live**. Pengujian live hanya dapat dilakukan setelah DDL diterapkan di Cloud.

---

## 3. Audit Risiko 2 — Importer & Dependensi Cloud Baseline

### 3.1. Hasil Pemeriksaan Dependensi Data (`scripts/audit_cloud_dependencies.py`):
- **Status Bukti:** `VERIFIED LIVE (READ-ONLY)`.
- **Data Cloud Aktual:**
  - `hosts`: 1 host (`host-fenn-ubuntu`).
  - `alerts`: 13 alert historis.
  - `alert_evidence`: 23 relasi evidence.
- **Pencocokan 136 Record SQLite VM:**
  - **Host Foreign Key:** 100% dari 136 record merujuk ke `'host-fenn-ubuntu'`. Missing host: **0**.
  - **Alert Foreign Key:** 100% dari parent alert yang dirujuk oleh 14 insiden dan 23 junction `incident_alerts` **cocok persis dengan 13 alert di Cloud**. Missing alert: **0**.
  - **Isolasi Host:** 0 host mismatch. Seluruh insiden dan alert berada pada host yang sama (`host-fenn-ubuntu`).

### 3.2. Batasan Pembuktian (Caveat):
> [!WARNING]
> **Batasan Produksi (`THEORETICAL ESTIMATE / KNOWN LIMITATION`):**
> Kecocokan referensial ini membuktikan bahwa tidak ada data yatim (*orphan data*) terhadap baseline Cloud saat ini. Namun, hal ini **belum menjamin** bahwa eksekusi live impor melalui jaringan WAN tidak akan mengalami gangguan latensi HTTP, batas payload PostgREST, atau lock timeout selama transaksi berjalan.

---

## 4. Audit Risiko 3 — Konkurensi & Resiliensi Mirror Worker

### 4.1. Hasil Pengujian Unit (`tests/test_mirror_worker_concurrency.py`):
- **Status Bukti:** `VERIFIED IN SIMULATION / LOCAL TEST`.
- **Skenario 1 (Intra-Process Concurrency):** Dua thread mengeksekusi `replay_failed_mirrors()` bersamaan. Kunci `threading.RLock()` dan klausa `ON CONFLICT (id)` berhasil mencegah rekaman ganda (5/5 record unik, status: `synced`).
- **Skenario 2 (SQLite Failure):** Saat SQLite disimulasikan mengalami disk lock/IO error, status record **tetap `pending_retry`** dan tidak pernah menghasilkan status 'synced' palsu.
- **Skenario 3 (Startup Recovery):** Record `pending_retry` dari proses lama berhasil dipulihkan secara otomatis saat inisialisasi backend (`lifespan`).
- **Skenario 4 (Strict Flow Direction):** Diverifikasi bahwa fungsi mirror **hanya melakukan operasi baca** terhadap Cloud (0 panggilan `insert`/`update`/`delete`). Arah aliran data selalu **Cloud SSoT $\rightarrow$ SQLite Lokal**.

### 4.2. Batasan Arsitektural Multi-Process & Stale Overwrites:
> [!CAUTION]
> **Batasan Arsitektural yang Diakui (`THEORETICAL ESTIMATE / KNOWN LIMITATION`):**
> 1. **Batas Kunci Thread:** `threading.RLock()` hanya melindungi konkurensi di dalam **satu proses Python tunggal**. Kunci ini tidak melindungi jika backend dijalankan dengan multi-worker (`uvicorn --workers > 1`) atau beberapa instance terdistribusi.
> 2. **Risiko Stale Overwrite:** Klausa `ON CONFLICT (id) DO UPDATE` mencegah duplikasi primary key, tetapi tanpa *monotonic versioning* (misal nomor versi increment atau vector clock), ada kemungkinan proses yang tertinggal menimpa data yang lebih baru di SQLite dengan data lama.
> 3. **Mitigasi di Lingkungan VM Saat Ini:** Pada VM `fenn`, `aegis-backend.service` beroperasi sebagai **satu proses tunggal** (`PID 51764`, 1 instance Uvicorn di port 8000), sehingga risiko konkurensi multi-proses belum aktif pada topologi saat ini. Namun, ini tetap dicatat sebagai batasan desain bila sistem discale di masa depan.

---

## 5. Audit Risiko 4 — Koreksi Klaim Retensi Journald Collector

### 5.1. Koreksi Formal Atas Klaim "Zero Telemetry Loss"
> [!NOTE]
> **Koreksi Klaim Teknis:**
> Klaim sebelumnya bahwa *"Zero Telemetry Loss terbukti secara matematis"* **DITARIK DAN DIKOREKSI**. Angka yang dilaporkan adalah **estimasi kapasitas retensi (Retention Headroom Estimation)** berdasarkan asumsi beban terukur, bukan jaminan mutlak ketiadaan log loss.

### 5.2. Data Pengukuran Aktual VM `fenn` (`scripts/measure_vm_journal_metrics.py`):
- **Status Bukti:** `VERIFIED LIVE (READ-ONLY)`.
- **Kapasitas Filesystem:** 9,75 GB Total, 3,89 GB Bebas.
- **Batas Maksimum Journal (`SystemMaxUse`):** 997,93 MB (10% batas FS).
- **Penggunaan Journal Saat Ini:** **184,00 MB** (23 file journal aktif di `/var/log/journal`).
- **Headroom Bebas Sebelum Rotasi Log:** **813,93 MB**.
- **Volume Log Terukur (1 Jam Terakhir):**
  - Total Log Sistem: 491 entri/jam (**557,65 KB / jam**, rata-rata 1.163 bytes/entri).
  - Telemetri Keamanan (SSH, PAM, Sudo): 69 entri/jam (**72,34 KB / jam**).

### 5.3. Estimasi Durasi Retensi Berdasarkan Model:
1. **Model Beban Normal (~558 KB/jam):**
   $$\text{Estimasi Headroom} = \frac{813,93\text{ MB}}{0,544\text{ MB/jam}} \approx \mathbf{62,3\text{ hari}}$$
2. **Model Serangan Ekstrem (100 percobaan login/detik $\approx 418,7\text{ MB/jam}$):**
   $$\text{Estimasi Headroom} = \frac{813,93\text{ MB}}{418,7\text{ MB/jam}} \approx \mathbf{1,94\text{ jam (118 menit)}}$$

### 5.4. Skenario Nyata yang Dapat Menyebabkan Kehilangan Telemetri (Known Failure Modes):
Meskipun kapasitas disk mencukupi, kehilangan telemetri tetap dapat terjadi dalam kondisi berikut:
1. **Log Vacuuming / Aggressive Rotation:** Eksekusi `journalctl --vacuum-size` atau `systemd-journald` me-rotate journal file saat batas ukuran file per-arsip tercapai.
2. **Downtime Melebihi Headroom:** Jika collector tidak aktif melebihi jendela retensi saat terjadi banjir event log.
3. **Cursor Invalidation:** File `/home/ubuntu/aegis/.collector_cursor` korup, terhapus, atau pointer cursor berada di luar rentang log yang tersisa di disk.
4. **Filesystem Saturation:** Partisi root `/` penuh akibat file log lain atau proses di luar journald.
5. **Network Ingestion Stalls:** Collector kehabisan memori buffer lokal jika backend mengalami unreachable berkepanjangan saat volume event sangat tinggi.
6. **Log Surge di Luar Asumsi:** Serangan terdistribusi dengan intensitas > 500 event/detik yang dapat menghabiskan headroom 813 MB dalam hitungan belasan menit.

---

## 6. Audit Konsistensi File Migrasi SQL

Pemeriksaan konsistensi teks dan substansi antara file individual dan script unified dijalankan secara otomatis:
- **`002_atomic_alert_evidence_rpc.sql`** $\rightarrow$ Cocok 100% di dalam `unified_migration_002_to_004.sql`.
- **`003_security_checker.sql`** $\rightarrow$ Cocok 100% di dalam `unified_migration_002_to_004.sql`.
- **`004_incident_investigation.sql`** $\rightarrow$ Cocok 100% di dalam `unified_migration_002_to_004.sql`.
- **Batas Transaksi:** Dibungkus dalam blok atomik tunggal `BEGIN; ... COMMIT;`.
- **Privilege & Owner:** Seluruh function dimiliki oleh `postgres`, search path diset ke `public, pg_temp`, eksekusi publik dicabut, dan diberikan strictly kepada `service_role`.

---

## 7. Kesimpulan & Rekomendasi Akhir

| Parameter | Status Evaluasi | Rekomendasi |
| :--- | :---: | :--- |
| **Kesiapan DDL & Schema** | Lulus Simulasi & Audit Konsistensi | Siap bila disetujui |
| **Kesiapan Data 136 Record**| Lulus Rekonsiliasi & Dependensi Cloud | Siap bila disetujui |
| **Resiliensi Mirror Worker** | Lulus Single-Process (Ada batasan multi-process) | Diterima dengan catatan |
| **Estimasi Retensi Telemetri**| Terukur 813 MB Headroom (Bukan jaminan mutlak) | Diterima dengan catatan |
| **Status Supabase Cloud** | 100% Untouched (Nol DDL, Nol Impor) | Terpelihara |
| **Layanan VM fenn** | Backend & Collector Aktif di Hybrid Mode | Terpelihara |

### Rekomendasi: **`NO-GO FOR CUTOVER AT THIS TIME`**
Sistem AEGIS **tetap beroperasi pada arsitektur Hybrid Mode**. Seluruh hasil pengujian dan batasan arsitektur telah tercatat secara jujur dan transparan. Tidak ada tindakan lanjutan yang akan dieksekusi tanpa persetujuan eksplisit dari Project Owner.
