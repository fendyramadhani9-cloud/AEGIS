# AEGIS DATA CONSISTENCY, RECOVERY & SPLIT-BRAIN PREVENTION SPECIFICATION

**Dokumen:** `docs/cloud-ssot-recovery-and-data-consistency.md`  
**Sistem:** AEGIS — AI-Powered Linux Security Monitoring and Incident Investigation  
**Status:** Unified Cloud SSoT Architecture  
**Tanggal:** 8 November 2026  
**Penulis:** Apri (Senior Software Engineer, Database Architect, DevSecOps Lead)

---

## 1. Analisis dan Mitigasi Split-Brain (Dual-Master Prevention)

Salah satu risiko terbesar saat migrasi basis data adalah munculnya kondisi **Split-Brain**, di mana dua basis data (SQLite lokal dan Supabase Cloud) secara simultan menerima penulisan data yang saling berkonflik, atau saat terjadi rollback ke mode Hybrid tanpa rekonsiliasi data yang telah masuk ke Cloud.

### 1.1 Model Kepemilikan Otoritatif Tunggal
AEGIS menerapkan hierarki kepemilikan data yang tegas berdasarkan mode operasi:
1. **Mode `cloud_ssot` (Operasi Normal Produksi):**
   - **Otoritas Tunggal:** Supabase Cloud PostgreSQL adalah satu-satunya master data.
   - **Peran SQLite:** Asynchronous read replica & disaster recovery archive.
   - **Aturan Penulisan:** Semua penulisan harus berhasil di Cloud terlebih dahulu. Penulisan ke SQLite dilakukan melalui mekanisme mirror asinkron (`_execute_mirror`).
   - **Anti-Split-Brain:** Jika Cloud tidak dapat dihubungi, backend menolak operasi (`fail-loud`) dan **TIDAK MENGIZINKAN PENULISAN LOKAL SECARA MANDIRI**. Hal ini menjamin SQLite tidak pernah menyimpang (*diverge*) menjadi master tandingan saat Cloud down.

2. **Mode `hybrid` (Rollback atau Transisional):**
   - **Otoritas Tunggal:** SQLite lokal bertindak sebagai primary storage untuk investigasi.
   - **Transisi Terkendali:** Perpindahan dari `cloud_ssot` kembali ke `hybrid` wajib didahului oleh prosedur rekonsiliasi data (reverse sync) menggunakan `scripts/sync_cloud_to_sqlite.py`.

---

## 2. Analisis Efek Samping Trigger `updated_at` pada 14 Incidents

Pada saat pengujian idempotensi re-import Stage 1, tercatat bahwa kolom `updated_at` pada 14 record insiden mengalami pembaruan timestamp, meskipun konten bisnis tidak berubah.

### 2.1 Investigasi Akar Masalah (Root Cause Analysis)
1. **Definisi Trigger Database:**
   Pada skema dasar Supabase (`001_initial_schema.sql`), terpasang trigger otomatis:
   ```sql
   CREATE OR REPLACE FUNCTION public.fn_set_updated_at()
   RETURNS TRIGGER AS $$
   BEGIN
       NEW.updated_at = clock_timestamp();
       RETURN NEW;
   END;
   $$ LANGUAGE plpgsql;

   CREATE TRIGGER trg_incidents_updated_at
       BEFORE UPDATE ON public.incidents
       FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();
   ```
2. **Perilaku UPSERT PostgREST:**
   Ketika perintah UPSERT dijalankan terhadap record yang sudah ada (`ON CONFLICT (id) DO UPDATE ...`), PostgreSQL mengeksekusi trigger `BEFORE UPDATE`. Fungsi `fn_set_updated_at()` secara mutlak memperbarui `updated_at` menjadi waktu eksekusi (`clock_timestamp()`).
3. **Integritas Timestamp Bisnis:**
   Pemeriksaan mendalam membuktikan bahwa:
   - `created_at` (waktu penciptaan insiden): **100% UTUH DAN TIDAK BERUBAH**.
   - `first_seen_at` (waktu event pertama): **100% UTUH DAN TIDAK BERUBAH**.
   - `last_seen_at` (waktu event terakhir): **100% UTUH DAN TIDAK BERUBAH**.
   - Seluruh kolom klasifikasi ancaman, severity, risk score, dan foreign key: **100% IDENTIK**.
4. **Perbaikan pada Script Rekonsiliasi:**
   Alat audit `scripts/reconcile_delta_cutover.py` telah diperbarui untuk:
   - Mengecualikan perbedaan mikrodetik dan trigger update pada `updated_at` saat membandingkan kesetaraan substantif data.
   - Tidak melakukan operasi UPSERT redundan pada record yang sudah 100% identik substantif, sehingga tidak memicu pembaruan `updated_at` yang tidak perlu.

---

## 3. Batas Transaksi Multi-Tabel & Jaminan Foreign Key

Operasi data pada AEGIS melibatkan relasi multi-tabel yang kompleks:
- `alerts` <-> `alert_evidence` <-> `telemetry_events`
- `incidents` <-> `incident_alerts` <-> `incident_risk_factors` <-> `incident_timeline`
- `security_check_runs` <-> `security_findings`
- `incidents` <-> `incident_status_history`

### 3.1 Transaksi Atomik Alert & Evidence (RPC `fn_ingest_alert_with_evidence`)
- Menjamin bahwa alert dan seluruh bukti telemetri dimasukkan dalam satu transaksi atomik di level basis data.
- Jika terjadi kegagalan pada penyisipan bukti, seluruh alert di-rollback secara otomatis. Tidak pernah ada orphaned alert tanpa bukti.
- Mencegah deadlock dengan pengurutan penguncian baris (`lock ordering`) berbasis `id`.

### 3.2 Isolasi Host (Anti-Cross-Host Conflation)
- Trigger database dan validasi backend menolak keras pengikatan bukti telemetri atau alert yang berasal dari `host_id` berbeda.
- Insiden hanya dapat menghubungkan alert yang berada dalam satu host yang sama.

---

## 4. Rencana Kontinjensi Rollback & Rekonsiliasi Tertutup (Closed-Loop)

Jika terjadi insiden kritis pada Supabase Cloud setelah cutover (misal: pemutusan jaringan WAN atau gangguan hosting cloud), berikut adalah prosedur mitigasi data:

```
[KONDISI CLOUD SSOT] -----> [GANGGUAN TERDETEKSI] -----> [EKSEKUSI ROLLBACK]
        |                                                        |
        v                                                        v
Penulisan ke Cloud          Jika Cloud masih reachable:          Ubah .env ke hybrid
dimirrorkan ke SQLite       Jalankan reverse sync                Restart backend
via _execute_mirror         (sync_cloud_to_sqlite.py)            (Downtime < 15s)
        |                                                        |
        |                   Jika Cloud hard-down:                v
        v                   Data di SQLite sudah mutakhir        SQLite menjadi SSoT
SQLite memiliki snapshot    berkat _execute_mirror               sementara (Hybrid)
terkini secara asinkron     sebelum gangguan terjadi                     |
                                                                         v
                                                        Saat Cloud kembali pulih:
                                                        Jalankan reconcile_delta_cutover.py
                                                        untuk sync data baru ke Cloud.
```

### 4.1 Prosedur Planned Rollback (Cloud Masih Terbaca)
1. Jalankan `python scripts/sync_cloud_to_sqlite.py --sync` untuk menyalin seluruh data dari Cloud ke SQLite lokal.
2. Ubah konfigurasi `/home/ubuntu/aegis/.env` menjadi `AEGIS_DATABASE_MODE=hybrid`.
3. Restart layanan: `sudo systemctl restart aegis-backend.service`.
4. Hasil: Data 100% konsisten, zero data loss, tidak ada inkonsistensi.

### 4.2 Prosedur Emergency Disaster Rollback (Cloud Hard-Down)
1. Langsung ubah konfigurasi `/home/ubuntu/aegis/.env` menjadi `AEGIS_DATABASE_MODE=hybrid`.
2. Restart layanan: `sudo systemctl restart aegis-backend.service`.
3. Backend langsung aktif kembali melayani sistem melalui SQLite lokal yang telah memiliki data mutakhir hasil mirroring hingga detik sebelum outage.
4. Setelah Cloud pulih, jalankan audit delta `python scripts/reconcile_delta_cutover.py` untuk mengidentifikasi dan menyinkronkan data yang dibuat selama masa pemulihan darurat.

---

## 5. Kontinuitas Pengumpul Log (Collector Two-Phase Commit)

Layanan `aegis-collector.service` dirancang mandiri dari status backend:
- Menggunakan **Two-Phase Cursor Commit**:
  1. **Phase 1 (Read):** Membaca baris log baru dari journald dan mendapatkan `pending_cursor`.
  2. **Phase 2 (Transmit & Acknowledge):** Mengirimkan batch log ke endpoint backend `/api/telemetry/ingest`.
  3. **Commit Cursor:** File `.collector_cursor` HANYA diperbarui jika backend mengembalikan respon `HTTP 200 OK`.
- **Ketahanan Terhadap Restart Backend:**
  - Jika backend sedang direstart (downtime < 15 detik), permintaan kirim collector akan mengalami network timeout/connection refused.
  - Collector menahan cursor pada posisi sebelumnya.
  - Pada siklus berikutnya (interval 15 detik), collector mencoba ulang (*retry*) batch log yang sama.
  - **Hasil:** Nol baris log hilang atau terlewatkan selama backend restart.
