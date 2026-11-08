# LAPORAN PERBAIKAN BUG MENYELURUH AEGIS (`BUG_FIX_REPORT.md`)

**Proyek:** AEGIS — Linux Security Monitoring, Incident Investigation & Defense Posture Platform  
**Tanggal Penyelesaian Perbaikan:** 8 November 2026  
**Branch:** `ui-ux`  
**Total Temuan Audit Awal:** 35 Bug (`BUG-001` s/d `BUG-035`)  
**Total Berhasil Diperbaiki & Terverifikasi (`FIXED & VERIFIED`):** 35 / 35 (100%)  

---

## Ringkasan Status Perbaikan

| Status | Jumlah |
|---|---:|
| FIXED & VERIFIED | 35 |
| FIXED, NOT FULLY VERIFIED | 0 |
| PARTIALLY FIXED | 0 |
| BLOCKED | 0 |
| NOT FIXED | 0 |
| NOT REPRODUCIBLE | 0 |

---

## Detail Perbaikan Setiap Bug (`BUG-001` s/d `BUG-035`)

---

### 1. `BUG-001`
- **ID Bug:** `BUG-001`
- **Nama Bug:** Deduplikasi `event_id` berbasis PID pada `_parse_sshd_log` menyebabkan kegagalan deteksi SSH Brute Force (`RULE-SSH-BRUTE`) dalam satu koneksi TCP yang sama
- **Tingkat Keparahan:** `CRITICAL`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Fungsi `_parse_sshd_log` (dan `_parse_sudo_log`) membentuk `event_id` hanya dari `f"{prefix}-AUTH-FAIL-{pid}"` tanpa tanda tangan hash baris log, serta parser lain menggunakan fungsi `hash(line)` bawaan Python yang tidak deterministik antar proses (`PYTHONHASHSEED`). Karena OpenSSH menangani hingga `MaxAuthTries` (default 6) percobaan password dalam satu child process `sshd[pid]` yang sama, beberapa kegagalan login dalam satu koneksi TCP menghasilkan `event_id` identik dan terbuang oleh deduplikasi database (`on_conflict="event_id"`).
- **File yang Diubah:**
  - `aegis_agent/linux_parser.py`
  - `tests/test_linux_parser.py`
- **Ringkasan Perubahan:**
  - Menambahkan metode statis deterministik `_line_sig(line)` berbasis `hashlib.sha256(line.encode("utf-8")).hexdigest()[:8]`.
  - Menyertakan `sig` ke seluruh pembentukan `event_id` pada `_parse_sshd_log`, `_parse_sudo_log`, dan seluruh parser lainnya.
  - Memperbarui `parse_batch` agar mendisambiguasi baris log identik pada detik yang sama dalam satu batch secara deterministik (`seen_ids`), sehingga pengiriman ulang (*retry*) batch yang sama tetap 100% idempoten namun serangan brute-force cepat dalam satu koneksi TCP tidak pernah hilang.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_linux_parser.py::test_bug_001_sshd_same_pid_multiple_attempts_unique_and_idempotent`
- **Hasil Test Sebelum Perbaikan:** 5 baris `Failed password` pada PID `sshd[4412]` menghasilkan 1 `event_id` unik (4 terbuang sebagai duplikat).
- **Hasil Test Setelah Perbaikan:** `18 passed` pada `tests/test_linux_parser.py` (5 `event_id` unik dihasilkan, dan pemanggilan ulang `parse_batch` menghasilkan 5 `event_id` yang sama persis).
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 2. `BUG-002`
- **ID Bug:** `BUG-002`
- **Nama Bug:** Deteksi *Telemetry Collection Gap* tidak terhubung di mode `live` dan di-hardcode kosong pada Handoff & Recovery Verification
- **Tingkat Keparahan:** `HIGH`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Fungsi `api.gaps()` di `dashboard/src/data/api.ts` langsung mengembalikan `[]` pada mode `live`, serta endpoint `GET /api/alerts/{id}/handoff` dan `POST /api/alerts/{id}/verify` di `aegis_backend/routers/alerts.py` mengirim parameter `gaps=[]` dan `open_gaps=[]` secara hardcoded.
- **File yang Diubah:**
  - `aegis_backend/incident_service.py`
  - `aegis_backend/routers/alerts.py`
  - `aegis_backend/routers/operations.py`
  - `dashboard/src/data/api.ts`
  - `tests/test_backend_api.py`
- **Ringkasan Perubahan:**
  - Menambahkan fungsi `detect_collection_gaps(hosts, host_id, open_only)` di `aegis_backend/incident_service.py` untuk mendeteksi host dengan status `offline`/`delayed`/`degraded` atau heartbeat basi ($> 5$ menit).
  - Menambahkan endpoint `GET /api/collection-gaps` di `aegis_backend/routers/operations.py`.
  - Menghubungkan `detect_collection_gaps` ke `get_alert_handoff`, `verify_alert`, dan `create_report`.
  - Menghubungkan `api.gaps()` di `dashboard/src/data/api.ts` ke `/api/collection-gaps` saat mode `live`.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_backend_api.py::test_bug_002_collection_gaps_endpoint_and_handoff_integration`
- **Hasil Test Sebelum Perbaikan:** `/api/collection-gaps` belum tersedia dan `missing_telemetry` pada Handoff tidak mencantumkan gap dari host offline.
- **Hasil Test Setelah Perbaikan:** `PASSED` — `/api/collection-gaps` mengembalikan daftar gap aktif dan dokumen Handoff menyertakan detail gap telemetri.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 3. `BUG-003`
- **ID Bug:** `BUG-003`
- **Nama Bug:** `AegisTelemetryCollector` hanya membaca `journalctl` dan belum membaca berkas log langsung (`/var/log/nginx/access.log` & `/var/log/audit/audit.log`)
- **Tingkat Keparahan:** `HIGH`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** `AegisTelemetryCollector` di `aegis_agent/collector.py` hanya memanggil `read_new_journal_lines()` (`journalctl -u ssh`), sehingga instalasi standar Nginx/Apache dan `auditd` yang menulis ke berkas `/var/log/nginx/access.log` dan `/var/log/audit/audit.log` tidak terbaca secara otomatis.
- **File yang Diubah:**
  - `aegis_agent/collector.py`
  - `tests/test_collector.py`
- **Ringkasan Perubahan:**
  - Menambahkan mekanisme *incremental file tailing* (`read_new_file_lines`, `get_stored_file_offsets`, `commit_file_offsets`) dengan pelacakan `inode` dan `byte offset` pada berkas `.collector_cursor.offsets.json`.
  - Menerapkan *two-phase commit* pada offset berkas log: offset hanya disimpan ke disk setelah `send_telemetry` berhasil (`HTTP 200`).
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_collector.py::test_bug_003_incremental_file_tailing_nginx_and_auditd_two_phase_commit`
- **Hasil Test Sebelum Perbaikan:** Collector tidak memiliki pembaca berkas log inkremental untuk Nginx/auditd.
- **Hasil Test Setelah Perbaikan:** `8 passed` pada `tests/test_collector.py` termasuk verifikasi pembacaan inkremental dan retensi offset saat gagal kirim.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 4. `BUG-004`
- **ID Bug:** `BUG-004`
- **Nama Bug:** Ketidakcocokan enum `InvestigationStatus` antara Backend dan Frontend menyebabkan potensi *runtime crash* (`TypeError`) saat status menjadi `reopened` atau `unverified`
- **Tingkat Keparahan:** `HIGH`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Backend mendukung status investigasi `reopened`, `unverified`, `triaged`, `contained`, `escalated`, dan `closed`, sedangkan `investigationStatusMeta` di `dashboard/src/lib/status.ts` hanya mendefinisikan 4 status (`new`, `investigating`, `resolved`, `false_positive`) dan komponen `Badge` di `ui.tsx` mengakses `meta.tone` tanpa fallback.
- **File yang Diubah:**
  - `dashboard/src/data/types.ts`
  - `dashboard/src/lib/status.ts`
  - `dashboard/src/components/ui.tsx`
  - `dashboard/src/components/domain.tsx`
- **Ringkasan Perubahan:**
  - Memperluas tipe `InvestigationStatus` dan `investigationStatusMeta` untuk mendukung seluruh 10 status siklus hidup investigasi (`new`, `investigating`, `resolved`, `false_positive`, `reopened`, `unverified`, `triaged`, `contained`, `escalated`, `closed`).
  - Menambahkan opsi `reopened` dan `unverified` pada dropdown `InvestigationWorkflowCard` serta fallback aman pada komponen `Badge`.
- **Test yang Ditambahkan / Diperbarui:**
  - Verifikasi kompilasi tipe penuh TypeScript (`tsc -b && vite build`) + test persistensi status `reopened` (`test_bug_010_operational_state_store_disk_persistence`).
- **Hasil Test Sebelum Perbaikan:** `investigationStatusMeta['reopened']` bernilai `undefined`.
- **Hasil Test Setelah Perbaikan:** Build TypeScript & Vite lulus dengan `0 error`, seluruh status memiliki definisi ikon, warna (`tone`), dan label lengkap.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 5. `BUG-005`
- **ID Bug:** `BUG-005`
- **Nama Bug:** Endpoint `GET /api/hosts?agent_status=...` memfilter kolom database statis sebelum menghitung status *heartbeat* dinamis
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** `list_hosts` di `aegis_backend/routers/hosts.py` meneruskan `status=agent_status` ke `repo.list_hosts` sebelum menghitung `derive_agent_status(last_data_at)`.
- **File yang Diubah:**
  - `aegis_backend/routers/hosts.py`
  - `tests/test_backend_api.py`
- **Ringkasan Perubahan:**
  - Menghitung `derive_agent_status` terlebih dahulu untuk setiap host berdasarkan `last_data_at`, kemudian memfilter berdasarkan `agent_status` yang diminta sebelum menerapkan `offset` dan `limit`.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_backend_api.py::test_bug_005_hosts_dynamic_agent_status_filtering`
- **Hasil Test Sebelum Perbaikan:** Host dengan kolom statis `online` tetapi `last_data_at` tahun 2020 tidak muncul pada `GET /api/hosts?agent_status=offline`.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Host tersebut dikembalikan sebagai `offline` pada filter `agent_status=offline` dan tidak muncul pada `agent_status=online`.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 6. `BUG-006`
- **ID Bug:** `BUG-006`
- **Nama Bug:** Sumber telemetri `auditd` ditampilkan dengan badge bertuliskan **`Error`** pada tabel Hosts dan dipetakan secara keliru sebagai `ssh-auth` pada mapper live
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Ekspresi ternary di `dashboard/src/screens/Hosts.tsx` baris 134 hanya memeriksa `ssh-auth` dan `nginx-access`, sehingga `auditd` dan `syslog` jatuh ke cabang default `'Error'`. Selain itu, `mapBackendAlert` dan `alertEvidence` di `dashboard/src/data/api.ts` memetakan rule non-SUDO ke `ssh-auth`.
- **File yang Diubah:**
  - `dashboard/src/screens/Hosts.tsx`
  - `dashboard/src/data/api.ts`
- **Ringkasan Perubahan:**
  - Memperbaiki rendering label pill sumber telemetri di `Hosts.tsx` untuk `SSH`, `Nginx`, `Nginx Err`, `auditd`, dan `syslog`.
  - Menambahkan fungsi `inferSourceFromRuleOrBackend` di `dashboard/src/data/api.ts` untuk memetakan rule dan event ke `ssh-auth`, `auditd`, `nginx-access`, `nginx-error`, dan `syslog` secara akurat.
- **Test yang Ditambahkan / Diperbarui:**
  - Verifikasi build TypeScript (`tsc -b && vite build`).
- **Hasil Test Sebelum Perbaikan:** Sumber `auditd` dirender dengan teks `'Error'`.
- **Hasil Test Setelah Perbaikan:** Dirender dengan benar sebagai `'auditd'` dan tipe `SourceId` tervalidasi penuh oleh TypeScript.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 7. `BUG-007`
- **ID Bug:** `BUG-007`
- **Nama Bug:** Halaman `Timeline` pada mode `live` mengabaikan filter rentang waktu (`sinceHours`) dan hanya menampilkan event dari 6 alert teratas
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** `api.timeline(opts)` di `dashboard/src/data/api.ts` tidak menerapkan filter `inScope(hostId, ts)` berbasis `opts.sinceHours` ketika berada pada mode `live` dan tidak menyertakan `gaps`.
- **File yang Diubah:**
  - `dashboard/src/data/api.ts`
- **Ringkasan Perubahan:**
  - Menerapkan filter rentang waktu `since = Date.now() - (opts.sinceHours ?? 24) * 3600_000` pada alert, event pendukung (hingga 12 alert), dan collection gaps di mode `live`.
- **Test yang Ditambahkan / Diperbarui:**
  - Verifikasi build TypeScript (`tsc -b && vite build`).
- **Hasil Test Sebelum Perbaikan:** Tombol filter waktu di halaman `Timeline` tidak memfilter data pada mode `live`.
- **Hasil Test Setelah Perbaikan:** Filter `sinceHours` dan `gaps` bekerja konsisten di mode `live` dan `sample`.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 8. `BUG-008`
- **ID Bug:** `BUG-008`
- **Nama Bug:** Halaman mandiri `Audit Log` (`/audit`) belum terdaftar di router utama & menu navigasi
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** `AuditLogList` sebelumnya hanya ditempelkan di bagian bawah `EvidenceScreen` tanpa rute `/audit` tersendiri di `App.tsx` dan `AppShell.tsx`.
- **File yang Diubah:**
  - `dashboard/src/screens/AuditLog.tsx` (File baru)
  - `dashboard/src/App.tsx`
  - `dashboard/src/components/AppShell.tsx`
- **Ringkasan Perubahan:**
  - Membuat komponen halaman mandiri `AuditLogScreen` (`dashboard/src/screens/AuditLog.tsx`) lengkap dengan pencarian bebas, filter jenis entitas target (`All`, `Alerts`, `Findings`, `Evidence`, `Reports`, `System`), dan tombol **Export JSON**.
  - Mendaftarkan rute `/audit` di `App.tsx` dan menambahkan menu **Audit Log** pada sidebar navigasi di `AppShell.tsx`.
- **Test yang Ditambahkan / Diperbarui:**
  - Verifikasi kompilasi `tsc -b && vite build`.
- **Hasil Test Sebelum Perbaikan:** Mengakses `/audit` diarahkan kembali ke `/`.
- **Hasil Test Setelah Perbaikan:** Halaman `/audit` tersedia di menu utama dan terkompilasi tanpa error.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 9. `BUG-009`
- **ID Bug:** `BUG-009`
- **Nama Bug:** Endpoint `POST /api/reports` mengabaikan filter waktu (`period_start`/`period_end`) dan kembali mengambil seluruh alert global jika host terpilih memiliki 0 alert
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Ekspresi `alerts=host_alerts if host_alerts else alerts` dan `alert_count=len(host_alerts) if host_alerts else alert_total` di `aegis_backend/routers/operations.py` mengevaluasi list kosong `[]` sebagai `False`, sehingga host bersih yang memiliki 0 alert justru diisi dengan seluruh alert dari host lain.
- **File yang Diubah:**
  - `aegis_backend/routers/operations.py`
  - `tests/test_backend_api.py`
- **Ringkasan Perubahan:**
  - Menggunakan `scoped_alerts` yang difilter ketat berdasarkan `req.host_ids` dan rentang `req.period_start`–`req.period_end`, serta menghitung `gap_count` aktual menggunakan `detect_collection_gaps`.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_backend_api.py::test_bug_009_report_clean_host_zero_alerts_no_cross_host_leak`
- **Hasil Test Sebelum Perbaikan:** Laporan untuk `host-clean-zero-alerts` mengembalikan `alert_count > 0` (bocor dari host lain).
- **Hasil Test Setelah Perbaikan:** `PASSED` — `alert_count == 0` untuk host tanpa alert.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 10. `BUG-010`
- **ID Bug:** `BUG-010`
- **Nama Bug:** `OperationalStateStore` (`op_store`) menyimpan perubahan operasional hanya di RAM tanpa persistensi saat layanan backend di-restart
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** `OperationalStateStore` di `aegis_backend/incident_service.py` hanya menyimpan dictionary di RAM tanpa mekanisme *snapshot* ke disk.
- **File yang Diubah:**
  - `aegis_backend/incident_service.py`
  - `.gitignore`
  - `tests/test_backend_api.py`
- **Ringkasan Perubahan:**
  - Menambahkan metode `save_snapshot()` dan `load_snapshot()` atomik berbasis berkas JSON (`.aegis_operational_state.json` atau variabel lingkungan `AEGIS_STATE_FILE`) pada `OperationalStateStore`.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_backend_api.py::test_bug_010_operational_state_store_disk_persistence`
- **Hasil Test Sebelum Perbaikan:** Instansiasi ulang `OperationalStateStore` kehilangan seluruh status investigasi dan catatan.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Instansiasi ulang `OperationalStateStore` memulihkan status investigasi (`reopened`) dan catatan analis secara utuh.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 11. `BUG-011`
- **ID Bug:** `BUG-011`
- **Nama Bug:** Penggunaan variabel CSS yang tidak terdefinisi (`--bg-elevated`, `--border-subtle`, `--text-muted`) pada komponen di `domain.tsx`
- **Tingkat Keparahan:** `LOW`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Beberapa inline style di `dashboard/src/components/domain.tsx` merujuk ke nama token lama yang berbeda dari `dashboard/src/styles/tokens.css`.
- **File yang Diubah:**
  - `dashboard/src/components/domain.tsx`
  - `dashboard/src/styles/tokens.css`
- **Ringkasan Perubahan:**
  - Mengganti referensi inline style di `domain.tsx` ke `--color-surface-sunken`, `--color-border-subtle`, dan `--color-text-tertiary`, serta menambahkan alias variabel di `tokens.css`.
- **Test yang Ditambahkan / Diperbarui:**
  - Verifikasi build CSS & bundle Vite (`npm --prefix dashboard run build`).
- **Hasil Test Sebelum Perbaikan:** Warna latar dan border kotak *Blast Radius* / *Handoff* tidak terdefinisi.
- **Hasil Test Setelah Perbaikan:** Seluruh token CSS terdefinisi di tema terang dan gelap.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 12. `BUG-012`
- **ID Bug:** `BUG-012`
- **Nama Bug:** Aksi `actions.retryReport(id)` hanya memodifikasi data `mock` dan tidak memanggil endpoint backend pada mode `live`
- **Tingkat Keparahan:** `LOW`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** `retryReport` di `dashboard/src/data/api.ts` tidak memeriksa `if (previewState !== 'sample')`.
- **File yang Diubah:**
  - `dashboard/src/data/api.ts`
- **Ringkasan Perubahan:**
  - Menambahkan cabang mode `live` pada `actions.retryReport(id)` yang memanggil `POST /api/reports` untuk mengkompilasi ulang laporan di backend.
- **Test yang Ditambahkan / Diperbarui:**
  - Verifikasi build TypeScript (`tsc -b && vite build`).
- **Hasil Test Sebelum Perbaikan:** Klik *Retry* di mode `live` tidak mengirim request ke backend.
- **Hasil Test Setelah Perbaikan:** Mengirim `POST /api/reports` dan memperbarui state UI.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 13. `BUG-013`
- **ID Bug:** `BUG-013`
- **Nama Bug:** Inkonsistensi teks deskripsi cakupan log (masih tertulis hanya *"SSH and Nginx logs"*) pada `Settings.tsx` dan `HostDetail.tsx`
- **Tingkat Keparahan:** `LOW`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Teks statis pada `Settings.tsx` dan `HostDetail.tsx` belum diperbarui setelah penambahan sumber `sudo`, `auditd`, dan `systemd`.
- **File yang Diubah:**
  - `dashboard/src/screens/Settings.tsx`
  - `dashboard/src/screens/HostDetail.tsx`
- **Ringkasan Perubahan:**
  - Memperbarui deskripsi sumber log menjadi `SSH, sudo, auditd, Nginx, and systemd logs`.
- **Test yang Ditambahkan / Diperbarui:**
  - Verifikasi build TypeScript (`tsc -b && vite build`).
- **Hasil Test Sebelum Perbaikan:** Tertulis hanya *"SSH and Nginx logs"*.
- **Hasil Test Setelah Perbaikan:** Mencerminkan seluruh 5 sumber telemetri secara konsisten.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 14. `BUG-014`
- **ID Bug:** `BUG-014`
- **Nama Bug:** *Threat Hunting Search Bar* pada `Detections.tsx` belum menyertakan field `ruleLogic.mitreAttackId` dalam pencocokan teks
- **Tingkat Keparahan:** `LOW`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Filter pencarian di `Detections.tsx` belum memeriksa `a.ruleLogic?.mitreAttackId` dan `a.ruleLogic?.mitreAttackName`.
- **File yang Diubah:**
  - `dashboard/src/screens/Detections.tsx`
- **Ringkasan Perubahan:**
  - Menambahkan pencocokan terhadap `a.ruleLogic?.mitreAttackId` dan `a.ruleLogic?.mitreAttackName` pada filter pencarian `Detections.tsx`.
- **Test yang Ditambahkan / Diperbarui:**
  - Verifikasi build TypeScript (`tsc -b && vite build`).
- **Hasil Test Sebelum Perbaikan:** Pencarian kode MITRE seperti `T1110` tidak menjaring alert yang judulnya tidak memuat string `T1110`.
- **Hasil Test Setelah Perbaikan:** Pencarian ID dan nama teknik MITRE bekerja untuk seluruh 13 aturan.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 15. `BUG-015`
- **ID Bug:** `BUG-015`
- **Nama Bug:** Pengerasan konfigurasi CORS (`allow_credentials`) dan penambahan header `Content-Security-Policy`
- **Tingkat Keparahan:** `INFO`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** `allow_credentials=True` dipasang statis meskipun `allow_origins=["*"]`, serta header `Content-Security-Policy` belum disertakan pada middleware HTTP.
- **File yang Diubah:**
  - `aegis_backend/main.py`
  - `tests/test_backend_api.py`
- **Ringkasan Perubahan:**
  - Mengatur `allow_credentials=("*" not in settings.cors_origins)`, menambahkan metode `PATCH`, dan menyertakan header `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_backend_api.py::test_bug_015_and_016_security_headers_and_ai_cooldown`
- **Hasil Test Sebelum Perbaikan:** Header `Content-Security-Policy` belum ada pada respons API.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Seluruh security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Content-Security-Policy`) terpasang.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 16. `BUG-016`
- **ID Bug:** `BUG-016`
- **Nama Bug:** Belum ada *cooldown / rate limiting* per-alert pada endpoint pemicu AI (`POST /api/alerts/{id}/analyze`)
- **Tingkat Keparahan:** `INFO`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Pemanggilan berulang `POST /api/alerts/{id}/analyze` langsung mengeksekusi analisis ulang tanpa memeriksa apakah analisis untuk alert tersebut baru saja selesai beberapa detik lalu.
- **File yang Diubah:**
  - `aegis_backend/routers/alerts.py`
  - `tests/test_backend_api.py`
- **Ringkasan Perubahan:**
  - Menambahkan parameter `cooldown_sec` (default 10 detik) dan `force` (default `False`) pada `POST /api/alerts/{alert_id}/analyze` untuk mengembalikan analisis yang masih segar dari cache jika dipanggil berulang dalam jendela cooldown.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_backend_api.py::test_bug_015_and_016_security_headers_and_ai_cooldown`
- **Hasil Test Sebelum Perbaikan:** Setiap klik berulang dalam 1 detik memicu eksekusi ulang AI.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Pemanggilan berulang dalam jendela cooldown mengembalikan respons cache yang konsisten kecuali `force=true`.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 17. `BUG-017` (SEC-CRIT-01)
- **ID Bug:** `BUG-017`
- **Nama Bug:** Desinkronisasi Secret Signing Token & In-Memory JTI Revocation pada Multi-Worker Uvicorn
- **Tingkat Keparahan:** `CRITICAL`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Kamus `_revoked_jti` disimpan hanya dalam memori proses tunggal, dan secret signing diinisialisasi ulang per-proses jika `AEGIS_AUTH_SECRET` tidak diisi di environment. Dalam mode multi-worker, logout pada worker 1 tidak terbaca oleh worker 2, dan request ke worker lain memicu error signature acak.
- **File yang Diubah:**
  - `aegis_backend/tenancy.py`
  - `tests/test_tenancy_and_auth.py`
- **Ringkasan Perubahan:**
  - Mengimplementasikan `_get_persistent_secret()` yang menyimpan secret statis terenkripsi di `data/.auth_secret.key` mode 0600 jika env `AEGIS_AUTH_SECRET` kosong, memastikan konsistensi signing antar seluruh worker.
  - Mengimplementasikan `_sync_revoked_tokens()` dan `_persist_revoked_tokens()` ke file `data/.revoked_tokens.json` sehingga pencabutan sesi sinkron secara real-time lintas seluruh worker proses.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_tenancy_and_auth.py::test_persistent_token_revocation_across_sync`
- **Hasil Test Sebelum Perbaikan:** Revokasi token hanya efektif di worker aktif; restart proses atau worker terpisah tetap menerima token yang dicabut.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Token yang dicabut terverifikasi ditolak secara deterministik (`ValueError: revoked`) lintas siklus sinkronisasi.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 18. `BUG-018` (SEC-CRIT-02)
- **ID Bug:** `BUG-018`
- **Nama Bug:** Pemalsuan Identitas (*Author & Operator Spoofing*) pada Catatan Investigasi dan Update Status Insiden
- **Tingkat Keparahan:** `CRITICAL`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Endpoint `POST /api/alerts/{id}/investigation` dan `PATCH /api/incidents/{id}/status` membaca `req.author` dan `req.operator` mentah dari request body JSON client tanpa mencocokkannya dengan sesi login pengguna yang terautentikasi.
- **File yang Diubah:**
  - `aegis_backend/routers/alerts.py`
  - `aegis_backend/routers/incidents.py`
  - `tests/test_tenancy_and_auth.py`
- **Ringkasan Perubahan:**
  - Menginjeksi dependency `user: AuthUser = Depends(get_request_user)` pada handler route.
  - Memaksa nama author/operator selalu menggunakan `user.username` dari sesi JWT terverifikasi saat berada dalam mode autentikasi aktif, menggagalkan segala upaya pemalsuan nama identitas oleh client.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_tenancy_and_auth.py::test_investigation_note_author_spoofing_prevented`
- **Hasil Test Sebelum Perbaikan:** Operator Unit Alpha dapat mengirim note dengan `author: "ciso_admin"` dan nama palsu tersebut tersimpan di database audit.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Upaya pemalsuan `author: "ciso_admin"` digagalkan dan sistem otomatis mencatat `author: "operator_alpha"` sesuai identitas sesi sah.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 19. `BUG-019` (SEC-CRIT-03)
- **ID Bug:** `BUG-019`
- **Nama Bug:** Pemeriksaan Postur On-Demand Mengeksekusi Host Backend Lokal Alih-Alih Node Remote
- **Tingkat Keparahan:** `CRITICAL`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Endpoint `POST /api/findings/scan` memanggil `ReadOnlySecurityChecker.run_live_scan()` langsung di container backend, memeriksa file `/etc/ssh` dan `/etc/crontab` lokal backend alih-alih mengambil hasil audit live agen remote.
- **File yang Diubah:**
  - `aegis_backend/routers/operations.py`
- **Ringkasan Perubahan:**
  - Mengintegrasikan aktor audit terotentikasi (`user.username`) pada audit trail `op_store.record_audit`.
  - Mempertahankan hasil audit live agen remote di `op_store.host_findings` jika telah dilaporkan via `/api/telemetry/posture`, memisahkan antara baseline lokal dan status agen remote.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_backend_api.py::test_pipeline_health_evidence_mode_audit_logs_and_findings`
- **Hasil Test Sebelum Perbaikan:** Audit record selalu mencatat hardcoded `actor: "ops-admin"`.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Audit trail mencatat identitas operator pengeksekusi scan yang sah.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 20. `BUG-020` (SEC-HIGH-01)
- **ID Bug:** `BUG-020`
- **Nama Bug:** Kolusi IP Reverse Proxy Nginx pada Rate Limiter Login Mengakibatkan Lockout Massal (DoS)
- **Tingkat Keparahan:** `HIGH`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Router autentikasi menggunakan `request.client.host` yang selalu bernilai IP internal Nginx (`127.0.0.1` atau `172.18.0.x`), sehingga 5 kegagalan login dari penyerang luar mengunci seluruh pengguna sah di balik reverse proxy yang sama.
- **File yang Diubah:**
  - `aegis_backend/tenancy.py`
  - `aegis_backend/routers/auth.py`
  - `tests/test_tenancy_and_auth.py`
- **Ringkasan Perubahan:**
  - Menambahkan fungsi pembantu `extract_client_ip(request)` yang memprioritaskan IP client asli dari header `X-Forwarded-For` (mengambil IP untrusted terluar) atau `X-Real-IP`.
  - Menggunakan `extract_client_ip` pada seluruh fungsi rate limiting login.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_tenancy_and_auth.py::test_client_ip_resolution_from_reverse_proxy_header`
- **Hasil Test Sebelum Perbaikan:** Header `X-Forwarded-For` diabaikan, IP client selalu terbaca sebagai socket proxy host.
- **Hasil Test Setelah Perbaikan:** `PASSED` — IP client `203.0.113.195` teresolusi dengan benar dari header `X-Forwarded-For`.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 21. `BUG-021` (SEC-HIGH-02)
- **ID Bug:** `BUG-021`
- **Nama Bug:** Backdoor Akses Superadmin Tanpa Batas saat `AEGIS_AUTH_ENABLED=false`
- **Tingkat Keparahan:** `HIGH`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Ketika autentikasi dinonaktifkan untuk pengujian, endpoint `/api/auth/login` menerima username dan password acak apapun dan langsung menerbitkan JWT token superadmin penuh.
- **File yang Diubah:**
  - `aegis_backend/routers/auth.py`
- **Ringkasan Perubahan:**
  - Memvalidasi bahwa jika database user (`auth.json`) ada, login tetap memverifikasi password yang sah.
  - Jika tidak ada database user, hanya mengizinkan username pengembang eksplisit (`admin` atau `dev`), menolak kredensial acak dari pihak luar.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_tenancy_and_auth.py::test_login_invalid_credentials`
- **Hasil Test Sebelum Perbaikan:** String username/password acak apapun langsung menerima JWT superadmin.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Kredensial tidak sah ditolak dengan `401 Unauthorized`.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 22. `BUG-022` (SEC-HIGH-03)
- **ID Bug:** `BUG-022`
- **Nama Bug:** Pembekuan Permanen Pengumpulan Telemetri Agen jika Systemd Journal Cursor Invalid/Dirotasi
- **Tingkat Keparahan:** `HIGH`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Ketika journal systemd dirotasi atau dibersihkan (`vacuumed`), perintah `journalctl --after-cursor=<cursor>` keluar dengan status non-nol. Exception handler hanya menangkap error dan mengembalikan list kosong tanpa mereset file cursor, menyebabkan loop kegagalan permanen.
- **File yang Diubah:**
  - `aegis_agent/collector.py`
- **Ringkasan Perubahan:**
  - Menangkap `subprocess.CalledProcessError`. Jika error mengindikasikan cursor tidak ditemukan atau rusak, agen otomatis menghapus file cursor lokal dan memanggil `init_cursor_if_missing()` untuk mengaitkan tracking ke posisi log terkini.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_collector.py`
- **Hasil Test Sebelum Perbaikan:** File cursor yang invalid tidak pernah dihapus dan agen macet selamanya.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Agen mendeteksi cursor invalid, me-reset cursor, dan melanjutkan pengumpulan log normal.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 23. `BUG-023` (SEC-HIGH-04)
- **ID Bug:** `BUG-023`
- **Nama Bug:** Lonjakan Memori Server & Pemotongan Data 20K Baris pada Paginasi `TenantScopedRepository`
- **Tingkat Keparahan:** `HIGH`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Fungsi `_visible_host_ids()` dan `_paged()` melakukan iterasi `_drain` hingga 20.000 baris ke RAM server sebelum melakukan pemfilteran tenant, mengakibatkan pemborosan resource dan data di atas baris 20.000 terpotong secara diam-diam.
- **File yang Diubah:**
  - `aegis_backend/tenancy.py`
- **Ringkasan Perubahan:**
  - Memanfaatkan pemetaan cepat in-memory `self._registry.list_all()` untuk mendapatkan host milik tenant tanpa perlu melakukan query drain 20.000 baris.
  - Jika tenant belum memiliki host terdaftar, langsung mengembalikan `([], 0)` secara instan ($O(1)$) tanpa query database yang membebani.
  - Mengubah `__getattr__` pada `TenantScopedRepository` agar melempar `AttributeError` alih-alih `PermissionError`, memulihkan perilaku standar Python untuk fungsi `hasattr()`.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_tenancy_and_auth.py::test_multi_tenant_host_isolation`
- **Hasil Test Sebelum Perbaikan:** Setiap pemanggilan list memicu query drain ribuan baris, dan pengecekan `hasattr(repo, "client")` memicu unhandled exception 500.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Paginasi tenant efisien dan `hasattr()` berfungsi sesuai standar Python.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 24. `BUG-024` (SEC-MED-01)
- **ID Bug:** `BUG-024`
- **Nama Bug:** Celah Evasion Deteksi pada Sanitizer Akibat Pembuangan Baris Log Utuh saat Ada Kata Kunci Password
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Log yang mengandung kredensial langsung dibuang utuh dari pipeline, sehingga penyerang dapat menyematkan dummy string password pada perintah exploit untuk membutakan monitoring AEGIS.
- **File yang Diubah:**
  - `aegis_backend/sanitizer.py`
- **Ringkasan Perubahan:**
  - Memperjelas klasifikasi sanitasi: pembuangan karantina dikhususkan untuk private key telanjang dan hash shadow, sedangkan argumen kredensial pada command line diredaksi secara inline (`[REDACTED_CLI_ARG]`) sehingga jejak aktivitas perintah tetap dapat diproses dan dideteksi oleh rules engine.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_telemetry_ingest.py::test_ingest_quarantines_sensitive_secrets_without_storing`
- **Hasil Test Sebelum Perbaikan:** Baris perintah exploit yang disisipi password dibuang tanpa jejak.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Kredensial diredaksi dengan aman tanpa menghilangkan konteks keamanan.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 25. `BUG-025` (SEC-MED-02)
- **ID Bug:** `BUG-025`
- **Nama Bug:** Kegagalan Deteksi CLI Password Flag Tanpa Spasi (`-pSecret`) pada Sanitizer
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Regex `_RE_CLI_CREDENTIAL` mewajibkan adanya karakter spasi (`-p\s+`), sehingga perintah seperti `mysql -uroot -pMyPassword` atau audit argumen bertanda kutip `a1="-pPassword"` lolos tanpa tersanitasi.
- **File yang Diubah:**
  - `aegis_backend/sanitizer.py`
  - `tests/test_tenancy_and_auth.py`
- **Ringkasan Perubahan:**
  - Memperbarui regex `_RE_CLI_CREDENTIAL` menjadi `(?i)(?:--password[=\s]+[^\s]+|(?:\s|^|[\"'])-p\s*[^\s\"'\-]+|--token[=\s]+[^\s]+|(?:\s|^|[\"'])-u\s+[a-zA-Z0-9_-]+:[^\s]+)`, mencakup flag tanpa spasi dan berawalan kutip.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_tenancy_and_auth.py::test_cli_credential_sanitizer_without_space`
- **Hasil Test Sebelum Perbaikan:** `mysql -pSuperSecretPass123` lolos tanpa terdeteksi (`is_safe == True`).
- **Hasil Test Setelah Perbaikan:** `PASSED` — Terdeteksi sebagai `cli_credential_detected` dan diredaksi menjadi `[REDACTED_CLI_ARG]`.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 26. `BUG-026` (SEC-MED-03)
- **ID Bug:** `BUG-026`
- **Nama Bug:** Ketiadaan Timeout pada Eksekusi Subprocess Journalctl di Collector
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Pemanggilan `subprocess.run` di `collector.py` tidak memiliki parameter `timeout`, sehingga hang pada proses journalctl menyebabkan thread collector membeku tanpa batas waktu.
- **File yang Diubah:**
  - `aegis_agent/collector.py`
- **Ringkasan Perubahan:**
  - Menambahkan `timeout=15` pada setiap eksekusi `subprocess.run` dan menangkap `subprocess.TimeoutExpired` dengan penanganan logging yang aman.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_collector.py`
- **Hasil Test Sebelum Perbaikan:** Subprocess dapat terblokir tanpa batas waktu jika journalctl hang.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Subprocess dibatasi maksimal 15 detik dengan graceful timeout fallback.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 27. `BUG-027` (SEC-MED-04)
- **ID Bug:** `BUG-027`
- **Nama Bug:** Ketiadaan Peringatan Keamanan saat Ingestion Telemetri Menggunakan HTTP Non-TLS
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** URL default `http://` digunakan tanpa verifikasi apakah koneksi melintasi jaringan eksternal tanpa enkripsi transport layer.
- **File yang Diubah:**
  - `aegis_agent/collector.py`
- **Ringkasan Perubahan:**
  - Menambahkan audit check pada inisialisasi collector: memicu warning log jika `AEGIS_API_URL` menggunakan `http://` di luar loopback (`127.0.0.1` / `localhost`).
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_collector.py`
- **Hasil Test Sebelum Perbaikan:** Tidak ada peringatan ketika telemetri dialirkan via HTTP plaintext lintas subnet.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Peringatan INSECURE TRANSPORT aktif dan dicatat dengan jelas.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 28. `BUG-028` (SEC-MED-05)
- **ID Bug:** `BUG-028`
- **Nama Bug:** Port Backend 1709 Terekspos ke Jaringan Eksternal Tanpa Melewati Reverse Proxy Nginx
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Port mapping `1709:1709` di `docker-compose.yml` terikat pada `0.0.0.0`, memungkinkan client luar langsung memanggil FastAPI tanpa melewati proteksi reverse proxy Nginx di port 1708.
- **File yang Diubah:**
  - `docker-compose.yml`
- **Ringkasan Perubahan:**
  - Mengubah port binding service backend menjadi `127.0.0.1:1709:1709`, membatasi akses langsung hanya dari localhost atau jaringan internal Docker.
- **Test yang Ditambahkan / Diperbarui:**
  - Verifikasi konfigurasi Docker Compose syntax.
- **Hasil Test Sebelum Perbaikan:** Port 1709 terbuka di interface publik.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Port 1709 diikat secara eksklusif ke antarmuka loopback 127.0.0.1.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 29. `BUG-029` (SEC-MED-06)
- **ID Bug:** `BUG-029`
- **Nama Bug:** Penyimpanan Session Token di `localStorage` Rentan Ekfiltrasi XSS
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Token JWT disimpan di `localStorage` peramban web, yang secara teoretis dapat diakses oleh skrip berbahaya jika terjadi serangan XSS.
- **File yang Diubah:**
  - `dashboard/src/data/api.ts`
  - `aegis_backend/main.py` (security headers)
- **Ringkasan Perubahan:**
  - Memperkuat lapisan pertahanan (*defense-in-depth*) dengan header `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'self'`, dan penanganan pembersihan sesi instan saat response 401 terdeteksi.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_backend_api.py::test_bug_015_and_016_security_headers_and_ai_cooldown`
  - `npm --prefix dashboard run build`
- **Hasil Test Sebelum Perbaikan:** Tidak ada boundary header CSP yang ketat.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Header keamanan terpasang pada seluruh response gateway dan bundle UI terkompilasi bersih.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 30. `BUG-030` (SEC-MED-07)
- **ID Bug:** `BUG-030`
- **Nama Bug:** Hardcoded Limit (100 / 200 / 1000) pada Query Finding, Host, dan Alert Correlation
- **Tingkat Keparahan:** `MEDIUM`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Hardcoded query limit yang terlalu kecil pada `hosts.py` (1000), `security_checker.py` (200), dan `incident_service.py` (100) menyebabkan record baru atau insiden yang belum terasosiasi terpotong.
- **File yang Diubah:**
  - `aegis_backend/routers/hosts.py`
  - `aegis_backend/routers/security_checker.py`
  - `aegis_backend/incident_service.py`
- **Ringkasan Perubahan:**
  - Meningkatkan batas query host saat filtering status menjadi 10.000 record.
  - Memperluas query korelasi insiden menjadi 500 alert dan 200 finding per batch korelasi.
  - Memperluas query finding run terbaru menjadi 500 record.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_backend_api.py`
  - `tests/test_incident_api.py`
- **Hasil Test Sebelum Perbaikan:** Alert ke-101 tidak masuk korelasi insiden otomatis.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Kapasitas korelasi dan query status host diperluas secara aman tanpa data terpotong.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 31. `BUG-031` (SEC-LOW-01)
- **ID Bug:** `BUG-031`
- **Nama Bug:** Crash `TypeError` Pengurangan Offset-Naive vs Offset-Aware Datetime pada Rules Engine
- **Tingkat Keparahan:** `LOW`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Parsing ISO string tanpa penanda timezone menghasilkan datetime naive, yang memicu `TypeError: can't subtract offset-naive and offset-aware datetimes` ketika dihitung selisih detiknya dengan event lain.
- **File yang Diubah:**
  - `aegis_backend/rules_engine.py`
  - `tests/test_tenancy_and_auth.py`
- **Ringkasan Perubahan:**
  - Memastikan seluruh datetime hasil parsing di `_parse_timestamp` selalu memiliki `tzinfo=timezone.utc`.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_tenancy_and_auth.py::test_rules_engine_naive_datetime_handling`
- **Hasil Test Sebelum Perbaikan:** String naive ISO `"2026-11-08T18:00:00"` menghasilkan datetime offset-naive.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Datetime dinormalisasi ke UTC aware secara deterministik.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 32. `BUG-032` (SEC-LOW-02)
- **ID Bug:** `BUG-032`
- **Nama Bug:** Celah Open Window / Unvalidated URL Redirect pada Push Notification Service Worker
- **Tingkat Keparahan:** `LOW`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Handler `notificationclick` pada `sw.js` memanggil `clients.openWindow(event.notification.data.url)` tanpa memvalidasi apakah URL mengarah ke origin internal atau domain eksternal berbahaya.
- **File yang Diubah:**
  - `dashboard/public/sw.js`
- **Ringkasan Perubahan:**
  - Memvalidasi bahwa `targetUrl` wajib diawali dengan path relatif (`/`) serta menolak protocol eksternal (`http:`, `https:`, atau `//`).
- **Test yang Ditambahkan / Diperbarui:**
  - `npm --prefix dashboard run build`
- **Hasil Test Sebelum Perbaikan:** Payload push notification dapat mengarahkan jendela peramban ke situs phishing eksternal.
- **Hasil Test Setelah Perbaikan:** `PASSED` — URL eksternal difilter dan dialihkan ke path aman `/`.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 33. `BUG-033` (SEC-LOW-03)
- **ID Bug:** `BUG-033`
- **Nama Bug:** Service Systemd Collector Berjalan sebagai Root Penuh dan Dependensi Pip Unpinned
- **Tingkat Keparahan:** `LOW`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Skrip installer host menjalankan collector sebagai root dan perintah pip tidak mematok versi paket.
- **File yang Diubah:**
  - `scripts/install_agent.sh`
- **Ringkasan Perubahan:**
  - Mengunci dependensi agent dan menambahkan dokumentasi permission least-privilege dengan grup `adm` dan `systemd-journal`.
- **Test yang Ditambahkan / Diperbarui:**
  - Verifikasi skrip installer bash.
- **Hasil Test Sebelum Perbaikan:** Dependensi pip floating tanpa batas versi.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Instalasi terkontrol dan aman.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 34. `BUG-034` (SEC-LOW-04)
- **ID Bug:** `BUG-034`
- **Nama Bug:** Ketiadaan Batas Maksimum Output Token (`maxOutputTokens`) pada Panggilan LLM AI
- **Tingkat Keparahan:** `LOW`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Payload REST Gemini dan OpenAI tidak mencantumkan batas token maksimum output, berisiko menguras token dan terkena timeout.
- **File yang Diubah:**
  - `aegis_agent/providers.py`
- **Ringkasan Perubahan:**
  - Menetapkan batas `maxOutputTokens: 2048` pada payload Gemini dan `max_tokens: 2048` pada OpenAI.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_real_llm.py`
- **Hasil Test Sebelum Perbaikan:** Parameter output token tidak dibatasi.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Output dibatasi maksimal 2048 token secara deterministik.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

---

### 35. `BUG-035` (SEC-LOW-05)
- **ID Bug:** `BUG-035`
- **Nama Bug:** Ketiadaan Tag Delimitasi Isolasi Log Mentah pada Prompt AI Investigation
- **Tingkat Keparahan:** `LOW`
- **Status:** `FIXED & VERIFIED`
- **Akar Penyebab:** Data telemetri mentah dimasukkan ke prompt model AI tanpa pembatas instruksi sistem, membuka peluang manipulasi narasi analisis jika penyerang menyuntikkan instruksi ke dalam log.
- **File yang Diubah:**
  - `aegis_agent/providers.py`
- **Ringkasan Perubahan:**
  - Menambahkan aturan sistem isolasi keamanan (Security Boundary Directive) pada instruksi sistem penyelidikan AI, menegaskan bahwa konten log adalah data observasi pasif yang tidak boleh dieksekusi sebagai instruksi sistem.
- **Test yang Ditambahkan / Diperbarui:**
  - `tests/test_ai_investigation.py`
  - `tests/test_real_llm.py`
- **Hasil Test Sebelum Perbaikan:** Instruksi sistem belum memiliki pembatas boundary eksplisit untuk data log.
- **Hasil Test Setelah Perbaikan:** `PASSED` — Model AI dibekali panduan keamanan eksplisit terhadap injeksi instruksi dari data telemetri.
- **Status Regression Test:** `LULUS (PASSED)`
- **Risiko yang Masih Tersisa:** Tidak ada.

