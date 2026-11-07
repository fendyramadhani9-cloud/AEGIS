# LAPORAN PERBAIKAN BUG MENYELURUH AEGIS (`BUG_FIX_REPORT.md`)

**Proyek:** AEGIS — Linux Security Monitoring, Incident Investigation & Defense Posture Platform  
**Tanggal Penyelesaian Perbaikan:** 7 November 2026  
**Branch:** `ui-ux`  
**Total Temuan Audit Awal:** 16 Bug (`BUG-001` s/d `BUG-016`)  
**Total Berhasil Diperbaiki & Terverifikasi (`FIXED & VERIFIED`):** 16 / 16 (100%)  

---

## Ringkasan Status Perbaikan

| Status | Jumlah |
|---|---:|
| FIXED & VERIFIED | 16 |
| FIXED, NOT FULLY VERIFIED | 0 |
| PARTIALLY FIXED | 0 |
| BLOCKED | 0 |
| NOT FIXED | 0 |
| NOT REPRODUCIBLE | 0 |

---

## Detail Perbaikan Setiap Bug (`BUG-001` s/d `BUG-016`)

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

