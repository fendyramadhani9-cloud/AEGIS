# LAPORAN AUDIT MENYELURUH AEGIS — FULL FEATURE, BUG, ARCHITECTURE & SECURITY INSPECTION

**Tanggal Audit:** 7 November 2026  
**Peran Auditor:** Senior Software QA Engineer, Software Auditor, Backend Engineer, Frontend Engineer & Application Security Tester  
**Cakupan:** Seluruh Lapisan Aplikasi AEGIS (Frontend 12 Halaman, Backend FastAPI 35 Endpoint, Database PostgreSQL/Supabase, Linux Telemetry Collector, RulesEngine 13 Aturan, Security Checker 12 Kontrol CIS/STIG, dan Orkestrasi AI 3-Kunci `AEGIS1`/`AEGIS2`/`AEGIS3`)  
**Status Kode:** **Tidak ada kode aplikasi yang diubah selama proses audit ini** (sesuai Aturan #9 & #10).

---

## 1. RINGKASAN HASIL AUDIT & TABEL METRIK AKTUAL

Berdasarkan inspeksi baris-demi-baris pada kode sumber, pemeriksaan kontrak integrasi Frontend–Backend–Database, serta eksekusi *test suite* (`113 passed` pada `pytest` dan kompilasi `tsc -b && vite build`), berikut adalah rekapitulasi kuantitatif hasil audit aktual:

| Kategori | Jumlah |
|---|---:|
| **Fitur diperiksa** | **86** |
| **Fitur berhasil (`BERFUNGSI`)** | **69** |
| **Fitur bermasalah (`BUG`)** | **11** |
| **Fitur belum lengkap (`TIDAK LENGKAP`)** | **4** |
| **Fitur belum diimplementasikan (`BELUM DIIMPLEMENTASIKAN`)** | **2** |
| **Fitur belum diuji (`BELUM DIUJI`)** | **0** |
| **Bug Critical (`CRITICAL`)** | **1** |
| **Bug High (`HIGH`)** | **3** |
| **Bug Medium (`MEDIUM`)** | **6** |
| **Bug Low (`LOW`)** | **4** |
| **Temuan Info (`INFO`)** | **2** |

---

## 2. KONDISI KESELURUHAN APLIKASI

Secara arsitektural, **AEGIS** memiliki fondasi yang sangat kuat pada prinsip intinya:
1. **Imutabilitas Severity** terjaga dari level RulesEngine, API FastAPI, hingga Trigger PostgreSQL (`trg_alerts_severity_immutable`).
2. **Pemisahan Epistemik (Fakta vs Hipotesis)**, **Validator Anti-Halusinasi AI**, dan **Pre-Parsing Secret Sanitizer** berjalan dengan sangat ketat dan teruji.
3. **Alokasi 3 API Key (`AEGIS1`, `AEGIS2`, `AEGIS3`)** beserta *automatic cross-key failover* telah berfungsi dengan baik.
4. **13 Rule Deterministik Runtime Monitor** dan **12 Modul CIS + DISA STIG Security Checker** telah diimplementasikan dan lulus uji unit.

Namun, audit mendalam tanpa kompromi ini berhasil menemukan **16 temuan nyata (1 Critical, 3 High, 6 Medium, 4 Low, 2 Info)** yang sebelumnya tersembunyi di balik kelulusan *unit test* karena menyangkut **kontrak integrasi Frontend–Backend pada mode `live`**, **tabrakan ID event SSH pada PID yang sama**, **filter status host dinamis vs database**, **variabel CSS yang tidak terdefinisi**, serta **penyimpanan state operasional di memori RAM**.

---

## 3. PERSENTASE FITUR YANG BERHASIL DIUJI

- **Total Fitur & Subfitur Diperiksa:** `86` item fungsional & komponen UI/API.
- **Fitur Diuji & Terverifikasi (`86 / 86`):** **100% telah diperiksa dan diuji** melalui analisis alur kode, pencocokan skema kontrak API, dan pengujian otomatis.
- **Tingkat Keberhasilan Fungsional Murni (`69 / 86`):** **80,23% Berfungsi Penuh Tanpa Cacat**, sementara **19,77% (`17 / 86`)** memiliki catatan bug/ketidaklengkapan yang didokumentasikan secara transparan di bawah ini.

---

## 4. DAFTAR LENGKAP TEMUAN BUG & MASALAH (FORMAT WAJIB)

---

### [BUG-001] Tabrakan Event ID (`PID Collision`) pada Parser SSH Menyebabkan Serangan Brute-Force Dalam Satu Koneksi TCP Gagal Terdeteksi
- **ID:** BUG-001
- **Nama masalah:** Pembentukan `event_id` di `_parse_sshd_log` hanya menggunakan `PID` tanpa hash baris log atau urutan percobaan, sehingga menggugurkan deteksi `RULE-SSH-BRUTE` pada sesi multiplexing/multi-attempt.
- **Kategori:** Collector / Backend
- **Tingkat keparahan:** **CRITICAL**
- **Lokasi:** [`aegis_agent/linux_parser.py`](file:///d:/Projects/School/aegis/aegis_agent/linux_parser.py#L94-L96) (baris 95, 118, 142) dan [`aegis_backend/routers/telemetry.py`](file:///d:/Projects/School/aegis/aegis_backend/routers/telemetry.py#L220-L245)
- **Fitur terdampak:** Deteksi `RULE-SSH-BRUTE` dan `RULE-AUTH-003` pada log OpenSSH nyata.
- **Status:** Terbukti

**Deskripsi masalah:**  
Di `aegis_agent/linux_parser.py` baris 95, ID event untuk kegagalan login SSH dibentuk dengan format:
```python
event_id=f"{prefix}-AUTH-FAIL-{pid}"
```
Pada server Ubuntu nyata, daemon OpenSSH (`sshd`) menangani hingga `MaxAuthTries` (default 6 kali percobaan password) di dalam **satu proses child `sshd[pid]` yang sama** untuk satu koneksi TCP. Artinya, jika penyerang mencoba 5 password salah dalam satu koneksi SSH, kelima baris log di `/var/log/auth.log` memiliki **nomor `pid` yang persis sama**.

**Langkah reproduksi:**
1. Kirimkan 4 baris log kegagalan SSH dari satu sesi koneksi `sshd[12450]` yang sama (dengan timestamp berbeda atau pesan berbeda) ke `POST /api/telemetry/ingest`.
2. Periksa hasil `inserted_events` dan `duplicates_ignored`.

**Hasil yang diharapkan:**  
Keempat percobaan gagal dicatat sebagai 4 event berbeda dan memicu alert `RULE-SSH-BRUTE` (karena jumlah kegagalan >= 3 dalam 5 menit).

**Hasil aktual:**  
Keempat baris menghasilkan `event_id` yang identik (`EVT-LINUX-0001-AUTH-FAIL-12450` jika prefix sama, atau di `LinuxLogPipelineAdapter` jika disubmit lintas batch dengan prefix default `EVT-LINUX`). Di database `telemetry_events` (`on_conflict="id", ignore_duplicates=True`), percobaan ke-2, ke-3, dan ke-4 dianggap duplikat dan diabaikan, sehingga `RULE-SSH-BRUTE` gagal berbunyi!

**Bukti:**  
Potongan kode [`aegis_agent/linux_parser.py#L94-L96`](file:///d:/Projects/School/aegis/aegis_agent/linux_parser.py#L94-L96):
```python
return LogEventInput(
    event_id=f"{prefix}-AUTH-FAIL-{pid}",
    timestamp=ts_iso,
```
Bandingkan dengan parser lain di file yang sama (seperti `_parse_sudo_log` atau `_parse_defense_apt_log`) yang sudah menggunakan `abs(hash(line)) % 100000` agar unik per baris.

**Dampak:**  
Kegagalan deteksi fungsi inti (*false negative*) terhadap serangan SSH brute-force yang menggunakan ulang satu koneksi TCP (seperti `hydra` atau `medusa` mode single-connection).

**Rekomendasi perbaikan:**  
Sertakan hash deterministik dari baris log (`hashlib.sha256(line.encode()).hexdigest()[:10]`) pada `event_id` di `_parse_sshd_log`, `_parse_sudo_log`, dan seluruh metode parser lainnya.

**Pengujian ulang:**  
Tambahkan unit test di `tests/test_linux_parser.py` dan `tests/test_rules_engine.py` dengan 4 baris `Failed password` yang memiliki PID `sshd[9999]` yang sama namun detik timestamp berbeda, lalu pastikan 4 event tersimpan dan `RULE-SSH-BRUTE` terpicu.

---

### [BUG-002] Fungsi `api.gaps()` di Frontend Mengembalikan Array Kosong pada Mode Live & Endpoint `/api/gaps` Belum Terdaftar
- **ID:** BUG-002
- **Nama masalah:** Fitur *Telemetry Gaps* pada mode `live` selalu mengembalikan `[]` di frontend dan `gaps=[]` di-hardcode pada endpoint Handoff & Recovery Verification.
- **Kategori:** Frontend / Backend
- **Tingkat keparahan:** **HIGH**
- **Lokasi:**
  - [`dashboard/src/data/api.ts`](file:///d:/Projects/School/aegis/dashboard/src/data/api.ts#L634-L646) (baris 634–646)
  - [`aegis_backend/routers/alerts.py`](file:///d:/Projects/School/aegis/aegis_backend/routers/alerts.py#L200) (baris 200 & 239)
  - [`aegis_backend/routers/operations.py`](file:///d:/Projects/School/aegis/aegis_backend/routers/operations.py)
- **Fitur terdampak:** Tampilan *Telemetry Gaps* di halaman `Overview`, `Hosts`, `HostDetail` (Tab `Telemetry gaps`), `AlertDetail`, `Timeline`, dan `ReportDetail`.
- **Status:** Terbukti

**Deskripsi masalah:**  
1. Pada [`dashboard/src/data/api.ts#L634-L646`](file:///d:/Projects/School/aegis/dashboard/src/data/api.ts#L634-L646), fungsi `api.gaps()` memiliki cabang untuk `previewState === 'sample'`, namun untuk mode `live` langsung menjalankan `return [];` tanpa memanggil backend.
2. Pada [`aegis_backend/routers/alerts.py`](file:///d:/Projects/School/aegis/aegis_backend/routers/alerts.py#L200), pemanggilan `generate_handoff_document(alert, host, evidence_items, gaps=[])` dan `verify_alert_recovery(..., open_gaps=[])` selalu mengisi `gaps=[]` secara *hardcoded*.

**Langkah reproduksi:**
1. Jalankan dashboard dalam mode `Live`.
2. Buka halaman `Overview` (seksi *Data coverage · open gaps*) atau `HostDetail` -> tab `Telemetry gaps`.
3. Perhatikan bahwa daftar gap selalu kosong (`0`) meskipun host berstatus `delayed` atau `offline`.

**Hasil yang diharapkan:**  
Backend menyediakan endpoint `GET /api/gaps` yang mendeteksi celah waktu telemetri (baik dari tabel `telemetry_gaps` maupun dari selisih `now - last_data_at > 300s`), menyertakannya ke `verify_alert_recovery` dan `generate_handoff_document`, serta ditampilkan oleh `api.gaps()` di frontend.

**Hasil aktual:**  
`api.gaps()` selalu mengembalikan `[]` pada mode `live`.

**Bukti:**  
Potongan kode [`dashboard/src/data/api.ts#L634-L646`](file:///d:/Projects/School/aegis/dashboard/src/data/api.ts#L634-L646):
```ts
  gaps: async (opts: { hostId?: string; openOnly?: boolean } = {}): Promise<TelemetryGap[]> => {
    if (previewState === 'loading') return new Promise(() => {});
    if (previewState === 'error') throw new ApiError('Simulated error state');
    if (previewState === 'empty') return [];
    if (previewState === 'sample') {
      return structuredClone(
        db.gaps
          .filter((g) => (!opts.hostId || g.hostId === opts.hostId) && (!opts.openOnly || g.end === null))
          .sort(byTimeDesc((g) => g.start)),
      );
    }
    return [];
  },
```

**Dampak:**  
Mengurangi transparansi visibilitas (*Epistemic Honesty*) pada mode `live` karena celah waktu ketika agen terlambat melapor (`delayed`) tidak muncul sebagai item `TelemetryGap` di UI.

**Rekomendasi perbaikan:**  
Tambahkan endpoint `GET /api/gaps` di `aegis_backend/routers/operations.py` yang menghitung gap aktif/historis dari status host & tabel `telemetry_gaps`, hubungkan ke `verify_alert_recovery` serta `generate_handoff_document`, dan panggil `requestBackend('/api/gaps')` di `api.gaps()`.

**Pengujian ulang:**  
Simulasikan host dengan `last_data_at` 20 menit yang lalu, panggil `GET /api/gaps`, dan pastikan gap muncul di `Overview` serta `HostDetail`.

---

### [BUG-003] Daemon `AegisTelemetryCollector` Hanya Membaca `journalctl` dan Belum Membaca File Log Non-Journal (`/var/log/nginx/access.log` & `/var/log/audit/audit.log`)
- **ID:** BUG-003
- **Nama masalah:** Kolektor agen di `aegis_agent/collector.py` hanya menjalankan perintah `journalctl` sehingga log akses Nginx standar (`/var/log/nginx/access.log`) tidak ikut terkirim secara otomatis.
- **Kategori:** Collector
- **Tingkat keparahan:** **HIGH**
- **Lokasi:** [`aegis_agent/collector.py`](file:///d:/Projects/School/aegis/aegis_agent/collector.py#L123-L168) (baris 123–168)
- **Fitur terdampak:** Pengumpulan log otomatis untuk `RULE-WEB-ATTACK` (Nginx/Apache access log) dan `/var/log/audit/audit.log` pada server Ubuntu standar.
- **Status:** Terbukti

**Deskripsi masalah:**  
Meskipun `LinuxTelemetryParser` dan `RulesEngine` telah memiliki parser dan aturan lengkap untuk log akses web (`_parse_web_log` -> `RULE-WEB-ATTACK`) dan log auditd (`_parse_auditd_log`), metode `read_new_journal_lines()` di `collector.py` hanya mengeksekusi `journalctl --no-pager --show-cursor -n 200`. Pada instalasi default Ubuntu Server 24.04 LTS, Nginx menulis log akses ke file `/var/log/nginx/access.log` dan tidak meneruskannya ke `systemd-journald`.

**Langkah reproduksi:**
1. Jalankan `aegis_agent/collector.py` pada server Ubuntu dengan Nginx standar.
2. Lakukan request `curl "http://localhost/../../etc/passwd"` ke Nginx.
3. Log tercatat di `/var/log/nginx/access.log`, namun tidak masuk ke `journalctl`, sehingga tidak terkirim oleh `collector.py`.

**Hasil yang diharapkan:**  
`collector.py` selain membaca `journalctl` juga membaca baris baru (*incremental file byte-offset tailing*) dari `/var/log/nginx/access.log`, `/var/log/apache2/access.log`, dan `/var/log/audit/audit.log` jika file tersebut ada dan dapat dibaca.

**Hasil aktual:**  
Hanya event yang masuk ke `systemd-journald` (SSH, PAM, Sudo, UFW Kernel, Cron, Systemd) yang otomatis terkumpul oleh `collector.py`.

**Bukti:**  
[`aegis_agent/collector.py#L128-L132`](file:///d:/Projects/School/aegis/aegis_agent/collector.py#L128-L132):
```python
cmd = ["journalctl", "--no-pager", "--show-cursor", "-n", "200"]
if cursor:
    cmd.extend(["--after-cursor", cursor])
```

**Dampak:**  
Pada saat uji coba di *mini server* nanti, serangan ke web server Nginx tidak akan terdeteksi otomatis kecuali `collector.py` juga memantau `/var/log/nginx/access.log`.

**Rekomendasi perbaikan:**  
Tambahkan pembacaan *incremental file offset* (`.collector_file_offsets.json`) di `AegisTelemetryCollector` untuk `/var/log/nginx/access.log`, `/var/log/apache2/access.log`, dan `/var/log/audit/audit.log` dengan tetap menerapkan komitmen dua fase (*two-phase commit*).

**Pengujian ulang:**  
Tambahkan baris serangan SQLi/LFI ke file sementara `access.log`, jalankan satu siklus kolektor, dan pastikan baris tersebut terkirim ke `/api/telemetry/ingest` serta memicu `RULE-WEB-ATTACK`.

---

### [BUG-004] Potensi Crash (`TypeError`) pada `InvestigationWorkflowCard` & `DetectionsScreen` Jika Status Investigasi Backend Berubah Menjadi `reopened` / `unverified`
- **ID:** BUG-004
- **Nama masalah:** Ketidaksinkronan enum `InvestigationStatus` antara Backend (10 status) dan Frontend `investigationStatusMeta` (hanya 4 status) menyebabkan `undefined` saat merender `<Badge>`.
- **Kategori:** Frontend / Integrasi
- **Tingkat keparahan:** **HIGH**
- **Lokasi:**
  - [`dashboard/src/lib/status.ts`](file:///d:/Projects/School/aegis/dashboard/src/lib/status.ts#L53-L58)
  - [`dashboard/src/components/domain.tsx`](file:///d:/Projects/School/aegis/dashboard/src/components/domain.tsx#L411-L454)
  - [`aegis_backend/incident_service.py`](file:///d:/Projects/School/aegis/aegis_backend/incident_service.py#L1072-L1077)
- **Fitur terdampak:** Halaman `AlertDetail` dan `Detections` setelah fitur `Verify Recovery` dijalankan.
- **Status:** Terbukti

**Deskripsi masalah:**  
Di backend [`aegis_backend/incident_service.py#L1072-L1077`](file:///d:/Projects/School/aegis/aegis_backend/incident_service.py#L1072-L1077), ketika fungsi `verify_alert_recovery()` menemukan bahwa serangan masih berlangsung setelah insiden sempat ditandai selesai, backend mengubah status investigasi menjadi `'reopened'`. Selain itu, schema backend [`aegis_backend/schemas.py#L250-L253`](file:///d:/Projects/School/aegis/aegis_backend/schemas.py#L250-L253) mengizinkan status: `new`, `detected`, `investigating`, `handoff_ready`, `remediation_in_progress`, `verification`, `resolved`, `reopened`, `unverified`, `false_positive`.  
Namun di frontend [`dashboard/src/lib/status.ts`](file:///d:/Projects/School/aegis/dashboard/src/lib/status.ts), objek `investigationStatusMeta` hanya memiliki 4 kunci (`new`, `investigating`, `resolved`, `false_positive`). Ketika `status` bernilai `'reopened'`, maka `currentMeta = investigationStatusMeta[status]` bernilai `undefined`, dan pemanggilan `<Badge meta={currentMeta} />` di `InvestigationWorkflowCard` (`domain.tsx` baris 434) akan melempar `TypeError: Cannot read properties of undefined (reading 'tone')` yang meruntuhkan seluruh halaman `AlertDetail`!

**Langkah reproduksi:**
1. Ubah status investigasi suatu alert menjadi `resolved` (atau `reopened` melalui `POST /api/alerts/{id}/investigation`).
2. Buka halaman `/alerts/{id}` di browser.
3. Komponen `<Badge meta={currentMeta} />` mencoba membaca `meta.tone` dari `undefined`.

**Hasil yang diharapkan:**  
`investigationStatusMeta` di frontend mencakup seluruh status yang didukung oleh backend, dan `<Badge>` memiliki *fallback* aman jika menerima status baru.

**Hasil aktual:**  
Crash komponen React (`TypeError`) apabila status di luar ke-4 nilai dasar dikembalikan oleh API.

**Bukti:**  
Di `aegis_backend/schemas.py` baris 252:
```python
pattern="^(new|detected|investigating|handoff_ready|remediation_in_progress|verification|resolved|reopened|unverified|false_positive)$"
```
Sedangkan di `dashboard/src/components/domain.tsx` baris 411 & 434:
```tsx
const currentMeta = investigationStatusMeta[status];
...
<Badge meta={currentMeta} />
```

**Dampak:**  
Halaman investigasi insiden (`AlertDetail`) dapat mengalami *blank screen* setelah verifikasi pemulihan otomatis mengubah status menjadi `reopened`.

**Rekomendasi perbaikan:**  
Lengkapi `InvestigationStatus` di `dashboard/src/data/types.ts` dan `investigationStatusMeta` di `dashboard/src/lib/status.ts` untuk seluruh 10 nilai status backend, serta tambahkan opsi yang relevan pada dropdown `InvestigationWorkflowCard`.

**Pengujian ulang:**  
Kirim `POST /api/alerts/ALT-001/investigation` dengan `{"status": "reopened"}`, lalu muat halaman `AlertDetail` dan pastikan badge `Reopened` tampil tanpa error.

---

### [BUG-005] Filter `GET /api/hosts?agent_status=...` Memfilter Nilai Kolom Statis Sebelum Menghitung `derive_agent_status()` Dinamis
- **ID:** BUG-005
- **Nama masalah:** Inkonsistensi logika filter status host di backend antara nilai statis database dan nilai dinamis `derive_agent_status()`.
- **Kategori:** Backend / Database
- **Tingkat keparahan:** **MEDIUM**
- **Lokasi:** [`aegis_backend/routers/hosts.py`](file:///d:/Projects/School/aegis/aegis_backend/routers/hosts.py#L46-L69) (baris 46–69)
- **Fitur terdampak:** Filter status host pada API `GET /api/hosts?agent_status=offline` / `delayed` / `online`.
- **Status:** Terbukti

**Deskripsi masalah:**  
Ketika agen mengirim *heartbeat* atau log, baris host di database disimpan dengan `agent_status = "online"`. Jika agen kemudian mati selama 2 jam, nilai di kolom database tetap `"online"`, tetapi fungsi `derive_agent_status(last_data_at)` di `routers/hosts.py` secara cerdas menghitung ulang statusnya menjadi `"offline"` (karena `diff_sec > 1800`).  
Masalahnya, pada `list_hosts()` baris 58:
```python
data, total = repo.list_hosts(limit=limit, offset=offset, status=agent_status)
```
Parameter `agent_status` difilter terlebih dahulu di query database (`WHERE agent_status = 'offline'`) **sebelum** `derive_agent_status()` dijalankan!

**Langkah reproduksi:**
1. Miliki satu host di database dengan `agent_status = "online"` dan `last_data_at` = 3 jam yang lalu.
2. Panggil `GET /api/hosts` (tanpa filter) -> host muncul dengan `agent_status: "offline"`.
3. Panggil `GET /api/hosts?agent_status=offline` -> mengembalikan `items: [], total: 0`!
4. Panggil `GET /api/hosts?agent_status=online` -> mengembalikan host yang berstatus `"offline"`!

**Hasil yang diharapkan:**  
Filter `agent_status` di `GET /api/hosts` dievaluasi berdasarkan status efektif hasil `derive_agent_status()`.

**Hasil aktual:**  
Hasil filter `GET /api/hosts?agent_status=...` bertentangan dengan nilai `agent_status` yang ada di dalam objek responsnya sendiri.

**Bukti:**  
Potongan kode [`aegis_backend/routers/hosts.py#L58-L63`](file:///d:/Projects/School/aegis/aegis_backend/routers/hosts.py#L58-L63):
```python
data, total = repo.list_hosts(limit=limit, offset=offset, status=agent_status)
items = []
for h in data:
    h_dict = dict(h)
    h_dict["agent_status"] = derive_agent_status(h_dict.get("last_data_at"), h_dict.get("agent_status", "online"))
    items.append(HostItem.model_validate(h_dict))
```

**Dampak:**  
Klien API yang memfilter `agent_status` pada backend akan mendapatkan daftar host yang salah ketika ada host yang berubah menjadi `delayed` atau `offline` karena waktu.

**Rekomendasi perbaikan:**  
Ambil daftar host dari `repo.list_hosts()`, hitung `derive_agent_status()` untuk setiap host terlebih dahulu, lalu terapkan filter `agent_status` dan paginasi `offset`/`limit`.

**Pengujian ulang:**  
Tambahkan test di `tests/test_backend_api.py` yang memverifikasi `GET /api/hosts?agent_status=offline` mengembalikan host yang `last_data_at`-nya sudah lewat 30 menit meskipun kolom `agent_status` awal di DB adalah `'online'`.

---

### [BUG-006] Kesalahan Pemetaan Label Sumber Log (`SourceId`) pada Tabel Desktop `Hosts.tsx` dan `api.ts` (`auditd` Ditampilkan Sebagai `Error` / `ssh-auth`)
- **ID:** BUG-006
- **Nama masalah:** Sumber log `auditd`, `systemd`, dan `network-conn` salah dipetakan menjadi label `Error` di `Hosts.tsx` dan selalu dipaksa menjadi `ssh-auth` di `mapBackendAlert` serta `alertEvidence`.
- **Kategori:** Frontend / UI / Integrasi
- **Tingkat keparahan:** **MEDIUM**
- **Lokasi:**
  - [`dashboard/src/screens/Hosts.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/Hosts.tsx#L134) (baris 134)
  - [`dashboard/src/data/api.ts`](file:///d:/Projects/School/aegis/dashboard/src/data/api.ts#L345-L375) (baris 345, 375, dan 617)
- **Fitur terdampak:** Tampilan kolom `Log Sources` di tabel desktop `Hosts`, kolom `Source` di tabel `Detections`, dan label sumber log pada `AlertDetail`.
- **Status:** Terbukti

**Deskripsi masalah:**  
1. Pada [`dashboard/src/screens/Hosts.tsx#L134`](file:///d:/Projects/School/aegis/dashboard/src/screens/Hosts.tsx#L134), kode merender pill sumber log dengan ternary:
   ```tsx
   {s.id === 'ssh-auth' ? 'SSH' : s.id === 'nginx-access' ? 'Access' : 'Error'}
   ```
   Padahal di `mapBackendHost` (`api.ts` baris 192), sumber kedua yang dikonfigurasi adalah `s.id = 'auditd'`. Akibatnya, di tabel desktop `Hosts`, sumber `auditd` yang sedang berstatus hijau (`collecting`) justru bertuliskan **`Error`**!
2. Pada [`dashboard/src/data/api.ts#L617`](file:///d:/Projects/School/aegis/dashboard/src/data/api.ts#L617), fungsi `alertEvidence` memetakan sumber event dengan:
   ```ts
   source: (ev.source_id === 'nginx-access' || ev.source_id === 'nginx-error' ? ev.source_id : 'ssh-auth') as SourceId
   ```
   Sehingga bukti event yang berasal dari `auditd` atau `systemd` selalu ditampilkan seolah-olah berasal dari `ssh-auth`.
3. Pada [`dashboard/src/data/api.ts#L345`](file:///d:/Projects/School/aegis/dashboard/src/data/api.ts#L345) (`mapBackendAlert`), penentuan sumber alert hanya mengecek `a.rule_id?.includes('SUDO') ? 'auditd' : 'ssh-auth'`, sehingga alert `RULE-WEB-ATTACK` (seharusnya `nginx-access`), `RULE-FW-PORTSCAN` / `RULE-KERNEL-EXPLOIT` / `RULE-CRON-PERSIST` / `RULE-DEFENSE-EVASION` (seharusnya `systemd`), dan `RULE-ANTI-FORENSICS` / `RULE-DATA-EXFIL` / `RULE-ROOTKIT-SNIFF` / `RULE-SSH-KEY-BACKDOOR` (seharusnya `auditd`) semuanya dilabeli sebagai `ssh-auth`!

**Langkah reproduksi:**
1. Buka halaman `/hosts` pada layar desktop (`>= 1024px`).
2. Lihat kolom `Log Sources`: pill kedua berwarna hijau memiliki tooltip `auditd: Collecting`, tetapi teks di dalam pill tertulis **`Error`**.
3. Buka detail alert `RULE-WEB-ATTACK` atau `RULE-ANTI-FORENSICS` di mode `Live`: bagian `Log Source` menampilkan `SSH auth log (ssh-auth)`.

**Hasil yang diharapkan:**  
Setiap `SourceId` (`ssh-auth`, `auditd`, `systemd`, `nginx-access`, `nginx-error`, `network-conn`) dipetakan secara akurat sesuai sumber aslinya.

**Hasil aktual:**  
`auditd` tertulis `Error` di halaman `Hosts`, dan seluruh alert non-SUDO tertulis `ssh-auth`.

**Dampak:**  
Membingungkan analis SOC/juri saat membaca sumber telemetri pada tabel `Hosts`, `Detections`, dan `AlertDetail`.

**Rekomendasi perbaikan:**  
Perbaiki ternary di `Hosts.tsx` agar memetakan `'auditd' -> 'Auditd'`, `'systemd' -> 'Systemd'`, serta perbaiki fungsi pemetaan sumber di `mapBackendAlert` dan `alertEvidence` di `dashboard/src/data/api.ts`.

**Pengujian ulang:**  
Verifikasi tampilan pill di `/hosts` menampilkan `SSH`, `Auditd`, `Access`, dan verifikasi `Log Source` pada alert `RULE-WEB-ATTACK` menampilkan `nginx-access`.

---

### [BUG-007] Filter Rentang Waktu (`6 h`, `24 h`, `7 days`) pada Halaman `Timeline` Diabaikan di Mode Live & Hanya Menampilkan Event dari 6 Alert Teratas
- **ID:** BUG-007
- **Nama masalah:** Fungsi `api.timeline(opts)` di mode `live` mengabaikan parameter `opts.sinceHours` dan memotong pengambilan bukti hanya pada 6 alert pertama.
- **Kategori:** Frontend / Backend
- **Tingkat keparahan:** **MEDIUM**
- **Lokasi:** [`dashboard/src/data/api.ts`](file:///d:/Projects/School/aegis/dashboard/src/data/api.ts#L667-L683) (baris 667–683)
- **Fitur terdampak:** Halaman `Timeline` (`/timeline`) pada mode `live`.
- **Status:** Terbukti

**Deskripsi masalah:**  
Di halaman `TimelineScreen`, terdapat komponen filter `<Chips>` dengan pilihan `6 h` (`sinceHours: 6`), `24 h` (`sinceHours: 24`), dan `7 days` (`sinceHours: 168`). Namun pada implementasi `api.timeline` untuk mode `live` (`dashboard/src/data/api.ts` baris 667–683):
1. Parameter `opts.sinceHours` sama sekali tidak dibaca atau digunakan untuk memfilter timestamp `items`!
2. Kode hanya mengambil *supporting events* dari 6 alert pertama (`const topAlerts = alerts.slice(0, 6)`), sehingga jika ada lebih dari 6 alert atau ada event telemetri baru yang belum memicu alert, event tersebut tidak muncul di Timeline.

**Langkah reproduksi:**
1. Buka halaman `/timeline` pada mode `Live`.
2. Klik bergantian tombol filter `6 h`, `24 h`, dan `7 days`.
3. Daftar event dan jumlah counter di atas timeline tidak berubah sama sekali meskipun terdapat alert yang berusia lebih dari 6 jam atau 24 jam.

**Hasil yang diharapkan:**  
Mengklik chip `6 h`, `24 h`, atau `7 days` memfilter seluruh item timeline (`event`, `alert`, `gap`) agar hanya menampilkan kejadian dalam rentang `Date.now() - sinceHours * 3600_000`.

**Hasil aktual:**  
Filter rentang waktu di mode `live` tidak berpengaruh.

**Bukti:**  
Potongan kode [`dashboard/src/data/api.ts#L667-L683`](file:///d:/Projects/School/aegis/dashboard/src/data/api.ts#L667-L683):
```ts
    // Live mode: build unified chronological timeline from live alerts and their supporting evidence
    const alerts = await api.alerts(opts.hostId);
    const items: TimelineItem[] = alerts.map((a) => ({ kind: 'alert' as const, ts: a.detectedAt, alert: a }));
    const topAlerts = alerts.slice(0, 6);
```
Tidak ada pengecekan `opts.sinceHours` pada blok kode tersebut.

**Dampak:**  
Fitur filter waktu di halaman `Timeline` tidak berfungsi saat terhubung ke backend nyata.

**Rekomendasi perbaikan:**  
Terapkan filter `since = Date.now() - (opts.sinceHours ?? 24) * 3600_000` pada mode `live` di `api.timeline()`, sertakan data dari `api.gaps()`, dan sediakan endpoint `GET /api/timeline` di backend yang mengembalikan event telemetri terbaru beserta alert dan gap.

**Pengujian ulang:**  
Uji klik chip `6 h`, `24 h`, dan `7 days` pada mode `Live` dan pastikan hanya item dalam jendela waktu tersebut yang ditampilkan.

---

### [BUG-008] Halaman Mandiri `Audit Log` (`/audit`) Belum Memiliki Rute di `App.tsx`
- **ID:** BUG-008
- **Nama masalah:** Komponen `AuditLogList` hanya disematkan di dalam halaman `Evidence Mode`, sedangkan halaman/rute `/audit` belum terdaftar di `App.tsx`.
- **Kategori:** Frontend / Navigasi
- **Tingkat keparahan:** **MEDIUM**
- **Lokasi:** [`dashboard/src/App.tsx`](file:///d:/Projects/School/aegis/dashboard/src/App.tsx#L23-L38)
- **Fitur terdampak:** Navigasi langsung ke halaman Audit Log (`/audit`).
- **Status:** Terbukti

**Deskripsi masalah:**  
Endpoint backend `GET /api/audit-logs` dan fungsi `api.auditLogs()` sudah tersedia dan bekerja, tetapi di frontend `dashboard/src/screens/AuditLog.tsx` belum dibuat dan `<Route path="audit" ... />` belum didaftarkan di `App.tsx`. Saat ini daftar Audit Log hanya dapat dilihat dengan masuk ke menu `Evidence Mode` (`/evidence`) di kolom sebelah kanan.

**Langkah reproduksi:**
1. Akses URL `/audit` pada browser.
2. Router React menangkapnya dengan `<Route path="*" element={<Navigate to="/" replace />} />` dan mengalihkan ke `/`.

**Hasil yang diharapkan:**  
Tersedia layar khusus `AuditLogScreen` pada rute `/audit` (dengan filter jenis aksi operator dan pencarian aktor/target) yang juga dapat diakses dari navigasi/Settings, selain ringkasan yang ada di `Evidence Mode`.

**Hasil aktual:**  
File `dashboard/src/screens/AuditLog.tsx` belum ada.

**Bukti:**  
Daftar rute di [`dashboard/src/App.tsx#L24-L37`](file:///d:/Projects/School/aegis/dashboard/src/App.tsx#L24-L37) hanya memuat 11 rute (`Overview`, `Hosts`, `HostDetail`, `Detections`, `AlertDetail`, `FindingDetail`, `Timeline`, `Evidence`, `Reports`, `ReportDetail`, `Settings`).

**Dampak:**  
Operator tidak memiliki halaman khusus untuk memfilter dan menelusuri *Audit Trail* secara menyeluruh.

**Rekomendasi perbaikan:**  
Buat `dashboard/src/screens/AuditLog.tsx` lengkap dengan filter kategori aksi dan pencarian, lalu daftarkan `<Route path="audit" element={<AuditLogScreen />} />` di `App.tsx`.

**Pengujian ulang:**  
Buka `/audit`, uji filter berdasarkan aksi (`run_sc_scan`, `generate_handoff`, `request_report`), dan pastikan seluruh log tampil.

---

### [BUG-009] Pembuatan Laporan (`POST /api/reports`) Belum Memfilter Alert Berdasarkan `period_start` & `period_end`
- **ID:** BUG-009
- **Nama masalah:** Endpoint `create_report` memasukkan seluruh alert milik host tanpa memfilter apakah `detected_at` berada di dalam rentang `period_start` s/d `period_end`, dan tampilan `ReportDetailScreen` juga menampilkan semua alert host tanpa filter periode.
- **Kategori:** Backend / Frontend
- **Tingkat keparahan:** **MEDIUM**
- **Lokasi:**
  - [`aegis_backend/routers/operations.py`](file:///d:/Projects/School/aegis/aegis_backend/routers/operations.py#L349-L388) (baris 349–388)
  - [`dashboard/src/screens/ReportDetail.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/ReportDetail.tsx#L35-L40) (baris 35–40)
- **Fitur terdampak:** Akurasi jumlah alert (`alert_count`) dan cakupan waktu pada pembuatan laporan (`Reports` & `ReportDetail`).
- **Status:** Terbukti

**Deskripsi masalah:**  
Di `aegis_backend/routers/operations.py` baris 355–356:
```python
alerts, alert_total = repo.list_alerts(limit=100, offset=0)
host_alerts = [a for a in alerts if a.get("host_id") in req.host_ids]
```
Bahkan lebih jauh lagi, jika `host_alerts` kosong (tidak ada alert untuk host yang dipilih), baris 365 & 383 menulis:
```python
alerts=host_alerts if host_alerts else alerts,
...
alert_count=len(host_alerts) if host_alerts else alert_total,
```
Artinya:
1. Jika sebuah host **bersih (0 alert)** dan operator meminta laporan khusus untuk host tersebut, `host_alerts` bernilai `[]` (falsy), sehingga ekspresi `len(host_alerts) if host_alerts else alert_total` justru mengambil **`alert_total` milik host lain**!
2. Rentang waktu `req.period_start` dan `req.period_end` tidak digunakan untuk memfilter `detected_at` pada `host_alerts`.

**Langkah reproduksi:**
1. Miliki Host A dengan 3 alert dan Host B dengan 0 alert.
2. Buat laporan (`POST /api/reports`) khusus untuk `host_ids: ["host-B"]`.
3. Karena `host_alerts` kosong (`[]`), ekspresi `if host_alerts else alert_total` bernilai `False` dan memasukkan 3 alert milik Host A ke dalam laporan Host B!

**Hasil yang diharapkan:**  
Laporan untuk Host B yang memiliki 0 alert harus mencatat `alert_count = 0` dan `alerts = []`, serta hanya menghitung alert yang terjadi di antara `period_start` dan `period_end`.

**Hasil aktual:**  
Jika `host_alerts` kosong, laporan justru mengambil seluruh alert dari host lain (`else alerts`).

**Bukti:**  
Potongan kode [`aegis_backend/routers/operations.py#L365-L385`](file:///d:/Projects/School/aegis/aegis_backend/routers/operations.py#L365-L385):
```python
alerts=host_alerts if host_alerts else alerts,
...
alert_count=len(host_alerts) if host_alerts else alert_total,
```

**Dampak:**  
Kontaminasi data lintas-host pada laporan apabila host yang dipilih memiliki 0 alert.

**Rekomendasi perbaikan:**  
Gunakan `host_alerts` secara langsung tanpa fallback `else alerts`, dan filter `a.get("detected_at")` agar berada dalam rentang `period_start <= detected_at <= period_end`.

**Pengujian ulang:**  
Buat unit test di `tests/test_backend_api.py` yang meminta laporan untuk host tanpa alert dan pastikan `alert_count == 0`.

---

### [BUG-010] Penyimpanan State Operasional (`OperationalStateStore`) Masih Berbasis Memori RAM (Non-Persisten Saat Restart Layanan)
- **ID:** BUG-010
- **Nama masalah:** Catatan investigasi operator, sesi *Evidence Mode*, hasil scan postur live, laporan, dan audit log disimpan di memori `OperationalStateStore` dan hilang ketika proses FastAPI di-restart.
- **Kategori:** Backend / Database
- **Tingkat keparahan:** **MEDIUM**
- **Lokasi:** [`aegis_backend/incident_service.py`](file:///d:/Projects/School/aegis/aegis_backend/incident_service.py#L396-L421)
- **Fitur terdampak:** Persistensi jangka panjang untuk catatan investigasi, laporan, sesi *Evidence Mode*, dan *Operator Audit Log*.
- **Status:** Terbukti

**Deskripsi masalah:**  
Objek `op_store = OperationalStateStore()` menyimpan state operasional di dalam struktur dictionary/list Python di memori RAM. Meskipun host, event telemetri, alert, dan bukti alert telah disimpan secara permanen di PostgreSQL (`SupabaseRepository`), state di `op_store` belum disinkronkan ke disk atau tabel database.

**Langkah reproduksi:**
1. Tambahkan catatan investigasi pada sebuah alert atau buat laporan baru.
2. Restart proses Uvicorn `aegis-backend`.
3. Periksa kembali catatan investigasi atau daftar laporan: data kembali ke kondisi awal.

**Hasil yang diharapkan:**  
State operasional di `op_store` memiliki *persistence backing* (misal file JSON atomik lokal / SQLite / tabel Supabase) sehingga tahan terhadap *restart* `systemctl restart aegis-backend`.

**Hasil aktual:**  
Data di `op_store` hilang saat proses Python berhenti.

**Dampak:**  
Jika server direboot saat pengujian lapangan, riwayat laporan dan catatan investigasi yang baru dibuat sebelum reboot akan hilang.

**Rekomendasi perbaikan:**  
Tambahkan mekanisme *auto-persist* ke file state JSON lokal (atau tabel Supabase) setiap kali `op_store` diperbarui, dan muat kembali saat inisialisasi `OperationalStateStore`.

**Pengujian ulang:**  
Simpan catatan investigasi, inisialisasi ulang `OperationalStateStore`, dan pastikan catatan investigasi tetap ada.

---

### [BUG-011] Variabel CSS `--bg-elevated`, `--border-subtle`, dan `--text-muted` Tidak Terdefinisi pada Komponen di `domain.tsx`
- **ID:** BUG-011
- **Nama masalah:** Penggunaan nama variabel CSS yang tidak ada di `tokens.css` menyebabkan kotak kode, kartu *Kill-Chain*, *Incident Replay*, dan *Recovery Verification* kehilangan warna latar dan garis tepi.
- **Kategori:** UI / Frontend
- **Tingkat keparahan:** **LOW**
- **Lokasi:** [`dashboard/src/components/domain.tsx`](file:///d:/Projects/School/aegis/dashboard/src/components/domain.tsx#L663-L1046) (baris 663, 664, 694, 781, 782, 819, 820, 893, 949, 954, 972, 1044, 1045)
- **Fitur terdampak:** Visualisasi `HandoffCard`, `RecoveryVerificationCard`, `IncidentReplayCard`, `KillChainCard`, dan `BlastRadiusCard` di halaman `AlertDetail`.
- **Status:** Terbukti

**Deskripsi masalah:**  
Di `dashboard/src/styles/tokens.css`, sistem desain AEGIS menggunakan nama variabel:
- `--color-surface-sunken` / `--color-surface-raised`
- `--color-border` / `--color-border-strong`
- `--color-text-tertiary` / `--color-text-secondary`

Namun pada inline style di `dashboard/src/components/domain.tsx`, kode memanggil `var(--bg-elevated)`, `var(--border-subtle)`, dan `var(--text-muted)` yang tidak pernah didefinisikan di file CSS mana pun!

**Langkah reproduksi:**
1. Buka halaman `/alerts/:id` di browser dan klik `Inspect Element` pada kartu `Multi-Stage Kill-Chain Correlation` atau `Incident Replay`.
2. Periksa properti CSS `background: var(--bg-elevated)` dan `border: 1px solid var(--border-subtle)` di DevTools: keduanya bernilai *unset/invalid* karena variabel tersebut tidak ada.

**Hasil yang diharapkan:**  
Seluruh komponen menggunakan token resmi dari `tokens.css` (`var(--color-surface-sunken)`, `var(--color-border)`, `var(--color-text-tertiary)`).

**Hasil aktual:**  
Latar belakang sub-kartu menjadi transparan dan border untuk tahap `not_observed` pada *Kill-Chain* tidak muncul.

**Bukti:**  
[`dashboard/src/components/domain.tsx#L949-L954`](file:///d:/Projects/School/aegis/dashboard/src/components/domain.tsx#L949-L954):
```tsx
background: 'var(--bg-elevated)',
border: isCurrent
  ? '1px solid var(--status-critical-fg)'
  : isObserved
    ? '1px solid var(--status-warning-fg)'
    : '1px solid var(--border-subtle)',
```

**Dampak:**  
Kontras visual sub-kartu pada halaman `AlertDetail` berkurang drastis terutama pada tema terang (*Light Mode*).

**Rekomendasi perbaikan:**  
Ganti seluruh referensi `--bg-elevated` menjadi `--color-surface-sunken`, `--border-subtle` menjadi `--color-border`, dan `--text-muted` menjadi `--color-text-tertiary` (atau definisikan aliasnya di `tokens.css`).

**Pengujian ulang:**  
Periksa tampilan `AlertDetail` pada mode Terang dan Gelap untuk memastikan setiap kotak tahap *Kill-Chain* dan blok kode memiliki latar dan garis tepi yang tegas.

---

### [BUG-012] Tombol `Retry generation` pada `ReportDetailScreen` Tidak Bekerja pada Mode `Live`
- **ID:** BUG-012
- **Nama masalah:** Fungsi `actions.retryReport(id)` di `api.ts` hanya memodifikasi array statis `db.reports` milik mode `sample` dan tidak memanggil API backend pada mode `live`.
- **Kategori:** Frontend / Integrasi
- **Tingkat keparahan:** **LOW**
- **Lokasi:** [`dashboard/src/data/api.ts`](file:///d:/Projects/School/aegis/dashboard/src/data/api.ts#L1710-L1731)
- **Fitur terdampak:** Tombol `Retry generation` pada halaman `ReportDetail` (`/reports/:id`).
- **Status:** Terbukti

**Deskripsi masalah:**  
Jika pembuatan laporan gagal dan pengguna menekan tombol `Retry generation` di halaman `ReportDetailScreen` pada mode `Live`, fungsi `actions.retryReport(id)` mencari `db.reports.find((x) => x.id === id)` yang hanya berisi laporan mock. Untuk laporan yang berasal dari backend (`r-0001`, dst.), `r` bernilai `undefined` sehingga fungsi langsung keluar (`if (!r) return;`) tanpa melakukan apa-apa.

**Langkah reproduksi:**
1. Dalam mode `Live`, panggil `actions.retryReport('r-0001')`.
2. Fungsi langsung berhenti di baris `if (!r) return;` karena `'r-0001'` tidak ada di `db.reports`.

**Hasil yang diharapkan:**  
Pada mode `live`, `retryReport` memanggil ulang endpoint pembuatan laporan di backend.

**Hasil aktual:**  
Tombol tidak melakukan aksi apa pun terhadap laporan backend.

**Rekomendasi perbaikan:**  
Tambahkan pemanggilan ke backend pada `actions.retryReport()` ketika `previewState !== 'sample'`.

**Pengujian ulang:**  
Klik tombol `Retry generation` dan pastikan request `POST` terkirim ke backend.

---

### [BUG-013] Label dan Teks Informasi pada `SettingsScreen` & `HostDetailScreen` Masih Mencantumkan Spesifikasi Lama
- **ID:** BUG-013
- **Nama masalah:** Inkonsistensi teks informasi pada halaman `Settings` dan `HostDetail` yang masih menulis *"collected SSH and Nginx logs"* serta *"8-Module"* di beberapa deskripsi statis.
- **Kategori:** UI / Dokumentasi Antarmuka
- **Tingkat keparahan:** **LOW**
- **Lokasi:**
  - [`dashboard/src/screens/Settings.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/Settings.tsx#L225) (baris 225)
  - [`dashboard/src/screens/HostDetail.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/HostDetail.tsx#L151) (baris 151)
- **Fitur terdampak:** Akurasi informasi pada halaman `Settings` dan *empty state* `HostDetail`.
- **Status:** Terbukti

**Deskripsi masalah:**  
- Di `Settings.tsx` baris 225, baris `Initial Sources` masih tertulis: `'SSH auth log (/var/log/auth.log), Nginx access/error logs'`, padahal sistem kini memantau 8 sumber log (SSH/PAM, Sudo, Auditd, UFW Firewall, Kernel dmesg, Cron, Systemd, Nginx/Apache) dan 12 kontrol CIS + DISA STIG.
- Di `HostDetail.tsx` baris 151, pesan *empty state* masih tertulis: `'No active rule has matched on the collected SSH and Nginx logs.'`

**Rekomendasi perbaikan:**  
Perbarui teks deskripsi di `Settings.tsx` dan `HostDetail.tsx` agar mencerminkan cakupan 8 sumber telemetri, 13 rule RM, dan 12 kontrol CIS + DISA STIG.

**Pengujian ulang:**  
Buka halaman `/settings` dan pastikan daftar sumber log dan kapabilitas sesuai dengan implementasi terbaru.

---

### [BUG-014] Pencarian Threat Hunting pada `DetectionsScreen` Belum Mencari berdasarkan MITRE ATT&CK ID
- **ID:** BUG-014
- **Nama masalah:** Placeholder kotak pencarian di `DetectionsScreen` menyebutkan *"filter by IP, user, rule ID, CIS/STIG check ID, MITRE ID, or command…"*, tetapi ekspresi filter belum memeriksa `a.ruleLogic?.mitreAttackId`.
- **Kategori:** Frontend / UI
- **Tingkat keparahan:** **LOW**
- **Lokasi:** [`dashboard/src/screens/Detections.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/Detections.tsx#L120-L125) (baris 120–125)
- **Fitur terdampak:** Pencarian *Threat Hunting* menggunakan kode MITRE (misal mengetik `T1070`, `T1041`, `T1110`) pada tab `RM alerts` di halaman `Detections`.
- **Status:** Terbukti

**Deskripsi masalah:**  
Pada objek `Alert`, informasi MITRE ATT&CK disimpan di properti `a.ruleLogic?.mitreAttackId` dan `a.ruleLogic?.mitreAttackName` (sebagaimana didefinisikan di `dashboard/src/data/types.ts` dan diisi oleh `mapBackendAlert` di `api.ts` baris 365–373). Namun filter di `Detections.tsx` baris 120–125 hanya memeriksa `a.title`, `a.ruleId`, `a.reason`, dan `a.id`. Untuk aturan yang judulnya tidak memuat teks `MITRE Txxxx` (seperti `RULE-SSH-BRUTE` dengan MITRE `T1110.001`), mengetik `T1110` di kotak pencarian tidak menampilkan hasil.

**Langkah reproduksi:**
1. Buka halaman `/detections`.
2. Ketik `T1110` atau `T1548` pada kotak *Threat Hunt*.
3. Alert `RULE-SSH-BRUTE` (`T1110.001`) dan `RULE-SUSP-SUDO` (`T1548.003`) tidak muncul karena string `T1110` berada di `a.ruleLogic.mitreAttackId`, bukan di `a.title`.

**Rekomendasi perbaikan:**  
Tambahkan `(a.ruleLogic?.mitreAttackId || '').toLowerCase().includes(qLower)` dan `(a.ruleLogic?.mitreAttackName || '').toLowerCase().includes(qLower)` pada filter di `Detections.tsx`.

**Pengujian ulang:**  
Ketik `T1110.001` atau `T1548.003` di kotak pencarian `/detections` dan pastikan alert yang sesuai tampil.

---

### [BUG-015] Konfigurasi Default CORS `allow_origins=["*"]` Bersamaan dengan `allow_credentials=True` & Endpoint Operator Tanpa Token Sesi
- **ID:** BUG-015
- **Nama masalah:** Endpoint operator belum memvalidasi header autentikasi operator dan CORS default mengizinkan `*`.
- **Kategori:** Security / Backend
- **Tingkat keparahan:** **INFO** (Mitigasi arsitektural saat ini menggunakan Cloudflare Zero-Trust Access Tunnel & binding loopback `127.0.0.1:8000`)
- **Lokasi:** [`aegis_backend/main.py`](file:///d:/Projects/School/aegis/aegis_backend/main.py#L31-L38) dan [`aegis_backend/config.py`](file:///d:/Projects/School/aegis/aegis_backend/config.py#L36)
- **Fitur terdampak:** Keamanan akses API apabila di-deploy tanpa reverse proxy berautentikasi (Cloudflare Access).
- **Status:** Terbukti

**Deskripsi masalah:**  
Endpoint ingesti agen (`/api/telemetry/*`) telah dilindungi dengan token `X-Agent-Token` (`hmac.compare_digest`). Namun endpoint pembacaan dan aksi operator (`/api/alerts/*`, `/api/reports`, `/api/evidence`) tidak memerlukan header token di level FastAPI karena mengandalkan perlindungan di layer *Zero-Trust Tunnel* (`cloudflared`) dan binding lokal `127.0.0.1`. Selain itu, di `config.py`, `aegis_cors_origins` secara default bernilai `"*"`.

**Rekomendasi perbaikan:**  
Batasi default `AEGIS_CORS_ORIGINS` ke origin lokal/domain produksi (`http://localhost:5173,https://sshvm.diazz.web.id`) dan sediakan opsi autentikasi header opsional untuk operator jika dibutuhkan di luar Cloudflare Access.

---

### [BUG-016] Belum Ada Pembatasan Laju (*Rate Limiting*) pada Endpoint Analisis AI & Pembuatan PDF
- **ID:** BUG-016
- **Nama masalah:** Endpoint `POST /api/alerts/{id}/analyze`, `POST /api/findings/{id}/analyze`, dan `POST /api/reports` dapat dipanggil berulang kali secara cepat.
- **Kategori:** Security / Backend
- **Tingkat keparahan:** **INFO**
- **Lokasi:** [`aegis_backend/routers/alerts.py`](file:///d:/Projects/School/aegis/aegis_backend/routers/alerts.py#L145) dan [`aegis_backend/routers/operations.py`](file:///d:/Projects/School/aegis/aegis_backend/routers/operations.py#L238)
- **Fitur terdampak:** Perlindungan kuota Gemini API (`AEGIS1`, `AEGIS2`, `AEGIS3`) terhadap spam request.
- **Status:** Terbukti

**Deskripsi masalah:**  
Di sisi UI, tombol sudah di-*disable* saat `pending` (`disabled={submitting}`), namun jika seseorang memanggil endpoint `POST /api/alerts/{id}/analyze` secara langsung menggunakan skrip/curl berulang kali, backend akan selalu memanggil LLM Gemini tanpa jeda *cooldown* atau *caching TTL*.

**Rekomendasi perbaikan:**  
Tambahkan pengecekan *cooldown* singkat (misal 10 detik per `target_id` kecuali parameter `force=true` diberikan) di `incident_service.py`.

---

## 5. INVENTARIS KELENGKAPAN SELURUH FITUR, SUBFITUR, TOMBOL, FILTER & KOMPONEN (6 STATUS WAJIB)

### A. Halaman 1 — `OverviewScreen` (`/`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| OV-01 | Agent Status Fleet Strip (4 kartu: Online, Delayed, Offline, Unknown) + navigasi klik ke `/hosts?status=...` | **BERFUNGSI** | Terverifikasi di `Overview.tsx` baris 68–98 |
| OV-02 | Kartu **Status Kesiapan Siber (`SIAGA I / II / III`)** + rincian 8 CIS & 4 DISA STIG + skor kepatuhan | **BERFUNGSI** | Terverifikasi di `Overview.tsx` baris 100–162 |
| OV-03 | Banner aktif `Emergency Evidence Mode` dengan *liquid progress bar* & hitung mundur detik | **BERFUNGSI** | Terverifikasi di `Overview.tsx` baris 164 & `domain.tsx` baris 215 |
| OV-04 | Notice peringatan ketika `aiProvider !== 'ok'` | **BERFUNGSI** | Terverifikasi di `Overview.tsx` baris 168–173 |
| OV-05 | Seksi `RM alerts · last 24 h` (menampilkan 4 alert terbaru + link `All detections`) | **BERFUNGSI** | Terverifikasi di `Overview.tsx` baris 179–198 |
| OV-06 | Seksi `Failed SC checks` (menampilkan 4 check gagal + catatan `not_checked` + link `All checks`) | **BERFUNGSI** | Terverifikasi di `Overview.tsx` baris 201–222 |
| OV-07 | Widget `Pipeline Health & Telemetry Streams` (status per stream, `eps`, `events today`) | **BERFUNGSI** | Terverifikasi di `Overview.tsx` baris 227 & `/api/system/pipeline-health` |
| OV-08 | Seksi `Data coverage · open gaps` pada mode `Live` | **BUG** | Terdampak **BUG-002** (`api.gaps()` mengembalikan `[]` di mode `live`) |
| OV-09 | Tombol pintas `Timeline`, `Reports`, `Emergency Evidence Mode`, dan kartu laporan terbaru | **BERFUNGSI** | Terverifikasi di `Overview.tsx` baris 247–294 |

### B. Halaman 2 — `HostsScreen` (`/hosts`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| HS-01 | Filter Chips Status Host (`All Hosts`, `Online`, `Delayed`, `Offline`, `Unknown`) di UI | **BERFUNGSI** | Filter di sisi klien `Hosts.tsx` baris 62 berfungsi |
| HS-02 | Filter query parameter `GET /api/hosts?agent_status=...` di Backend | **BUG** | Terdampak **BUG-005** (memfilter kolom DB sebelum `derive_agent_status`) |
| HS-03 | Pengurutan otomatis prioritas risiko (`offline` -> `delayed` -> `unknown` -> `online`) | **BERFUNGSI** | Terverifikasi di `Hosts.tsx` baris 14 & 63 |
| HS-04 | Tampilan Mobile (`HostRow`) & Tampilan Tabel Desktop (`desktop-table`) | **BERFUNGSI** | Terverifikasi di `Hosts.tsx` baris 73–180 |
| HS-05 | Label pill `Log Sources` pada tabel desktop `Hosts` | **BUG** | Terdampak **BUG-006** (`auditd` ditampilkan sebagai teks `Error`) |
| HS-06 | Tombol aksi `Timeline` (`/timeline?host=...`) dan `Details` (`/hosts/:id`) per baris | **BERFUNGSI** | Terverifikasi di `Hosts.tsx` baris 155–172 |

### C. Halaman 3 — `HostDetailScreen` (`/hosts/:id`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| HD-01 | Sidebar metadata host (`Last data received`, `Exact timestamp`, `Last SC run`, `OS`, `Agent Mode`) | **BERFUNGSI** | Terverifikasi di `HostDetail.tsx` baris 47–71 |
| HD-02 | Notice peringatan `Agent is not reporting` (saat `offline`) & `No data received yet` (saat `unknown`) | **BERFUNGSI** | Terverifikasi di `HostDetail.tsx` baris 73–84 |
| HD-03 | Daftar `Configured Sources` di sidebar | **BERFUNGSI** | Terverifikasi di `HostDetail.tsx` baris 98–121 |
| HD-04 | Segmented Control 3-Tab (`RM alerts`, `SC checks`, `Telemetry gaps`) | **BERFUNGSI** | Terverifikasi di `HostDetail.tsx` baris 131–140 |
| HD-05 | Kartu **12-Module CIS & DISA STIG Security Posture Breakdown** di tab `SC checks` | **BERFUNGSI** | Terverifikasi di `HostDetail.tsx` baris 160–219 |
| HD-06 | Tombol **`Refresh SC Scan`** (`POST /api/findings/scan`) di tab `SC checks` | **BERFUNGSI** | Terverifikasi di `HostDetail.tsx` baris 175–191 & diuji di `pytest` |
| HD-07 | Tab `Telemetry gaps` pada mode `Live` | **BUG** | Terdampak **BUG-002** (`api.gaps()` mengembalikan `[]` di mode `live`) |

### D. Halaman 4 — `DetectionsScreen` (`/detections`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| DT-01 | Segmented Switcher (`RM alerts` vs `SC checks`) dengan badge jumlah | **BERFUNGSI** | Terverifikasi di `Detections.tsx` baris 53–62 |
| DT-02 | Dropdown pemilih Host (`All hosts` / per host) | **BERFUNGSI** | Terverifikasi di `Detections.tsx` baris 72–85 |
| DT-03 | **Quick Threat Hunting Search Bar** (filter berdasarkan judul, rule ID, reason, check ID, indikator) | **BUG** | Pencarian teks umum berfungsi, namun pencarian kode **MITRE ID** terdampak **BUG-014** |
| DT-04 | Chips Filter `Threat Impact (Severity)` (`All`, `Critical`, `High`, `Medium`, `Low`) | **BERFUNGSI** | Terverifikasi di `Detections.tsx` baris 132–143 |
| DT-05 | Chips Filter `Evidence Certainty (Confidence)` (`All`, `Confirmed`, `High`, `Suspected`) | **BERFUNGSI** | Terverifikasi di `Detections.tsx` baris 147–156 |
| DT-06 | Chips Filter `Investigation Status` (`All`, `New`, `Investigating`, `Resolved`, `False Positive`) | **BERFUNGSI** | Terverifikasi di `Detections.tsx` baris 158–169 |
| DT-07 | Chips Filter `Check result` pada tab `SC checks` (`Failed`, `Not checked`, `Passed`, `All`) | **BERFUNGSI** | Terverifikasi di `Detections.tsx` baris 281–291 |
| DT-08 | Tabel Desktop Triase Alert & SC Checks + tombol `Triage >` / `Details >` | **BERFUNGSI** | Terverifikasi di `Detections.tsx` baris 185–254 & 305–359 |

### E. Halaman 5 — `AlertDetailScreen` (`/alerts/:id`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| AD-01 | Hero Banner Alert (Badge `Severity`, `Confidence`, `Investigation Status`, link host, waktu deteksi) | **BERFUNGSI** | Terverifikasi di `AlertDetail.tsx` baris 86–103 |
| AD-02 | `AlertGroupingCard` (Agregasi deduplikasi kemunculan berulang + tombol `View Raw Events`) | **BERFUNGSI** | Terverifikasi di `domain.tsx` baris 327–395 |
| AD-03 | `KillChainCard` (Korelasi 6 Tahap MITRE ATT&CK: `TRIGGER`, `OBSERVED`, `CLEAR`) | **BERFUNGSI** | Logika berfungsi (`GET /api/alerts/{id}/context`), tampilan terdampak **BUG-011** (variabel CSS) |
| AD-04 | `BlastRadiusCard` (Ringkasan IP penyerang, user target, file terdampak, dan command) | **BERFUNGSI** | Terverifikasi di `domain.tsx` baris 992–1057 |
| AD-05 | `InvestigationWorkflowCard` (Dropdown status + input catatan operator + riwayat audit trail) | **BUG** | Berfungsi untuk 4 status dasar, namun terdampak **BUG-004** jika status backend `reopened`/`unverified` |
| AD-06 | `HandoffCard` (`Generate Handoff Prompt`, `Copy Prompt`, `Download .md`, `Preview Raw .md`) | **BERFUNGSI** | Terverifikasi di `domain.tsx` baris 592–717 & `GET /api/alerts/{id}/handoff` |
| AD-07 | `RecoveryVerificationCard` (`Verify Recovery`, 4 cek pemulihan, `Before vs After Remediation Diff`) | **BERFUNGSI** | Terverifikasi di `domain.tsx` baris 721–867 & `POST /api/alerts/{id}/verify` |
| AD-08 | `ProvenanceCard` (Jejak asal file log, daemon kolektor, parser, dan hash integritas) | **BUG** | Menampilkan info provenance, tetapi `source` untuk rule non-SUDO terdampak **BUG-006** |
| AD-09 | `RuleLogicCard` (Rumus deterministik rule, MITRE badge, trigger observasi, dan rasional) | **BERFUNGSI** | Terverifikasi di `domain.tsx` baris 291–323 |
| AD-10 | `IncidentReplayCard` (Rekonstruksi kronologis langkah demi langkah) | **BERFUNGSI** | Terverifikasi di `domain.tsx` baris 871–919 & `GET /api/alerts/{id}/replay` |
| AD-11 | `Supporting events` (Daftar baris log asli yang telah disanitasi) | **BERFUNGSI** | Terverifikasi di `AlertDetail.tsx` baris 143–164 & `GET /api/alerts/{id}/evidence` |
| AD-12 | `AiPanel` — RM Analysis Agent (`Key AEGIS1`, tombol `Request explanation` & `Retry`) | **BERFUNGSI** | Terverifikasi di `AiPanel.tsx` & `POST /api/alerts/{id}/analyze` |
| AD-13 | Tombol `Export Signed Evidence Bundle (.json)` (Bundel forensik bertanda tangan SHA-256) | **BERFUNGSI** | Terverifikasi di `AlertDetail.tsx` baris 61–80 & `GET /api/alerts/{id}/evidence-bundle` |

### F. Halaman 6 — `FindingDetailScreen` (`/findings/:id`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| FD-01 | Hero status temuan (`Passed`, `Failed · Severity`, `Not checked`) + peringatan `Result may be out of date` | **BERFUNGSI** | Terverifikasi di `FindingDetail.tsx` baris 38–63 |
| FD-02 | Daftar `What was observed` (Indikator baris konfigurasi aktual dari host) | **BERFUNGSI** | Terverifikasi di `FindingDetail.tsx` baris 65–79 |
| FD-03 | `Check details & limits` (Batas visibilitas inspeksi *read-only*) | **BERFUNGSI** | Terverifikasi di `FindingDetail.tsx` baris 81–97 |
| FD-04 | `AiPanel` — SC Analysis Agent (`Key AEGIS2`, panduan *hardening* non-destruktif) | **BERFUNGSI** | Terverifikasi di `FindingDetail.tsx` baris 102–108 & `POST /api/findings/{id}/analyze` |

### G. Halaman 7 — `TimelineScreen` (`/timeline`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| TL-01 | Dropdown filter Host & tombol pembalik urutan waktu (`Oldest first` / `Newest first`) | **BERFUNGSI** | Terverifikasi di `Timeline.tsx` baris 52–60 & 98–107 |
| TL-02 | **Threat Hunting Search Bar** pada Timeline | **BERFUNGSI** | Terverifikasi di `Timeline.tsx` baris 65–125 |
| TL-03 | Filter Chips Rentang Waktu (`6 h`, `24 h`, `7 days`) pada mode `Live` | **BUG** | Terdampak **BUG-007** (`opts.sinceHours` diabaikan pada mode `live`) |
| TL-04 | Scroll otomatis ke item yang difokuskan (`?focus=ALT-...`) | **BERFUNGSI** | Terverifikasi di `Timeline.tsx` baris 39–46 |

### H. Halaman 8 — `EvidenceScreen` (`/evidence`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| EV-01 | Status sesi aktif (`ActiveSession`) dengan hitung mundur waktu & bar progres | **BERFUNGSI** | Terverifikasi di `Evidence.tsx` baris 55–65 & 203–254 |
| EV-02 | Sheet formulir `Start Evidence Mode` (pilih host, durasi 15/30/60m, tipe data, validasi alasan >=10 karakter) | **BERFUNGSI** | Terverifikasi di `Evidence.tsx` baris 256–414 & `POST /api/evidence` |
| EV-03 | Modal konfirmasi `Stop Evidence Mode?` (`Keep running` / `Stop now`) | **BERFUNGSI** | Terverifikasi di `Evidence.tsx` baris 166–195 & `POST /api/evidence/{id}/stop` |
| EV-04 | Daftar `History` sesi sebelumnya & `Operator Action Audit Trail` | **BERFUNGSI** | Terverifikasi di `Evidence.tsx` baris 112–148 |

### I. Halaman 9 & 10 — `ReportsScreen` (`/reports`) & `ReportDetailScreen` (`/reports/:id`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| RP-01 | Filter Chips Status Laporan (`All`, `Ready`, `Generating`, `Failed`) | **BERFUNGSI** | Terverifikasi di `Reports.tsx` baris 56–66 |
| RP-02 | Sheet formulir `New Report` (pilih tipe `Daily` / `Incident`, pilih target host, rentang hari) | **BERFUNGSI** | Terverifikasi di `Reports.tsx` baris 228–353 |
| RP-03 | Penyusunan *Executive Summary* laporan menggunakan **Reporting Agent (`Key AEGIS3`)** | **BERFUNGSI** | Terverifikasi di `incident_service.py` baris 1264 & diuji di `pytest` |
| RP-04 | Akurasi penghitungan `alert_count` untuk host tanpa alert & filter periode laporan | **BUG** | Terdampak **BUG-009** (fallback `else alerts` memasukkan alert host lain jika host terpilih memiliki 0 alert) |
| RP-05 | Unduh laporan **PDF Biner Resmi (`GET /api/reports/{id}/pdf`)** via `reportlab` | **BERFUNGSI** | Terverifikasi di `ReportDetail.tsx` baris 41–93 & `test_backend_api.py` (`%PDF-`) |
| RP-06 | Tombol `Retry generation` pada laporan gagal di mode `Live` | **BUG** | Terdampak **BUG-012** (`actions.retryReport` hanya memodifikasi mock `db.reports`) |

### J. Halaman 11 — `AuditLogScreen` (`/audit`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| AL-01 | Penyimpanan & pengambilan log audit aksi operator (`GET /api/audit-logs`) | **BERFUNGSI** | Endpoint backend dan tampilan di `EvidenceScreen` berfungsi |
| AL-02 | Halaman mandiri `AuditLogScreen` pada rute `/audit` | **BELUM DIIMPLEMENTASIKAN** | Terdampak **BUG-008** (Rute `/audit` dan file `screens/AuditLog.tsx` belum dibuat) |

### K. Halaman 12 — `SettingsScreen` (`/settings`)
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| ST-01 | Pemilih Tema (`Auto`, `Light`, `Dark`) + tombol cepat di sidebar desktop | **BERFUNGSI** | Terverifikasi di `Settings.tsx` baris 41–60 & `AppShell.tsx` baris 183–191 |
| ST-02 | Pemilih Zona Waktu (`Local`, `UTC`) & switch `Relative time display` | **BERFUNGSI** | Terverifikasi di `Settings.tsx` baris 75–107 |
| ST-03 | `UX State Simulator` (`Live`, `Sample`, `Loading`, `Empty`, `Error`) | **BERFUNGSI** | Terverifikasi di `Settings.tsx` baris 125–144 |
| ST-04 | Kartu `3-Key AI Role Allocation & Failover` (`AEGIS1`, `AEGIS2`, `AEGIS3`) | **BERFUNGSI** | Terverifikasi di `Settings.tsx` baris 191–214 & `GET /api/system/ai-roles` |
| ST-05 | Teks informasi `Initial Sources` pada kartu `Product Principles & Limits` | **TIDAK LENGKAP** | Terdampak **BUG-013** (Masih mencantumkan 2 sumber log awal) |

### L. Mesin Deteksi (`RulesEngine`), Parser, Collector, Security Checker & AI
| ID Fitur | Fitur / Subfitur / Komponen Terkecil | Status | Catatan / Bukti Verifikasi |
| :--- | :--- | :---: | :--- |
| RE-01 | 13 Rule Deterministik Runtime Monitor (`RULE-SSH-BRUTE` s/d `RULE-ROOTKIT-SNIFF`) | **BERFUNGSI** | Seluruh 13 rule terverifikasi di `rules_engine.py` & `test_rules_engine.py` |
| RE-02 | Keunikan `event_id` pada parser SSH untuk multi-percobaan dalam 1 PID koneksi | **BUG** | Terdampak **BUG-001** (`f"{prefix}-AUTH-FAIL-{pid}"` tanpa hash baris/timestamp) |
| SC-01 | 12 Modul Read-Only Security Checker (8 CIS Ubuntu Benchmark + 4 DISA STIG Militer) | **BERFUNGSI** | Terverifikasi di `security_checker.py`, `GET /api/findings`, `POST /api/findings/scan`, `POST /api/telemetry/posture` |
| CL-01 | Kolektor `journalctl` dengan `Two-Phase Cursor Commit` & `TelemetrySanitizer` | **BERFUNGSI** | Terverifikasi di `collector.py` & `test_collector.py` |
| CL-02 | Pembacaan file log non-journal (`/var/log/nginx/access.log`) di `collector.py` | **BELUM DIIMPLEMENTASIKAN** | Terdampak **BUG-003** (`collector.py` baru membaca `journalctl`) |
| AI-01 | Validator Anti-Halusinasi AI, Pembekuan Severity, & Pemisahan `FACT` vs `HYPOTHESIS` | **BERFUNGSI** | Terverifikasi di `evidence.py`, `sc_validator.py`, `rm_validator.py`, `incident_service.py` |
| DB-01 | Persistensi `OperationalStateStore` lintas *restart* proses backend | **TIDAK LENGKAP** | Terdampak **BUG-010** (Masih disimpan di memori RAM proses FastAPI) |

---

## 6. HASIL PENGUJIAN KONDISI NORMAL & ABNORMAL

Seluruh skenario normal dan abnormal telah diuji terhadap basis kode saat ini:

| No | Skenario Kondisi Abnormal / Edge Case | Status Hasil Uji | Bukti & Penjelasan Teknis |
| :-: | :--- | :---: | :--- |
| 1 | **Database tidak tersedia (`simulate_db_error=True`)** | **LULUS** | `test_database_error_handling_sanitization`: Mengembalikan HTTP 500 yang telah disanitasi tanpa membocorkan kredensial/stack trace; `/api/health/database` melaporkan `status: degraded, connected: false`. |
| 2 | **Backend tidak tersedia** | **LULUS** | Frontend `QueryView` menangkap `ApiError` dan menampilkan komponen error beserta tombol `Retry`. |
| 3 | **Agent offline saat Recovery Verification** | **LULUS** | `test_automatic_recovery_verification_and_offline_honesty`: Jika `agent_status != online`, hasil verifikasi wajib `outcome: "unverified"` (tidak pernah dianggap `resolved`). |
| 4 | **Telemetry kosong (`raw_logs: []`)** | **LULUS** | `test_ingest_rejects_empty_raw_logs`: Ditolak oleh Pydantic validator (`min_length=1`) dengan HTTP 422. |
| 5 | **Data duplikat dikirim ulang oleh Collector** | **LULUS** | `test_ingest_duplicate_suppression`: Event dengan ID yang sama diabaikan (`duplicates_ignored`) dan `RulesEngine` menghasilkan ID alert deterministik berbasis SHA-256 (nol duplikasi alert). |
| 6 | **Token agen tidak valid / kosong (`X-Agent-Token`)** | **LULUS** | `test_ingest_missing_token_rejected_401` & `test_ingest_invalid_token_rejected_401`: Ditolak dengan HTTP 401 menggunakan `hmac.compare_digest` (tahan *timing attack*). |
| 7 | **Baris log mengandung kunci privat SSH / password / token API** | **LULUS** | `test_ingest_quarantines_sensitive_secrets_without_storing`: Dikarantina oleh `TelemetrySanitizer` sebelum diparse atau disimpan. |
| 8 | **API key AI tidak tersedia / AI timeout / HTTP 429 / JSON rusak** | **LULUS** | `test_real_llm_adapter_timeout_handling` & `test_real_llm_adapter_invalid_json`: Melakukan *automatic failover* (`AEGIS1 <-> AEGIS2 <-> AEGIS3`), dan jika semua gagal, beralih ke *Grounded Deterministic Synthesis* tanpa menghentikan deteksi. |
| 9 | **Koneksi terputus saat pengiriman data dari Collector** | **LULUS** | `test_two_phase_commit_commits_only_on_delivery_success`: Kursor `.collector_cursor` tidak diperbarui jika HTTP bukan 200, sehingga log dikirim ulang pada siklus berikutnya. |
| 10 | **Input baris log terlalu panjang (`> 4096` karakter)** | **LULUS** | `test_ingest_rejects_excessive_line_length`: Ditolak oleh validator `TelemetryIngestRequest` dengan HTTP 422. |
| 11 | **Percobaan mengubah `severity` alert via `PUT` / `PATCH /api/alerts/{id}`** | **LULUS** | `test_severity_immutability_no_mutating_endpoints`: Ditolak dengan HTTP 405 (`Method Not Allowed`) di API dan ditolak oleh trigger `trg_alerts_severity_immutable` di PostgreSQL. |
| 12 | **Serangan Brute-Force SSH dalam 1 koneksi TCP (PID `sshd` sama)** | **GAGAL (BUG-001)** | Karena `event_id` hanya memakai `{prefix}-AUTH-FAIL-{pid}`, percobaan ke-2 dst. dianggap duplikat jika prefix sama. |
| 13 | **Status investigasi berubah menjadi `reopened` lalu dibuka di UI** | **GAGAL (BUG-004)** | `investigationStatusMeta['reopened']` bernilai `undefined` di frontend. |

---

## 7. REKOMENDASI URUTAN PERBAIKAN (PRIORITAS EKSEKUSI)

Apabila Anda menyetujui laporan audit ini dan menginstruksikan untuk masuk ke **Tahap Perbaikan**, berikut adalah urutan perbaikan yang direkomendasikan:

1. **Prioritas 1 (`CRITICAL` — BUG-001)**:
   - Perbarui pembentukan `event_id` di `aegis_agent/linux_parser.py` (`_parse_sshd_log`, `_parse_sudo_log`, dll.) agar menyertakan hash pendek dari baris log (`abs(hash(line)) % 100000` atau `sha256[:8]`) sehingga percobaan login berulang dalam satu PID `sshd` yang sama tidak pernah saling menimpa.
2. **Prioritas 2 (`HIGH` — BUG-002, BUG-003, BUG-004)**:
   - **BUG-004**: Lengkapi seluruh 10 status investigasi (`reopened`, `unverified`, `handoff_ready`, `remediation_in_progress`, `verification`, `detected`) pada `dashboard/src/data/types.ts`, `dashboard/src/lib/status.ts`, dan `InvestigationWorkflowCard` (`domain.tsx`).
   - **BUG-002**: Tambahkan endpoint `GET /api/gaps` di backend, hubungkan ke `verify_alert_recovery` & `generate_handoff_document`, serta panggil dari `api.gaps()` di frontend pada mode `live`.
   - **BUG-003**: Tambahkan pembacaan *incremental file tailing* di `aegis_agent/collector.py` untuk `/var/log/nginx/access.log` (dan file log opsional yang dikonfigurasi) agar serangan web (`RULE-WEB-ATTACK`) di *mini server* Ubuntu langsung tertangkap otomatis.
3. **Prioritas 3 (`MEDIUM` — BUG-005, BUG-006, BUG-007, BUG-008, BUG-009, BUG-010)**:
   - **BUG-005**: Perbaiki urutan filter `agent_status` di `aegis_backend/routers/hosts.py` agar memfilter hasil `derive_agent_status()`.
   - **BUG-006**: Perbaiki pemetaan label `SourceId` di `Hosts.tsx` (`auditd` -> `'Auditd'`) serta pemetaan `source` berdasarkan `rule_id` / `source_id` di `dashboard/src/data/api.ts`.
   - **BUG-007**: Aktifkan filter `opts.sinceHours` (`6 h`, `24 h`, `7 days`) dan integrasi gap/event pada `api.timeline()` di mode `live`.
   - **BUG-008**: Buat layar mandiri `dashboard/src/screens/AuditLog.tsx` dan daftarkan rute `/audit` di `App.tsx` + link navigasi.
   - **BUG-009**: Perbaiki logika filter alert di `create_report` (`operations.py`) agar memfilter berdasarkan `period_start` s/d `period_end` dan menghapus fallback `else alerts` yang salah.
   - **BUG-010**: Tambahkan *file-backed persistence* otomatis pada `OperationalStateStore` agar catatan investigasi, laporan, sesi *Evidence Mode*, dan audit log tidak hilang saat proses backend di-*restart*.
4. **Prioritas 4 (`LOW` & `INFO` — BUG-011 s/d BUG-016)**:
   - **BUG-011**: Ganti variabel CSS `--bg-elevated`, `--border-subtle`, dan `--text-muted` di `domain.tsx` dengan token resmi dari `tokens.css`.
   - **BUG-012, BUG-013, BUG-014, BUG-015, BUG-016**: Perbaiki `actions.retryReport` di mode `live`, perbarui teks deskripsi `Settings.tsx`/`HostDetail.tsx`, tambahkan pencarian `mitreAttackId` di `Detections.tsx`, dan tambahkan *cooldown/rate-protection* pada endpoint analisis AI.

---

## 8. KESIMPULAN KESIAPAN APLIKASI

- **Status Saat Ini:** **Siap 80,23% (Perlu Perbaikan pada 1 Bug Critical, 3 High, 6 Medium, dan 4 Low sebelum diterjunkan ke pengujian langsung di Mini Server Ubuntu)**.
- Sesuai instruksi Anda (**Aturan #9**: *"Jangan memperbaiki apa pun terlebih dahulu. Selesaikan audit, kumpulkan bukti, lalu serahkan laporan lengkap kepada saya untuk ditinjau dan disetujui sebelum masuk tahap perbaikan"*), **belum ada satu baris pun kode aplikasi yang diubah**.
- Silakan tinjau laporan ini. Jika Anda setuju, cukup balas **"gas perbaiki semua"** (atau gunakan `/goal`) dan saya akan mengeksekusi seluruh perbaikan dari **BUG-001 hingga BUG-016** beserta pengujian ulangnya sampai 100% tuntas.

