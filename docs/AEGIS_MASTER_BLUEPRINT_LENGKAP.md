# DOKUMEN MASTER SPESIFIKASI TEKNIS & KATALOG FITUR MENYELURUH
# AEGIS — AI-Assisted Linux Security Monitoring, Detection, Investigation, Handoff & Recovery Verification Platform
**(Edisi Khusus: Pertahanan Siber Infrastruktur Kritis & Komando Siber TNI AD)**

---

## DAFTAR ISI
1. **BAB 1: Identitas Produk, Filosofi Desain & Prinsip Fundamental (Non-Negotiable Core Rules)**
2. **BAB 2: Arsitektur Sistem End-to-End & Topologi Deployment (Server Ubuntu + Cloudflare Zero-Trust)**
3. **BAB 3: Spesifikasi Lengkap Sistem Desain UI/UX, Palet Warna Hex, Tipografi, Grid, dan Responsivitas**
4. **BAB 4: Katalog Lengkap Seluruh Layar (12 Screen), Tab, Tombol, Filter, dan Komponen Interaktif Frontend**
5. **BAB 5: Arsitektur Agen Telemetri Linux (`AegisTelemetryCollector`) & Mekanisme Two-Phase Cursor Commit**
6. **BAB 6: Mesin Normalisasi Log Multi-Sumber (`LinuxTelemetryParser`) & Pre-Transmission Sanitizer**
7. **BAB 7: Spesifikasi Lengkap 13 Rule Deterministik Runtime Monitor (RM) & Pemetaan MITRE ATT&CK**
8. **BAB 8: Spesifikasi Lengkap 12 Modul Read-Only Security Checker (8 CIS Ubuntu Benchmark + 4 DISA STIG Militer)**
9. **BAB 9: Arsitektur Orkestrasi Multi-Agent AI 3-Kunci (`AEGIS1`, `AEGIS2`, `AEGIS3`) & Automatic Cross-Key Failover**
10. **BAB 10: Sistem Anti-Halusinasi AI, Epistemic Separation (Fakta vs Hipotesis), dan Backend Gatekeeper**
11. **BAB 11: Fitur Investigasi Tingkat Lanjut (Kill-Chain 6 Tahap, Blast Radius, Before/After Remediation Diff, SHA-256 Evidence Bundle, Handoff Markdown, PDF Report Generator)**
12. **BAB 12: Katalog Lengkap Seluruh Endpoint REST API Backend FastAPI & Kontrak Schema Pydantic**
13. **BAB 13: Arsitektur Database PostgreSQL (Supabase), Row-Level Security (RLS), dan Transaksi RPC Atomik**
14. **BAB 14: Katalog Lengkap 113 Pengujian Otomatis (`pytest`) & Jaminan Kualitas (Quality Assurance)**

---

## BAB 1: IDENTITAS PRODUK, FILOSOFI DESAIN & PRINSIP FUNDAMENTAL

### 1.1 Definisi Produk
**AEGIS** adalah platform pemantauan keamanan (*Security Monitoring*), deteksi ancaman (*Runtime Threat Detection*), pemeriksaan postur konfigurasi (*Security Posture Checker*), investigasi insiden berbantuan AI (*AI-Assisted Investigation*), pembuatan dokumen serah-terima (*Portable AI Handoff Prompt*), dan verifikasi pemulihan otomatis (*Automatic Recovery Verification*) yang dirancang khusus untuk **server Linux (Ubuntu Server LTS)** pada infrastruktur kritis dan lingkungan pertahanan siber (**TNI AD / Komando Pertahanan Siber**).

### 1.2 7 Hukum Besi (Ironclad Architectural Principles) AEGIS
Seluruh baris kode AEGIS mematuhi 7 batasan arsitektur yang tidak dapat dilanggar:
1. **Zero Autonomous Remediation (Tanpa Eksekusi Otomatis yang Merusak)**:
   - AEGIS **tidak pernah** memblokir IP secara otomatis, mematikan proses (*kill process*), merestart layanan produksi, atau mengubah file konfigurasi server secara sepihak. Semua tindakan perbaikan dilakukan oleh operator manusia atau agen penerima melalui dokumen **AI Handoff** dengan persetujuan eksplisit.
2. **Deterministic Detection Engine (Deteksi 100% Deterministik & Independen dari AI)**:
   - Seluruh *alert* keamanan dihasilkan oleh mesin aturan deterministik (`RulesEngine`). Apabila koneksi internet ke penyedia AI (Gemini) terputus atau *rate-limited*, fungsi pengumpulan log, deteksi serangan, korelasi *kill-chain*, dan penyimpanan *alert* tetap berjalan **100% tanpa gangguan**.
3. **Immutable Alert Severity (Tingkat Keparahan Alert Tidak Bisa Diubah)**:
   - Nilai `severity` (`critical`, `high`, `medium`, `low`) ditentukan mutlak oleh `RulesEngine` saat *alert* dibuat. AI maupun endpoint HTTP (`PUT`/`PATCH /api/alerts/{id}`) dilarang keras mengubah `severity` untuk mencegah manipulasi tingkat bahaya (*severity downgrade attack*).
4. **Separated Severity vs. Confidence (Pemisahan Dampak Ancaman vs. Kepastian Bukti)**:
   - **Severity (Impact)** mengukur seberapa bahaya dampak serangan terhadap sistem (`critical`, `high`, `medium`, `low`).
   - **Confidence (Evidence Certainty)** mengukur tingkat kelengkapan bukti telemetri (`confirmed` 95%+, `high` 80–94%, `suspected` 50–79%).
5. **Epistemic Honesty & Gap Transparency (Kejujuran Epistemik atas Hilangnya Log)**:
   - Ketiadaan log atau agen yang *offline* **tidak pernah** dianggap sebagai bukti bahwa server aman atau insiden telah selesai. Jika agen mati saat verifikasi pemulihan, status wajib dilaporkan sebagai **`unverified`** (*tidak terverifikasi*), bukan `resolved`.
6. **Strict Epistemic Separation (Pemisahan Ketat Fakta Terkonfirmasi vs. Hipotesis)**:
   - Setiap analisis AI dan dokumen Handoff memisahkan secara eksplisit antara **[FACT]** (fakta yang terbukti langsung oleh ID log telemetri) dan **[HYPOTHESIS - UNVERIFIED]** (dugaan/hipotesis yang masih harus dibuktikan lewat perintah investigasi *read-only*).
7. **Pre-Parsing Credential & Secret Sanitization (Sanitasi Rahasia Sebelum Penyimpanan & AI)**:
   - Baris log yang mengandung kunci privat (`BEGIN RSA/OPENSSH PRIVATE KEY`), *password* teks jelas, *hash* `/etc/shadow`, atau token API (`sk-...`, `Bearer ...`, `AIza...`) dikarantina dan disensor oleh `TelemetrySanitizer` **sebelum** masuk ke database maupun dikirim ke LLM.

---

## BAB 2: ARSITEKTUR SISTEM END-TO-END & TOPOLOGI DEPLOYMENT

```
+-----------------------------------------------------------------------------------+
|                        NODE SERVER LINUX (Ubuntu 24.04 LTS)                       |
|                                                                                   |
|  [Sumber Telemetri & Konfigurasi OS]                                              |
|   ├── /var/log/auth.log & systemd-journald (SSH, PAM, Sudo, Useradd/Usermod)      |
|   ├── /var/log/audit/audit.log (Auditd EXECVE, SYSCALL, File Tampering, APT)      |
|   ├── Kernel dmesg / UFW Firewall Logs (Port Scan, Segfault, Promiscuous Sniff)   |
|   ├── /var/log/nginx/access.log & apache2 (SQLi, LFI, RCE, .env Probe)            |
|   ├── Cron & Systemd Service State (Persistence & Defense Evasion)                |
|   └── 12 File Konfigurasi CIS + DISA STIG (/etc/ssh/sshd_config, /etc/issue, dll) |
|                                      │                                            |
|                                      ▼                                            |
|  [aegis-collector.service (Python Daemon — Group 'adm', Read-Only)]               |
|   ├── 1. Incremental journalctl --after-cursor (Two-Phase Cursor Commit)          |
|   ├── 2. TelemetrySanitizer (Redaksi kunci privat, password, shadow hash)         |
|   ├── 3. ReadOnlySecurityChecker.run_live_scan() (12 Kontrol CIS + DISA STIG)     |
|   └── 4. HTTP POST (/api/telemetry/ingest, /heartbeat, /posture) [X-Agent-Token]  |
|                                      │                                            |
|                                      ▼                                            |
|  [aegis-backend.service (FastAPI Uvicorn — 127.0.0.1:8000)]                       |
|   ├── LinuxLogPipelineAdapter & LinuxTelemetryParser (Normalisasi ke LogEvent)    |
|   ├── RulesEngine (13 Rule Deterministik: SSH, Sudo, Web, FW, Kernel, APT, dll)   |
|   ├── IncidentService (Kill-Chain 6 Tahap, Blast Radius, Handoff, Diff, PDF)      |
|   └── Multi-Agent AI Orchestrator (3 API Key: AEGIS1 [RM], AEGIS2 [SC], AEGIS3)   |
|          │                                                     │                  |
|          ▼                                                     ▼                  |
|  [Supabase PostgreSQL + RLS]                         [Nginx Reverse Proxy :80]    |
|   ├── hosts, telemetry_events                         ├── / -> dashboard/dist     |
|   ├── alerts, alert_evidence                          └── /api -> 127.0.0.1:8000  |
|   └── fn_ingest_alert_with_evidence (Atomic RPC)               │                  |
+----------------------------------------------------------------│------------------+
                                                                 ▼
                                            [Cloudflare Zero-Trust Tunnel (cloudflared)]
                                                                 │
                                                                 ▼
                                            [Browser Operator (Desktop & Mobile Web UI)]
```

---

## BAB 3: SPESIFIKASI LENGKAP SISTEM DESAIN UI/UX, PALET WARNA HEX, TIPOGRAFI, GRID & RESPONSIVITAS

Seluruh elemen visual dashboard AEGIS didefinisikan secara presisi di [`dashboard/src/styles/tokens.css`](file:///d:/Projects/School/aegis/dashboard/src/styles/tokens.css) dan [`dashboard/src/styles/app.css`](file:///d:/Projects/School/aegis/dashboard/src/styles/app.css).

### 3.1 Filosofi Visual & Identitas Warna Brand
- **Inspirasi Brand**: Burung Hantu Penjaga AEGIS (*Forest Green* `#0A4332`, *Liquid Amber* `#DE8121`, dan *Warm Ivory* `#FBF6F3`).
- **Dua Tema Penuh (Dual Theme — Light & Dark)**:
  - **Light Mode (`[data-theme='light']`)**: Kanvas *Warm Ivory* (`#F7F2E9`) yang nyaman untuk pembacaan laporan panjang di siang hari tanpa silau putih murni (`#FFFFFF`), dipadukan dengan aksen hijau hutan militer (`#0A4332`).
  - **Dark Mode (`[data-theme='dark']`)**: Kanvas *Crisp Obsidian* (`#0B0F10`) untuk ruang kendali SOC (*Security Operations Center*) malam hari, dengan warna primer *AEGIS Jade/Emerald* (`#1FA768`) dan gradien *Liquid Amber* untuk mode darurat.
  - **System Sync (`system`)**: Mengikuti `prefers-color-scheme` sistem operasi secara otomatis.

### 3.2 Tabel Lengkap Token Warna CSS (`tokens.css`)

#### A. Palet Permukaan & Latar (Surfaces & Borders)
| Nama Token CSS | Nilai Light Mode (Hex) | Nilai Dark Mode (Hex / RGBA) | Fungsi Penggunaan di UI |
| :--- | :--- | :--- | :--- |
| `--color-bg` | `#f7f2e9` (Warm Ivory) | `#0b0f10` (Crisp Obsidian) | Latar belakang utama layar aplikasi (`<body>`) |
| `--color-surface` | `#fdfaf4` | `#13191c` | Kartu grup daftar (`<Group>`), panel, tabel desktop, dan *bottom sheet* |
| `--color-surface-sunken` | `#f0eadf` | `#0c1012` | Blok kode perintah terminal, baris log mentah, *input search*, dan *segmented control* |
| `--color-surface-raised` | `#fffdf8` | `#182024` | Navigasi bawah (*bottom nav*), *header* lengket, dan *modal dialog* |
| `--color-border` | `#e4dacb` | `#1f2a30` | Garis tepi kartu standar (`1px solid`) |
| `--color-border-strong` | `#cdbfa9` | `#2c3c45` | Garis tepi tombol sekunder, *input focus*, dan kartu berprioritas tinggi |
| `--color-divider` | `#ece4d7` | `#182227` | Garis pemisah antar-baris (`<Row>`) di dalam grup |
| `--logo-tile-bg` | `#fbf6f3` | `#fbf6f3` | Latar khusus tempat logo burung hantu AEGIS berpijak |

#### B. Palet Teks & Tipografi (Text Hierarchy)
| Nama Token CSS | Nilai Light Mode | Nilai Dark Mode | Fungsi Penggunaan di UI |
| :--- | :--- | :--- | :--- |
| `--color-text` | `#1f1d1a` | `#e8ecee` | Judul layar, judul *alert*, nama *host*, dan teks utama |
| `--color-text-secondary` | `#5a5449` | `#9cb0b9` | Subjudul baris, deskripsi alasan *rule*, dan narasi analisis AI |
| `--color-text-tertiary` | `#7d7568` | `#6b808a` | *Timestamp* relatif, label kolom *overline*, dan petunjuk kaki (*footer hint*) |
| `--color-text-inverse` | `#fdfaf4` | `#0b0f10` | Teks di atas permukaan terbalik |

#### C. Palet Brand & Liquid Accent
| Nama Token CSS | Nilai Light Mode | Nilai Dark Mode | Fungsi Penggunaan di UI |
| :--- | :--- | :--- | :--- |
| `--color-primary` | `#0a4332` (Forest Green) | `#1fa768` (Jade Emerald) | Tombol aksi utama (`<Button variant="primary">`), indikator aktif |
| `--color-primary-hover` | `#0e5640` | `#26c078` | Warna tombol utama saat kursor *hover* |
| `--color-primary-pressed` | `#073326` | `#178652` | Warna tombol utama saat ditekan (*active*) |
| `--color-on-primary` | `#fdfaf4` | `#071910` | Teks & ikon di dalam tombol utama |
| `--color-primary-soft` | `#e0ebe3` | `rgba(31, 167, 104, 0.14)` | Latar belakang *chip* filter yang sedang dipilih & *badge* brand |
| `--color-accent` | `#c26a12` (Restrained Amber) | `#f59e0b` (Liquid Amber) | Sorotan penting, hitungan mundur *Emergency Evidence Mode* |
| `--liquid-fill` | `#0a4332` | `linear-gradient(135deg, #fbbf24 0%, #f59e0b 55%, #d97706 100%)` | Bar progres *Emergency Evidence Mode* & aksen gradien |

#### D. Palet Status Semantik (7 Tone Status Keamanan)
Setiap status keamanan memiliki 3 pasangan warna: **Foreground (`-fg`)** untuk teks/ikon, **Background (`-bg`)** untuk latar *badge/notice*, dan **Border (`-border`)** untuk garis tepi:

| Tone Semantik | Light FG / BG / Border | Dark FG / BG / Border | Digunakan Untuk Status Berikut |
| :--- | :--- | :--- | :--- |
| **1. Healthy (`healthy`)** | FG: `#1d6a44`<br>BG: `#e1eee3`<br>Border: `#b9d5c0` | FG: `#34d399`<br>BG: `rgba(52,211,153,0.12)`<br>Border: `rgba(52,211,153,0.30)` | Agent `Online`, SC Check `Passed`, Recovery `Resolved`, Confidence `Confirmed (95%+)`, Kesiapan `SIAGA III · TERKENDALI`, Key `Ready` |
| **2. Info (`info`)** | FG: `#2b5b88`<br>BG: `#e3ebf3`<br>Border: `#bccfe2` | FG: `#60a5fa`<br>BG: `rgba(96,165,250,0.12)`<br>Border: `rgba(96,165,250,0.30)` | Severity `Low`, Investigation `Investigating` / `Handoff Ready`, Confidence `High (80-94%)` |
| **3. Warning (`warning`)** | FG: `#855600`<br>BG: `#f7eacb`<br>Border: `#e5cd8f` | FG: `#facc15`<br>BG: `rgba(250,204,21,0.12)`<br>Border: `rgba(250,204,21,0.30)` | Severity `Medium`, Agent `Delayed`, Investigation `Remediation In Progress` / `Verification`, Confidence `Suspected`, Kesiapan `SIAGA II · WASPADA` |
| **4. High (`high`)** | FG: `#ad4c0e`<br>BG: `#f8e0cc`<br>Border: `#ecbd97` | FG: `#fa8c47`<br>BG: `rgba(250,140,71,0.13)`<br>Border: `rgba(250,140,71,0.32)` | Severity `High`, Investigation `New` / `Detected` |
| **5. Critical (`critical`)** | FG: `#b0261b`<br>BG: `#f8dfda`<br>Border: `#eab4ac` | FG: `#ff6b6b`<br>BG: `rgba(255,107,107,0.13)`<br>Border: `rgba(255,107,107,0.34)` | Severity `Critical`, Agent `Offline`, Recovery `Still Active` / `Reopened`, Kesiapan `SIAGA I · KRITIS` |
| **6. Unknown (`unknown`)** | FG: `#645d52`<br>BG: `#ebe5da`<br>Border: `#cfc5b5` | FG: `#94a3b8`<br>BG: `rgba(148,163,184,0.11)`<br>Border: `rgba(148,163,184,0.28)` | Agent `Unknown`, SC Check `Not Checked`, Recovery `Unverified (Telemetry Missing)` |
| **7. Disabled (`disabled`)** | FG: `#958d80`<br>BG: `#ede7dc`<br>Border: `#dcd3c4` | FG: `#62727b`<br>BG: `rgba(98,114,123,0.12)`<br>Border: `rgba(98,114,123,0.30)` | Source `Not Configured`, Session `Expired` / `Ended`, `False Positive` |

#### E. Pola Arsir Khusus Telemetry Gap (`GapBlock`)
- `--gap-stripe-a` & `--gap-stripe-b`: Membuat motif garis miring (`repeating-linear-gradient(-45deg, ...)`) pada blok **Telemetry Gap** sehingga operator secara visual langsung menyadari bahwa ada rentang waktu di mana log terputus (*blind spot*).

### 3.3 Tipografi, Skala Ukuran Huruf & Sistem Grid
- **Font Sans-Serif Utama (`--font-sans`)**: `'Inter Variable', 'Inter', system-ui, -apple-system, sans-serif` (dipaketkan secara *self-hosted* via `@fontsource-variable/inter` agar tetap tampil sempurna meskipun tanpa internet publik).
- **Font Monospace Teknis (`--font-mono`)**: `'JetBrains Mono', ui-monospace, monospace` (dipaketkan via `@fontsource/jetbrains-mono`). Wajib digunakan untuk seluruh **IP Address, Hostname, Rule ID, Check ID, SHA-256 Hash, Path File Linux (`/etc/ssh/sshd_config`), Perintah Terminal (`sudo sshd -t`), dan Timestamp**.
- **Skala Ukuran Font**:
  - `--text-2xs`: `11px` (Label *overline* huruf kapital, *chip* kecil)
  - `--text-xs`: `12px` (Metadata, *timestamp*, ID *event*, *tag*)
  - `--text-sm`: `13px` (Subteks baris, deskripsi sekunder)
  - `--text-md`: `15px` (Teks bodi utama, judul baris daftar)
  - `--text-lg`: `17px` (Judul seksi `<Section>`, judul *bottom sheet*)
  - `--text-xl`: `20px` (Judul utama layar `<Screen>`)
  - `--text-2xl`: `24px` (Headline detail insiden)
- **Grid Spasi 4-Point (`4pt Grid`)**:
  - `--space-1` (`4px`), `--space-2` (`8px`), `--space-3` (`12px`), `--space-4` (`16px`), `--space-5` (`20px`), `--space-6` (`24px`), `--space-8` (`32px`), `--space-10` (`40px`).
- **Radius Sudut (`Border Radius`)**:
  - `--radius-xs` (`4px` untuk kode & *tag*), `--radius-sm` (`6px` untuk *badge* & *input*), `--radius-md` (`10px` untuk grup kartu & tombol), `--radius-lg` (`14px` untuk *sheet*), `--radius-pill` (`999px` untuk *chip* filter).
- **Standar Aksesibilitas Sentuh (`Touch Target`)**:
  - `--touch-min: 44px`: Seluruh tombol, *tab*, dan baris interaktif memiliki tinggi minimum `44px` sesuai standar ergonomis mobile lapangan.

### 3.4 Arsitektur Layout Responsif (Mobile-First + Full Desktop SOC Mode)
1. **Mode Mobile / Tablet Lapangan (`< 1024px`)**:
   - Menggunakan **Sticky Top Bar** (`56px`) + **Fixed Bottom Navigation Bar** (`64px`) dengan 5 tab utama (`Overview`, `Hosts`, `Detections`, `Reports`, `Settings`).
   - Daftar *Alert* dan *SC Checks* dirender sebagai kartu vertikal (`<Group>` dengan `<AlertRow>` / `<FindingRow>`).
2. **Mode Desktop SOC (`>= 1024px`)**:
   - Berubah otomatis menjadi **Left Persistent Sidebar Navigation** lengkap dengan logo burung hantu AEGIS, sub-caption *"Linux Security Monitor"*, tombol pemilih status *Preview*, dan indikator versi `Ubuntu Server · Read-Only Agent · v0.1`.
   - Konten utama melebar menjadi **2-Column Asymmetric Grid (`desktop-grid-2`)** pada layar `Overview`, `HostDetail`, dan `AlertDetail`, serta berubah menjadi **Full Data Table (`desktop-table`)** pada layar `Hosts` dan `Detections`.

---

## BAB 4: KATALOG LENGKAP SELURUH LAYAR (12 SCREEN), TAB, TOMBOL, FILTER & KOMPONEN INTERAKTIF FRONTEND

Aplikasi Frontend React 18 + TypeScript + Vite memiliki **12 layar rute (`Routes`)** yang didefinisikan di [`dashboard/src/App.tsx`](file:///d:/Projects/School/aegis/dashboard/src/App.tsx):

### 4.1 Komponen Global (`AppShell.tsx`)
1. **Header Bar / Sidebar Navigation**:
   - Menampilkan logo AEGIS, judul layar aktif, tombol kembali (`Back` dengan ikon `ChevronLeft` pada halaman detail), serta slot aksi kanan (`actions`) dan sub-header (`subheader`).
2. **System Degraded Banner (`SystemBanner`)**:
   - Muncul otomatis di bagian paling atas layar apabila `collector === 'degraded'` atau `rulesEngine === 'degraded'`, memperingatkan operator bahwa pengumpulan log sedang terhambat.
3. **Preview State Switcher (`SlidersHorizontal` Sheet)**:
   - Memungkinkan penguji/dewan juri berpindah antar skenario tampilan UI secara instan:
     - `Normal — live populated data` (Terhubung penuh ke FastAPI Backend & Supabase)
     - `Loading — skeletons` (Menampilkan animasi *skeleton* saat memuat data)
     - `Empty — no hosts registered` (Menampilkan tampilan awal saat belum ada agen terdaftar)
     - `Error — backend unreachable` (Menampilkan *state* kegagalan koneksi jaringan)
     - `AI provider unavailable` (Simulasi ketika API Gemini sedang mati; membuktikan deteksi deterministik tetap berjalan 100%)
     - `Collector & rules degraded` (Simulasi ketika pipeline mengalami gangguan)

---

### 4.2 Layar 1: `OverviewScreen` (`/`) — Pusat Komando Utama
File: [`dashboard/src/screens/Overview.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/Overview.tsx)
1. **Agent Status Fleet Strip (`fleet-section`)**:
   - 4 kotak metrik interaktif yang dapat diklik menuju filter host:
     - **Online** (`tone-healthy`, ikon `CheckCircle2`)
     - **Delayed** (`tone-warning`, ikon `Clock`)
     - **Offline** (`tone-critical`, ikon `Unplug`)
     - **Unknown** (`tone-unknown`, ikon `CircleHelp`)
   - Baris kaki menampilkan waktu penerimaan data terakhir (`Last data received X ago from <hostname> · N hosts`).
2. **Kartu Status Kesiapan Siber (`Defense Cyber Readiness · CIS & DISA STIG`)**:
   - Menampilkan badge tingkat kesiapan komando secara *real-time*:
     - **`SIAGA I · KRITIS`** (Merah `--status-critical-fg`): Jika ada *alert* `Critical`/`High` yang belum selesai atau ada *host* `Offline`.
     - **`SIAGA II · WASPADA`** (Kuning Amber `--status-warning-fg`): Jika ada temuan postur CIS/STIG yang `Fail` atau *alert* `Medium`/`Low`.
     - **`SIAGA III · TERKENDALI`** (Hijau `--status-healthy-fg`): Jika seluruh *host* `Online`, nol insiden aktif, dan seluruh kontrol postur patuh.
   - Menampilkan 4 metrik kepatuhan:
     - **CIS Ubuntu Benchmark**: `X/8 Controls Compliant`
     - **DISA STIG Military Baseline**: `X/4 Controls Compliant`
     - **Overall Posture Score**: `X/12 Passing (Y%)`
     - **AI Orchestration**: `3-Key Active (AEGIS1 · AEGIS2 · AEGIS3)`
3. **Active Emergency Evidence Banner (`EvidenceBanner`)**:
   - Jika ada sesi *Emergency Evidence Mode* yang sedang berjalan, muncul banner berkedip dengan *progress bar* sisa waktu menit dan tombol `Stop`.
4. **Kolom Utama Desktop (`desktop-grid-2__main`)**:
   - **RM Alerts · Last 24 h**: Menampilkan 4 *alert* terbaru lengkap dengan badge `Severity`, `Confidence`, `Status Investigasi`, `Rule ID`, dan jumlah pengelompokan (`occurrences`).
   - **Failed SC Checks**: Menampilkan 4 temuan pemeriksaan konfigurasi yang gagal (`FAIL`) beserta indikator baris konfigurasinya.
5. **Kolom Samping Desktop (`desktop-grid-2__side`)**:
   - **Pipeline Health & Telemetry Streams (`PipelineHealthWidget`)**: Menampilkan status kesehatan *stream* `SSH / PAM Auth Logs`, `Sudo & Auditd Logs`, dan `Systemd Journal`, termasuk *throughput* (`events/min`), jumlah antrean, dan waktu *event* terakhir.
   - **Data Coverage · Open Gaps**: Menampilkan daftar celah waktu telemetri yang sedang terbuka.
   - **Investigate & Reports Quick Actions**: Tombol pintas menuju `Timeline`, `Reports`, `Emergency Evidence Mode`, dan laporan terbaru.
   - **Epistemic Honesty Footnote**: Catatan kaki transparansi bahwa *"No alert does not mean a host is secure. AEGIS reports what its checks and rules can observe on collected sources. It does not block traffic or change hosts."*

---

### 4.3 Layar 2: `HostsScreen` (`/hosts`) — Inventaris & Kesehatan Node Server
File: [`dashboard/src/screens/Hosts.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/Hosts.tsx)
1. **Filter & Pencarian Host**:
   - **Search Input**: Cari berdasarkan `hostname` atau sistem operasi (`Ubuntu 24.04 LTS`).
   - **Status Filter Chips**: `All`, `Online`, `Delayed`, `Offline`, `Unknown`.
2. **Tampilan Tabel Desktop & Kartu Mobile**:
   - Menampilkan `Hostname`, `OS`, `Agent Version (read-only)`, badge `Agent Status`, `Last Data Received`, `Last SC Run`, jumlah sumber log yang aktif (`collecting`), jumlah `Open Alerts`, dan jumlah `Failed SC Checks`.

---

### 4.4 Layar 3: `HostDetailScreen` (`/hosts/:id`) — Detail Telemetri & Postur per Server
File: [`dashboard/src/screens/HostDetail.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/HostDetail.tsx)
1. **Sidebar Metadata Host**:
   - Menampilkan badge status agen (`Online` / `Offline` / `Delayed`), `Last data received`, `Exact timestamp`, `Last SC run`, `OS`, dan `Agent Mode (v0.1.0 · read-only)`.
   - Tombol pintas `Timeline` (`/timeline?host=...`) dan `Evidence Mode` (`/evidence?new=1&host=...`).
   - **Configured Sources**: Daftar status tiap sumber log pada host tersebut (`ssh-auth` `/var/log/auth.log`, `auditd` `/var/log/audit/audit.log`, `nginx-access` `/var/log/nginx/access.log`).
2. **Segmented Control 3-Tab**:
   - **Tab 1 (`RM alerts`)**: Daftar seluruh *alert* deterministik yang terjadi pada host ini.
   - **Tab 2 (`SC checks`)**:
     - Menampilkan kartu **12-Module CIS & DISA STIG Security Posture Breakdown**:
       - `CIS Benchmark (8 Controls): X/8 Compliant`
       - `DISA STIG Military (4 Controls): X/4 Compliant`
       - `Non-Compliant (FAIL): X control(s)`
       - `AI Posture Agent: SC Analysis Agent (Key AEGIS2)`
     - **Tombol `Refresh SC Scan` (`actions.runPostureScan`)**: Memicu pemindaian ulang *read-only* 12 kontrol CIS + DISA STIG secara langsung pada host dan memperbarui hasil di layar.
     - Daftar lengkap 12 kartu kontrol postur (`FindingRow`).
   - **Tab 3 (`Telemetry gaps`)**: Daftar celah waktu ketika agen pada host ini sempat terputus.

---

### 4.5 Layar 4: `DetectionsScreen` (`/detections`) — Pusat Triase Alert & Threat Hunting
File: [`dashboard/src/screens/Detections.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/Detections.tsx)
1. **Subheader Segmented Switcher**:
   - Berpindah antara **`RM alerts`** (Deteksi Serangan *Runtime*) dan **`SC checks`** (Audit Konfigurasi *Security Checker*).
2. **Quick Threat Hunting Search Bar**:
   - Input pencarian instan (`Threat Hunt: filter by IP, user, rule ID, CIS/STIG check ID, MITRE ID, or command…`) yang memfilter daftar *alert* maupun *SC checks* secara *real-time* tanpa *reload*.
3. **Multi-Dimensional Filter Chips (Pada Tab `RM alerts`)**:
   - **Host Dropdown**: `All hosts` atau pilih host spesifik.
   - **Threat Impact (Severity)**: `All Severities`, `Critical`, `High`, `Medium`, `Low`.
   - **Evidence Certainty (Confidence)**: `All Confidence`, `Confirmed (95%+)`, `High (80-94%)`, `Suspected (50-79%)`.
   - **Investigation Status**: `All Statuses`, `New`, `Investigating`, `Resolved`, `False Positive`.
4. **Filter Chips (Pada Tab `SC checks`)**:
   - **Check Result**: `Failed`, `Not checked`, `Passed`, `All`.
5. **Tabel Triase Desktop**:
   - Menampilkan `Rule & Incident Title` (beserta *pill* `X occurrences` jika terdeduplikasi), `Severity (Impact)`, `Confidence (Evidence)`, `Investigation Status`, `Host`, `Source`, `Detected`, dan tombol `Triage >`.

---

### 4.6 Layar 5: `AlertDetailScreen` (`/alerts/:id`) — Ruang Investigasi Forensik & AI Handoff
File: [`dashboard/src/screens/AlertDetail.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/AlertDetail.tsx)
Merupakan layar paling kaya fitur di AEGIS, dibagi menjadi 2 kolom besar pada desktop:

#### Kolom Kiri (Konteks, Bukti Log, Provenance, Kill-Chain, Blast Radius, Replay):
1. **Header Bukti & Badge Tri-Dimensi**:
   - Menampilkan `Severity Badge` + `Confidence Badge` + `Investigation Status Badge` + `Rule ID Tag` (`v1.0`) + judul insiden.
   - Menampilkan kotak peringatan ketidaklengkapan data apabila terdapat *Telemetry Gap* pada saat insiden terjadi.
2. **Metadata Ringkas Insiden (`KeyValues`)**:
   - `Host` (link ke halaman host), `Source`, `Detected`, `Rule` (`RULE-... v1.0`), `Alert ID`, dan `Grouping` (rentang waktu kemunculan pertama hingga terakhir jika terjadi berulang).
3. **Rule Explanation Card (`Why this alert fired`)**:
   - Menampilkan alasan deterministik (`reason`), pemetaan **MITRE ATT&CK ID & Tactic**, ekspresi kondisi matematis (`Rule Condition`), dan rasional keamanan (`Rationale`).
4. **Telemetry Provenance & Chain-of-Custody Card (`provenance-card`)**:
   - Menampilkan `Collector Agent`, `Log File Path`, `Parser Pipeline`, `Ingested At`, dan `Integrity Fingerprint (sha256:...)`.
   - **Tombol `Download Signed Evidence (.json)`**: Mengunduh paket barang bukti forensik JSON yang ditandatangani dengan hash kriptografi **SHA-256** (`GET /api/alerts/{id}/evidence-bundle`).
5. **Multi-Stage Kill-Chain Correlation Card (`KillChainCard`)**:
   - Memetakan posisi *alert* saat ini di sepanjang **6 Tahap Serangan MITRE ATT&CK**:
     1. `Reconnaissance` (`TA0043 / TA0007`)
     2. `Credential Access` (`TA0006 · Brute Force / Sniffing`)
     3. `Initial Access` (`TA0001 · Valid Accounts`)
     4. `Privilege Escalation` (`TA0004 · Sudo / Exploit`)
     5. `Persistence` (`TA0003 · Backdoor / Cron / Keys`)
     6. `Defense Evasion & Exfil` (`TA0005 / TA0010 · Anti-Forensics & Exfil`)
   - Setiap tahap menampilkan indikator warna: **Merah (`CURRENT`)** untuk tahap *alert* yang sedang dibuka, **Kuning (`OBSERVED`)** jika ada *alert* lain di host yang sama pada tahap tersebut, atau **Abu-abu (`CLEAR`)** jika belum terdeteksi.
6. **Entity Blast Radius Summary Card (`BlastRadiusCard`)**:
   - Merangkum cakupan dampak serangan pada host tersebut:
     - `Impact Scope` (Single-stage vs Multi-stage activity)
     - `Attacker / Source IPs`
     - `Targeted Accounts`
     - `Affected / Probed Files`
     - `Executed Commands`
7. **Supporting Telemetry Events (`Supporting events`)**:
   - Menampilkan setiap baris log asli yang memicu *alert* (`trigger` vs `supporting`), lengkap dengan waktu presisi (`HH:MM:SS.mmm`), tipe event, pesan log dalam font monospace, serta *tag* pasangan `key: value` (`src_ip`, `user`, `port`, `command`).
8. **Chronological Incident Replay Card (`IncidentReplayCard`)**:
   - Merekonstruksi urutan kejadian langkah demi langkah (`Reconnaissance` -> `Trigger` -> `Detection` -> `Investigation` -> `Verification`) beserta keterbatasan visibilitas telemetri.
9. **Tombol Aksi Investigasi**:
   - `View in Timeline` (Melompat ke titik waktu *alert* di layar Timeline)
   - `Start Emergency Evidence Mode` (Membuka sesi pengumpulan bukti mendalam untuk *alert* ini)

#### Kolom Kanan (Alur Kerja Operator, AI Analysis, Handoff Generator, Recovery Verification):
1. **Operator Investigation Workflow Card (`InvestigationWorkflowCard`)**:
   - Menampilkan status alur kerja saat ini (`new`, `investigating`, `handoff_ready`, `remediation_in_progress`, `resolved`, `false_positive`).
   - Menyediakan 4 tombol transisi status cepat + kolom *textarea* untuk menambahkan **Catatan Investigasi Operator (`Investigation Note`)** yang tercatat permanen di Audit Log.
2. **Grounded AI Analysis Panel (`AiPanel`)**:
   - Menjalankan **RM Analysis Agent** menggunakan slot kunci khusus **`AEGIS1`** (`POST /api/alerts/{id}/analyze`).
   - Menampilkan badge **`Key AEGIS1`**, narasi ringkasan yang diikat ke ID bukti (`Evidence Citations`), bagian `Uncertainty / Visibility Limits`, dan `Recommended Next Steps` (non-destruktif).
3. **AI Investigation & Remediation Handoff Prompt Card (`HandoffGeneratorCard`)**:
   - Menghasilkan dokumen Markdown terstruktur (`GET /api/alerts/{id}/handoff`) yang siap diberikan kepada *engineer* manusia atau agen AI perbaikan di terminal server.
   - Menampilkan pemisahan **Confirmed Facts** vs **Unverified Hypotheses**, **Read-Only Investigation Commands**, **Proposed Remediation Plan**, **Service Impact Analysis**, dan **Rollback Commands**.
   - Menyediakan 3 tombol: `Preview Markdown`, `Copy Handoff Prompt`, dan `Download .md`.
4. **Automatic Recovery Verification Card (`RecoveryVerificationCard`)**:
   - Menjalankan verifikasi pemulihan pasca-remediasi (`POST /api/alerts/{id}/verify`).
   - Menampilkan **4 Pemeriksaan Pemulihan** (`Host Agent Liveness`, `Telemetry Gap Inspection`, `Trigger Rule Recurrence`, `Correlated Anomaly Check`).
   - Menampilkan **Before vs. After Remediation Diff**: Perbandingan berdampingan antara kondisi rentan saat insiden (`Before` — merah) dan kondisi terverifikasi setelah perbaikan (`After` — hijau/kuning).

---

### 4.7 Layar 6: `FindingDetailScreen` (`/findings/:id`) — Detail Pemeriksaan Postur CIS/STIG
File: [`dashboard/src/screens/FindingDetail.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/FindingDetail.tsx)
1. **Header & Status Kepatuhan**:
   - Menampilkan badge `Failed · High/Medium` atau `Passed` atau `Not checked` beserta `Check ID` (`CIS-...` atau `STIG-...`).
2. **Observed Indicators (`Observed indicators`)**:
   - Menampilkan daftar temuan faktual dari pembacaan file konfigurasi Linux (contoh: `/etc/ssh/sshd_config: PermitRootLogin prohibit-password`, `/var/www/html: mode 0777`).
3. **Inspection Limits (`What this check cannot see`)**:
   - Menjelaskan batas kemampuan inspeksi *read-only* (misalnya: tidak memodifikasi file atau mengecek ACL eksternal).
4. **SC AI Analysis Panel (`AiPanel`)**:
   - Menjalankan **SC Analysis Agent** menggunakan slot kunci khusus **`AEGIS2`** (`POST /api/findings/{id}/analyze`) untuk memberikan panduan *hardening* Linux yang aman beserta analisis dampak layanan.

---

### 4.8 Layar 7: `TimelineScreen` (`/timeline`) — Linimasa Kronologis Forensik
File: [`dashboard/src/screens/Timeline.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/Timeline.tsx)
1. **Filter & Threat Hunting Search Bar**:
   - **Host Dropdown**: `All hosts` atau per host.
   - **Threat Hunting Search Input**: Filter seluruh *event*, *alert*, dan *gap* berdasarkan IP, *username*, *command*, atau *rule ID*.
   - **Time Range Chips**: `6 h`, `24 h`, `7 days`.
   - **Sort Order Toggle (`ArrowDownUp`)**: Urutkan dari terlama ke terbaru (`oldest first` — cocok untuk membaca alur serangan dari awal) atau terbaru ke terlama (`newest first`).
2. **Visualisasi Linimasa Terpadu**:
   - Menggabungkan 3 jenis entitas dalam satu garis waktu vertikal:
     - **Telemetry Event (`tl-item--event`)**: Menampilkan jam presisi (`HH:MM:SS`), badge sumber log, tipe event, baris pesan monospace, dan *field tags*.
     - **Deterministic Alert (`tl-item--alert`)**: Kotak berbingkai warna *severity* yang dapat diklik menuju detail *alert*.
     - **Telemetry Gap (`tl-item--gap`)**: Blok berarsir diagonal yang menandai periode waktu saat log terputus.

---

### 4.9 Layar 8: `EvidenceScreen` (`/evidence`) — Mode Bukti Darurat (Emergency Evidence Mode)
File: [`dashboard/src/screens/Evidence.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/Evidence.tsx)
1. **Fungsi Utama**:
   - Mengaktifkan pengumpulan bukti forensik berfrekuensi tinggi yang dibatasi waktu (*time-boxed*: 15, 30, atau 60 menit) pada host yang sedang mengalami insiden aktif tanpa membebani ruang penyimpanan secara permanen.
2. **Formulir Aktivasi (`Start Emergency Evidence Mode`)**:
   - Pilih `Target Host`, `Duration` (`15 min`, `30 min`, `60 min`), `Data Types to Capture` (`Active network sockets (ss -tupn)`, `Process tree snapshot (ps auxf)`, `Open file descriptors (lsof)`, `Recent auth & sudo journal context`), dan `Operator Reason` (wajib diisi untuk jejak audit).
3. **Manajemen Sesi Aktif & Riwayat**:
   - Menampilkan hitung mundur waktu kedaluwarsa (`Expires in X min`), jumlah *snapshot* yang terkumpul, serta tombol `End session early` (`POST /api/evidence/{id}/stop`).

---

### 4.10 Layar 9 & 10: `ReportsScreen` (`/reports`) & `ReportDetailScreen` (`/reports/:id`) — Laporan Harian, Insiden & Ekspor PDF
File: [`dashboard/src/screens/Reports.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/Reports.tsx) dan [`dashboard/src/screens/ReportDetail.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/ReportDetail.tsx)
1. **Pembuatan Laporan Baru (`Request Report Sheet`)**:
   - Pilih tipe laporan: **`Daily security report`** atau **`Incident forensics report`**.
   - Pilih cakupan host (`All hosts` atau host tertentu) dan rentang tanggal periode laporan.
   - Saat dibuat (`POST /api/reports`), backend memanggil **Reporting Agent** yang menggunakan slot kunci khusus **`AEGIS3`** untuk menyusun ringkasan eksekutif (*Executive Summary*) yang diikat 100% ke data *alert* dan *posture* yang tersimpan.
2. **Halaman Detail Laporan (`ReportDetailScreen`)**:
   - Menampilkan metadata laporan (`Report ID`, `Type`, `Period`, `Generated At`, `AI Key Slot: AEGIS3`, jumlah `Alerts`, `Failed SC Checks`, dan `Telemetry Gaps`).
   - Menampilkan **Executive Summary** hasil sintesis agen `AEGIS3`.
   - Menampilkan rincian seluruh *Alert* dan *Failed Checks* yang tercakup dalam periode laporan.
   - **Tombol `Download Official PDF Report`**: Mengunduh dokumen PDF biner asli (`GET /api/reports/{id}/pdf`) yang dirender oleh mesin `reportlab` di backend lengkap dengan kop laporan, tabel metrik, tabel insiden, dan tabel kepatuhan postur.

---

### 4.11 Layar 11: `AuditLogScreen` (`/audit`) — Jejak Audit Aktivitas Operator
File: [`dashboard/src/screens/AuditLog.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/AuditLog.tsx)
- Mencatat setiap tindakan sensitif yang dilakukan di dalam platform (`system_startup`, `request_analysis`, `generate_handoff`, `verify_recovery`, `update_investigation`, `start_evidence_session`, `stop_evidence_session`, `request_report`, `run_sc_scan`, `ingest_posture`).
- Dilengkapi filter berdasarkan jenis aksi (`All Actions`, `AI Analysis`, `Handoff`, `Verification`, `Investigation`, `Evidence Mode`, `Reports`) sehingga mendukung kepatuhan audit komando militer.

---

### 4.12 Layar 12: `SettingsScreen` (`/settings`) — Pengaturan Tampilan, Zona Waktu & Status 3-Kunci AI
File: [`dashboard/src/screens/Settings.tsx`](file:///d:/Projects/School/aegis/dashboard/src/screens/Settings.tsx)
1. **Appearance (Theme Switcher)**:
   - Pilihan `Light` (*Warm Ivory*), `Dark` (*Obsidian Jade*), atau `System`.
2. **Time & Timestamps**:
   - **Timezone Switcher**: `Local time` (WIB / zona waktu browser) atau `UTC` (standar forensik internasional).
   - **Relative Timestamps Toggle**: Menampilkan waktu relatif (`2m ago`) disertai waktu absolut saat di-*hover*.
3. **3-Key AI Role Allocation & Failover Card**:
   - Menampilkan status langsung dari ketiga slot API Key (`GET /api/system/ai-roles`):
     - **`AEGIS1` -> RM Analysis & Incident Investigation Agent** (Failover: `AEGIS2 -> AEGIS3`)
     - **`AEGIS2` -> SC Security Posture Analysis Agent** (Failover: `AEGIS1 -> AEGIS3`)
     - **`AEGIS3` -> Dedicated Daily & Incident Reporting Agent** (Failover: `AEGIS2 -> AEGIS1`)
   - Menampilkan *masked preview* (`AIza...xxxx`) tanpa pernah membocorkan kunci asli ke frontend.
4. **System Health & Architecture Boundaries**:
   - Menampilkan status kesehatan `Telemetry Collector`, `Deterministic Rules Engine`, dan `AI Provider`, serta pengingat batasan operasional *read-only* AEGIS.

---

## BAB 5: ARSITEKTUR AGEN TELEMETRI LINUX (`AegisTelemetryCollector`) & MEKANISME TWO-PHASE CURSOR COMMIT

File: [`aegis_agent/collector.py`](file:///d:/Projects/School/aegis/aegis_agent/collector.py)

### 5.1 Cara Kerja Daemon Kolektor
1. **Hak Akses Minimum (*Least Privilege*)**:
   - Berjalan sebagai layanan systemd (`aegis-collector.service`) menggunakan akun non-root yang tergabung dalam grup `adm` atau `systemd-journal` untuk membaca log secara *read-only*.
2. **Two-Phase Cursor Commit (Anti Kehilangan Log Saat Jaringan Putus)**:
   - **Fase 1 (Read & Extract Cursor)**: Kolektor menjalankan `journalctl --after-cursor=<cursor_terakhir> -n 200 --no-pager --show-cursor`. Baris log baru diekstrak ke memori beserta string `pending_cursor` terbaru, namun file `.collector_cursor` di disk **belum diperbarui**.
   - **Fase 2 (Sanitize & Transmit)**: Baris log disanitasi oleh `TelemetrySanitizer`, lalu dikirim via `POST /api/telemetry/ingest` dengan header `X-Agent-Token`.
   - **Commit Atomik**: Hanya jika backend mengembalikan **HTTP 200 OK**, kolektor menulis `pending_cursor` ke file sementara `.collector_cursor.tmp` dengan mode izin ketat `0600`, lalu melakukan operasi atomik `replace()` ke `.collector_cursor`. Jika jaringan putus atau backend mengembalikan *error*, kursor tidak diubah sehingga pada siklus berikutnya (15 detik kemudian) log yang gagal terkirim akan dikirim ulang tanpa ada satu baris pun yang hilang.
3. **Tiga Tugas Siklus Kolektor**:
   - **Incremental Log Ingest** (setiap `AEGIS_POLL_INTERVAL` = 15 detik) -> `POST /api/telemetry/ingest`
   - **Host Heartbeat Ping** (setiap `AEGIS_HEARTBEAT_INTERVAL` = 60 detik) -> `POST /api/telemetry/heartbeat`
   - **Live 12-Control SC Posture Scan** (saat *startup* dan setiap `AEGIS_POSTURE_INTERVAL` = 300 detik) -> `POST /api/telemetry/posture`

---

## BAB 6: MESIN NORMALISASI LOG MULTI-SUMBER (`LinuxTelemetryParser`) & PRE-TRANSMISSION SANITIZER

### 6.1 Pre-Parsing Secret Sanitizer (`aegis_backend/sanitizer.py`)
Sebelum baris log diparse atau disimpan ke database, [`TelemetrySanitizer.inspect_line()`](file:///d:/Projects/School/aegis/aegis_backend/sanitizer.py) memeriksa pola sensitif berikut dan langsung mengkarantina baris yang melanggar:
- Kunci Privat SSH/TLS (`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
- Hash Password `/etc/shadow` (`$6$...`, `$y$...`, `$2b$...`)
- Token API & Bearer (`Bearer <token>`, `sk-...`, `AIzaSy...`, `ghp_...`)
- Parameter Password eksplisit (`password=...`, `passwd=...`, `secret=...`)

### 6.2 Urutan Prioritas Parser Multi-Sumber (`aegis_agent/linux_parser.py`)
[`LinuxTelemetryParser.parse_line()`](file:///d:/Projects/School/aegis/aegis_agent/linux_parser.py#L25-L75) menormalisasi 8 sumber log Linux ke dalam kontrak data standar `LogEventInput` sesuai urutan spesifisitas berikut:
1. **`_parse_sshd_log`**: Menangkap `Failed password` (`auth_failure`), `Accepted password/publickey` (`auth_success`), dan `pam_unix(sshd:session): session opened/closed` (`session_opened` / `session_closed`).
2. **`_parse_ssh_key_tamper_log`**: Menangkap modifikasi file sensitif (`authorized_keys`, `/etc/ssh/sshd_config`, `/etc/sudoers`) via `tee`, `echo >>`, `sed`, `vim`, `chmod`, `cp`, `mv` -> menghasilkan event `critical_file_modified`.
3. **`_parse_defense_apt_log`**: Menangkap 3 indikator serangan tingkat lanjut (APT / Militer):
   - Penghapusan jejak forensik (`history -c`, `unset HISTFILE`, `shred`, `truncate -s 0`, `rm -rf /var/log`, `journalctl --vacuum-time`) -> `anti_forensics_execution`.
   - Eksfiltrasi & pengarsipan data sensitif (`tar`/`zip`/`7z` pada `/etc`, `/var/www`, `/root`, `/home` atau transfer keluar `scp`, `rsync`, `curl -F`, `curl --upload-file`, `wget --post-file`) -> `data_exfiltration_attempt`.
   - Pemuatan modul kernel *rootkit* & penyadapan jaringan (`entered promiscuous mode`, `insmod`, `modprobe`, `rmmod audit`, `tcpdump -i`) -> `rootkit_or_sniff_activity`.
4. **`_parse_sudo_log`**: Menangkap eksekusi perintah sudo (`sudo_execution`) dan kegagalan autentikasi sudo (`sudo_auth_failure`).
5. **`_parse_auditd_log`**: Menangkap log kernel Auditd `type=SYSCALL` (`process_execution`) dan `type=EXECVE` (`process_cmdline`).
6. **`_parse_network_conn`**: Menangkap *snapshot* soket jaringan `ss -nt` / `netstat -nt` (`network_connection`).
7. **`_parse_account_management_log`**: Menangkap pembuatan akun baru via `useradd`/`adduser` (`account_created`), penambahan user ke grup berhak istimewa via `usermod`/`gpasswd` (`privilege_group_added`), dan perubahan password (`password_changed`).
8. **`_parse_firewall_or_kernel_log`**: Menangkap pemblokiran paket oleh firewall `[UFW BLOCK]` (`firewall_block`) dan kerusakan memori proses di kernel `segfault at ...` (`kernel_segfault`).
9. **`_parse_cron_or_systemd_log`**: Menangkap eksekusi tugas terjadwal `CRON[pid]: (user) CMD (...)` (`cron_execution`) dan penghentian layanan oleh systemd `Deactivated successfully` / `Stopped ...` (`service_stopped`).
10. **`_parse_web_log`**: Mem-parsing log akses Nginx/Apache Combined Format dengan **Smart Pre-Filtering** (mengabaikan request statis normal HTTP 200/304 dan hanya menangkap indikator serangan `path_traversal`, `sensitive_file_probe`, `sql_injection`, `command_injection`, `scanner_user_agent`, atau *burst* error HTTP 401/403/5xx).

---

## BAB 7: SPESIFIKASI LENGKAP 13 RULE DETERMINISTIK RUNTIME MONITOR (RM) & PEMETAAN MITRE ATT&CK

Seluruh aturan deteksi diimplementasikan secara deterministik di [`aegis_backend/rules_engine.py`](file:///d:/Projects/School/aegis/aegis_backend/rules_engine.py) dan dilengkapi metadata investigasi/remediasi di [`aegis_backend/incident_service.py`](file:///d:/Projects/School/aegis/aegis_backend/incident_service.py#L61-L365). Setiap *alert* memiliki ID deterministik berbasis hash (`SHA-256`) sehingga bersifat **idempoten** (tidak pernah menghasilkan *alert* ganda jika batch log yang sama dievaluasi ulang).

| No | Rule ID | Nama Insiden | MITRE ATT&CK | Severity | Kondisi Pemicu Deterministik (Trigger Condition) | Tahap Kill-Chain |
| :-: | :--- | :--- | :--- | :---: | :--- | :--- |
| **1** | `RULE-SSH-BRUTE` | SSH Repeated Authentication Failures (Brute-Force) | `T1110.001` (Password Guessing) | `HIGH` | Minimal **3 event `auth_failure`** dalam jendela geser **300 detik (5 menit)** pada `host_id` yang sama, dikorelasi secara terpisah berdasarkan `source_ip` atau `target_user`. | Credential Access |
| **2** | `RULE-AUTH-003` | Multiple Failed Logins Followed by Success | `T1078` / `T1110` (Valid Accounts) | `HIGH` | Event **`auth_success`** yang didahului oleh minimal **1 `auth_failure`** dalam **600 detik (10 menit)** dengan identitas `source_ip` atau `user_name` yang konsisten pada host yang sama. | Initial Access |
| **3** | `RULE-SUSP-SUDO` | Suspicious Sudo Execution / Privilege Escalation | `T1548.003` (Sudo Abuse) | `HIGH` / `MEDIUM` | - Eksekusi *interactive root shell* (`bash`, `sh`, `zsh`, `su`) atau *remote script* (`curl/wget \| bash`, `python -c`) via sudo -> `HIGH`.<br>- Perubahan izin berisiko (`chmod 777`) via sudo -> `MEDIUM`.<br>- Minimal **3 `sudo_auth_failure`** dalam 300 detik -> `HIGH`. | Privilege Escalation |
| **4** | `RULE-WEB-ATTACK` | Web Application Exploit Probe / HTTP Auth Burst | `T1190` (Exploit Public-Facing App) | `CRITICAL` / `HIGH` / `MEDIUM` | - Probe `command_injection` (`;cat`, `\|wget`, `${jndi:}`) atau `sql_injection` (`UNION SELECT`) -> `CRITICAL`.<br>- Probe `path_traversal` (`../etc/passwd`) atau `sensitive_file_probe` (`/.env`, `/.git`, `/wp-config`) -> `HIGH`.<br>- Scanner UA (`sqlmap`, `nikto`, `nuclei`) atau >=4 HTTP 401/403 dalam 300 detik -> `MEDIUM`. | Reconnaissance |
| **5** | `RULE-ACCT-BACKDOOR` | Rogue Account Creation / Privileged Group Escalation | `T1136.001` / `T1098` (Create Account) | `CRITICAL` / `HIGH` | - Pembuatan akun baru dengan **`UID=0`** -> `CRITICAL`.<br>- Pembuatan akun lokal baru (`useradd`/`adduser`) -> `HIGH`.<br>- Penambahan user ke grup `sudo`, `root`, `wheel`, `admin`, `docker`, `shadow` -> `CRITICAL`. | Persistence |
| **6** | `RULE-FW-PORTSCAN` | UFW Firewall Port Scan / Reconnaissance Burst | `T1046` (Network Service Discovery) | `MEDIUM` | Minimal **4 event `firewall_block` (`[UFW BLOCK]`)** dari `source_ip` yang sama dalam jendela **300 detik**. | Reconnaissance |
| **7** | `RULE-KERNEL-EXPLOIT` | Kernel Segmentation Fault / Binary Crash Anomaly | `T1068` (Exploitation for PrivEsc) | `HIGH` | Munculnya event `kernel_segfault` (`segfault at ... ip ...`) pada proses daemon atau biner sistem. | Privilege Escalation |
| **8** | `RULE-CRON-PERSIST` | Suspicious Scheduled Cron Persistence Execution | `T1053.003` (Scheduled Task: Cron) | `HIGH` | Eksekusi `cron_execution` yang mengandung indikator *payload* berbahaya (`curl`, `wget`, `nc`, `ncat`, `bash -i`, `/dev/tcp/`, `base64 -d`, `/tmp/`, `/dev/shm/`, `python -c`). | Persistence |
| **9** | `RULE-DEFENSE-EVASION` | Critical Security Service Stopped (Defense Evasion) | `T1562.001` (Disable or Modify Tools) | `CRITICAL` | Penghentian (`service_stopped`) layanan keamanan kritis: `ufw`, `auditd`, `ssh`/`sshd`, `fail2ban`, `apparmor`, `aegis-collector`, atau `rsyslog`. | Defense Evasion & Exfil |
| **10** | `RULE-SSH-KEY-BACKDOOR` | Critical Security File / SSH Authorized Keys Tampering | `T1098.004` (SSH Authorized Keys) | `CRITICAL` | Modifikasi terhadap file `~/.ssh/authorized_keys`, `/etc/ssh/sshd_config`, atau `/etc/sudoers` (`critical_file_modified`). | Persistence |
| **11** | `RULE-ANTI-FORENSICS` | Anti-Forensics Log Wiping & History Erasure | `T1070` (Indicator Removal on Host) | `CRITICAL` | Eksekusi perintah penghapusan jejak (`history -c`, `unset HISTFILE`, `shred`, `truncate -s 0 /var/log`, `rm -rf /var/log`, `journalctl --vacuum-time`, `> /var/log/auth.log`). | Defense Evasion & Exfil |
| **12** | `RULE-DATA-EXFIL` | Sensitive Data Staging & Outbound Exfiltration | `T1041` / `T1560` (Exfiltration Over C2) | `CRITICAL` | Pengarsipan direktori sensitif (`tar`/`zip`/`7z` pada `/etc/shadow`, `/etc/ssh`, `/var/www`, `/root`, `.sql`, `.env`) atau pengiriman keluar via `scp`, `rsync`, `curl -F`, `curl --upload-file`, `wget --post-file`. | Defense Evasion & Exfil |
| **13** | `RULE-ROOTKIT-SNIFF` | Kernel Rootkit Module Load / Promiscuous Sniffing | `T1547.006` / `T1040` (Kernel Modules & Sniffing) | `CRITICAL` | Interface jaringan masuk ke mode sadap (`device <iface> entered promiscuous mode`) atau eksekusi pemuatan modul kernel (`insmod`, `modprobe`, `rmmod audit`, `tcpdump -i`). | Credential Access |

---

## BAB 8: SPESIFIKASI LENGKAP 12 MODUL READ-ONLY SECURITY CHECKER (8 CIS UBUNTU BENCHMARK + 4 DISA STIG MILITER)

Diimplementasikan di [`aegis_agent/security_checker.py`](file:///d:/Projects/School/aegis/aegis_agent/security_checker.py). Seluruh pemeriksaan berjalan dalam mode **100% Read-Only** (tidak pernah mengubah konfigurasi server) dan mengevaluasi kepatuhan terhadap gabungan standar **CIS Ubuntu Linux 24.04 LTS Benchmark** serta standar pertahanan militer **DISA STIG (Defense Information Systems Agency — Security Technical Implementation Guide)**:

### 8.1 Kelompok 1: 8 Kontrol CIS Ubuntu Server Benchmark
1. **`CIS-SSH-5.2.8` — SSH Daemon Root Login & Authentication Hardening**:
   - **File yang Diperiksa**: `/etc/ssh/sshd_config`
   - **Parameter Evaluasi**: Memastikan `PermitRootLogin no`, `PasswordAuthentication no`, `PermitEmptyPasswords no`, dan `MaxAuthTries <= 4`.
2. **`CIS-PERM-6.1.2` — Critical File & Web Root (`/var/www/html`) Permission Hygiene**:
   - **File yang Diperiksa**: `/etc/shadow` (maks `0640`), `/etc/passwd` (maks `0644`), `/etc/sudoers` (maks `0440`), dan `/var/www/html` (maks `0755`, mendeteksi jika ada izin *world-writable* `0777`).
3. **`CIS-PRIV-5.3.4` — Sudoers NOPASSWD Scope & Non-Root UID 0 Account Audit**:
   - **File yang Diperiksa**: `/etc/passwd` dan `/etc/sudoers.d/*`
   - **Parameter Evaluasi**: Memastikan hanya akun `root` yang memiliki `UID 0` dan mendeteksi aturan `NOPASSWD:ALL` yang terlalu longgar.
4. **`CIS-SUID-6.1.12` — Dangerous SUID/SGID GTFOBins Binary Audit**:
   - **Path yang Diperiksa**: `/bin`, `/sbin`, `/usr/bin`, `/usr/local/bin`
   - **Parameter Evaluasi**: Memastikan biner interaktif (`bash`, `python3`, `find`, `vim`, `cp`, `nano`) tidak memiliki bit SUID/SGID yang dapat disalahgunakan untuk eskalasi hak akses.
5. **`CIS-NET-3.5.1` — Network Socket Exposure & Cloudflare Zero-Trust Firewall Posture**:
   - **Target yang Diperiksa**: Soket jaringan lokal (`ss -tuln`) dan layanan `cloudflared.service`.
   - **Parameter Evaluasi**: Memastikan API internal FastAPI (`:8000`) hanya terikat ke *loopback* `127.0.0.1` (bukan `0.0.0.0`) dan *ingress* dilindungi oleh terowongan Zero-Trust Cloudflare / UFW.
6. **`CIS-SYSCTL-3.3.1` — Kernel ASLR, TCP SYN Cookies & SUID Core Dump Hardening**:
   - **Target yang Diperiksa**: Parameter kernel `/proc/sys/...` dan `/etc/sysctl.d/`.
   - **Parameter Evaluasi**: Memastikan `kernel.randomize_va_space = 2` (Full ASLR), `net.ipv4.tcp_syncookies = 1` (proteksi SYN flood), dan `fs.suid_dumpable = 0`.
7. **`CIS-PKG-1.9` — Unattended Security Updates & Pending Patch Posture**:
   - **Target yang Diperiksa**: `/etc/apt/apt.conf.d/20auto-upgrades` dan status `unattended-upgrades.service`.
   - **Parameter Evaluasi**: Memastikan pembaruan keamanan otomatis aktif (`APT::Periodic::Unattended-Upgrade "1"`).
8. **`CIS-PERSIST-5.1.8` — Cron & Systemd Timer Persistence Hygiene Check**:
   - **Target yang Diperiksa**: `/etc/crontab`, `/etc/cron.d/*`, dan `/etc/cron.*`.
   - **Parameter Evaluasi**: Memastikan direktori cron dimiliki oleh `root:root` dengan izin ketat dan bebas dari referensi skrip di `/tmp` atau `/dev/shm`.

### 8.2 Kelompok 2: 4 Kontrol Militer DISA STIG (Pertahanan Siber / TNI AD)
9. **`STIG-BANNER-8.1` — Military Legal Warning Banner & Pre-Login OS Information Leakage**:
   - **File yang Diperiksa**: `/etc/issue` dan `/etc/issue.net`
   - **Parameter Evaluasi**:
     1. Memastikan banner pra-login **tidak membocorkan versi OS/kernel** (mendeteksi kode *escape* `\v`, `\r`, `\m`, `\n` atau string `Ubuntu 24.04` yang memudahkan penyerang mencari CVE spesifik).
     2. Memastikan terdapat **peringatan hukum otorisasi pertahanan/militer** (`authorized`, `restricted`, `monitoring`, `militer`, `tni`, `pertahanan`).
10. **`STIG-CRYPTO-5.2` — DISA STIG SSH Strong Cryptographic Ciphers, MACs & KexAlgorithms**:
    - **File yang Diperiksa**: `/etc/ssh/sshd_config`
    - **Parameter Evaluasi**: Memastikan algoritma kriptografi lemah/usang (`3des-cbc`, `aes128-cbc`, `aes256-cbc`, `arcfour`, `hmac-md5`, `hmac-sha1`) tidak diaktifkan, dan hanya cipher AEAD modern (`chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`) yang digunakan.
11. **`STIG-AUDIT-4.1` — Audit Log Tamper Protection & Persistent Systemd-Journald Storage**:
    - **Target yang Diperiksa**: Direktori `/var/log/journal` dan `/etc/systemd/journald.conf`.
    - **Parameter Evaluasi**: Memastikan penyimpanan log bersifat **persisten lintas *reboot*** (`Storage=persistent` atau keberadaan `/var/log/journal`) sehingga penyerang tidak dapat menghapus jejak log hanya dengan me-*reboot* server.
12. **`STIG-MEDIA-1.1` — Unauthorized USB Mass Storage Kernel Module Lockdown (BadUSB / Physical Exfil)**:
    - **File yang Diperiksa**: `/etc/modprobe.d/*.conf`
    - **Parameter Evaluasi**: Memeriksa apakah modul kernel penyimpanan USB (`usb-storage`) telah diblokir secara eksplisit (`blacklist usb-storage` atau `install usb-storage /bin/true`) guna mencegah pencurian data fisik via flashdisk atau serangan *BadUSB* pada server komando/lapangan.

---

## BAB 9: ARSITEKTUR ORKESTRASI MULTI-AGENT AI 3-KUNCI (`AEGIS1`, `AEGIS2`, `AEGIS3`) & AUTOMATIC CROSS-KEY FAILOVER

Diimplementasikan di [`aegis_backend/config.py`](file:///d:/Projects/School/aegis/aegis_backend/config.py), [`aegis_agent/providers.py`](file:///d:/Projects/School/aegis/aegis_agent/providers.py), dan [`aegis_backend/incident_service.py`](file:///d:/Projects/School/aegis/aegis_backend/incident_service.py).

### 9.1 Pembagian Tugas 3 API Key Gemini
Untuk mencegah habisnya kuota (*rate-limit exhaustion* `HTTP 429`) ketika sistem memproses *alert* secara bersamaan dengan pembuatan laporan harian, AEGIS membagi 3 API Key di `.env` ke dalam 3 agen spesialis:

| Slot Kunci `.env` | Nama Agen Spesialis | Tugas & Endpoint yang Dilayani | Rantai Failover Otomatis (`get_role_key_chain`) |
| :---: | :--- | :--- | :---: |
| **`AEGIS1`** | **RM Analysis & Incident Investigation Agent** | Menganalisis *Runtime Monitor Alerts*, mengkorelasi bukti log SSH/Sudo/Web/APT, dan menyusun langkah investigasi *read-only* (`POST /api/alerts/{id}/analyze`). | `AEGIS1` ➔ `AEGIS2` ➔ `AEGIS3` |
| **`AEGIS2`** | **SC Security Posture Analysis Agent** | Menganalisis temuan *Security Checker* (12 modul CIS + DISA STIG), menjelaskan risiko konfigurasi, dan menyusun panduan *hardening* (`POST /api/findings/{id}/analyze`). | `AEGIS2` ➔ `AEGIS1` ➔ `AEGIS3` |
| **`AEGIS3`** | **Dedicated Daily & Incident Reporting Agent** | **Khusus (Dedicated)** untuk menyusun *Executive Summary* pada Laporan Keamanan Harian (*Daily Report*) dan Laporan Forensik Insiden (`POST /api/reports`). | `AEGIS3` ➔ `AEGIS2` ➔ `AEGIS1` |

### 9.2 Mekanisme Automatic Cross-Key Failover & Degraded Fallback
1. Saat sebuah agen dipanggil (misal **Reporting Agent** dengan kunci utama `AEGIS3`), [`RealLLMAdapter`](file:///d:/Projects/School/aegis/aegis_agent/providers.py) mencoba memanggil Gemini API menggunakan `AEGIS3`.
2. Apabila `AEGIS3` mengalami *timeout*, *rate-limit* (`HTTP 429`), atau gangguan jaringan, `RealLLMAdapter` secara otomatis beralih (*failover*) ke kunci cadangan pertama (`AEGIS2`), lalu ke kunci cadangan kedua (`AEGIS1`) dalam satu siklus permintaan yang sama tanpa gagal.
3. Apabila seluruh koneksi internet ke Gemini terputus total, AEGIS memiliki **Grounded Deterministic Synthesis Fallback** yang tetap menghasilkan ringkasan faktual berdasarkan data *alert* dan indikator postur yang tersimpan di database, sehingga operator tidak pernah menghadapi layar kosong.

---

## BAB 10: SISTEM ANTI-HALUSINASI AI, EPISTEMIC SEPARATION & BACKEND GATEKEEPER

AEGIS dilengkapi lapisan pengaman berlapis pada modul AI (`aegis_agent/`) untuk menjamin AI tidak pernah berhalusinasi:

1. **Surgical Evidence Citation Validator (`aegis_agent/evidence.py` & `aegis_agent/sc_validator.py`)**:
   - Memeriksa setiap ID bukti (`evidence_refs`) yang dikutip oleh LLM.
   - Jika LLM mengutip ID event yang tidak ada di dalam database (*phantom evidence*) atau milik host yang berbeda (*cross-host contamination*), klaim tersebut langsung dikarantina secara bedah (*surgical invalidation*) tanpa merusak klaim lain yang valid.
2. **Quantitative Fidelity Verification (`aegis_agent/evidence_grounding.py`)**:
   - Memastikan kesesuaian kuantitatif antara jumlah log sebenarnya dan narasi AI (misal: jika hanya ada 1 kegagalan login, AI dilarang mengklaim terjadi *"multiple/repeated failures"*).
3. **Backend Gatekeeper (`aegis_agent/tools.py`)**:
   - Membatasi jumlah pemanggilan *tool* investigasi AI (*investigation budget limit*), menolak pergeseran konteks ke host yang tidak berwenang (*unauthorized context shift*), dan menyensor argumen perintah sensitif.
4. **Severity Freeze Enforcement**:
   - Jika output JSON dari LLM mencoba mengubah tingkat `severity` yang telah ditetapkan oleh `RulesEngine`, validator secara otomatis menimpa kembali nilai tersebut dengan `severity` asli dari `RulesEngine`.

---

## BAB 11: FITUR INVESTIGASI TINGKAT LANJUT, HANDOFF & FORENSIK

1. **Multi-Stage Kill-Chain Correlation (`build_alert_context` — `GET /api/alerts/{id}/context`)**:
   - Mengkorelasikan seluruh *alert* yang terjadi pada host yang sama ke dalam 6 tahapan serangan MITRE ATT&CK (`Reconnaissance`, `Credential Access`, `Initial Access`, `Privilege Escalation`, `Persistence`, `Defense Evasion & Exfil`).
2. **Entity Blast Radius Summary**:
   - Mengekstrak secara otomatis seluruh IP penyerang, akun user yang menjadi target, file sistem yang disentuh (`/etc/ssh/sshd_config`, `/var/www/html`, `authorized_keys`), dan daftar perintah yang dieksekusi dari seluruh bukti telemetri yang terhubung.
3. **Portable AI Investigation & Remediation Handoff Prompt (`generate_handoff_markdown` — `GET /api/alerts/{id}/handoff`)**:
   - Menghasilkan dokumen Markdown standar industri dengan 8 bagian wajib:
     1. *Mandatory Operating Rules for Receiving AI Agent* (Aturan wajib bagi agen AI penerima: investigasi dulu, dilarang eksekusi merusak tanpa izin, jaga barang bukti, wajib sertakan *rollback*).
     2. *Host & Environment Context Table*.
     3. *Triggered Alert & Deterministic Rule Context (MITRE ATT&CK)*.
     4. *Supporting Telemetry Evidence (Sanitized)*.
     5. *Epistemic Separation: Confirmed Facts `[FACT]` vs. Unverified Hypotheses `[HYPOTHESIS - UNVERIFIED]` vs. Missing Telemetry `[MISSING/UNKNOWN]`*.
     6. *Step-by-Step Read-Only Investigation Commands*.
     7. *Safe Remediation Plan, Service Impact Analysis & Rollback Instructions*.
     8. *Post-Remediation Recovery Verification Instructions*.
4. **Automatic Recovery Verification & Before/After Remediation Diff (`verify_alert_recovery` — `POST /api/alerts/{id}/verify`)**:
   - Mengevaluasi apakah host benar-benar online, tidak ada *telemetry gap* terbuka, dan aturan pemicu tidak berulang selama jendela observasi (15 menit).
   - Menghasilkan tabel **`remediation_diff`** (`Target Resource`, `Before State (Incident)`, `After State (Current)`, dan `Status`).
5. **Cryptographically Signed SHA-256 Forensic Evidence Bundle (`GET /api/alerts/{id}/evidence-bundle`)**:
   - Menghasilkan bundel JSON barang bukti forensik di mana setiap *event* di-hash secara individual dengan `SHA-256` (`event_sha256`), lalu seluruh bundel disegel dengan `manifest_sha256` untuk menjamin keutuhan rantai barang bukti (*chain-of-custody*) di pengadilan militer/audit.
6. **Binary PDF Security Report Generator (`generate_report_pdf_bytes` — `GET /api/reports/{id}/pdf`)**:
   - Menggunakan pustaka `reportlab` untuk merender dokumen PDF resmi berformat A4 lengkap dengan header AEGIS, metadata laporan, *Executive Summary* dari agen `AEGIS3`, tabel metrik ringkasan, tabel *Deterministic Alerts*, dan tabel *Security Checker Posture Controls*.

---

## BAB 12: KATALOG LENGKAP SELURUH ENDPOINT REST API BACKEND FASTAPI

Seluruh endpoint didefinisikan di [`aegis_backend/main.py`](file:///d:/Projects/School/aegis/aegis_backend/main.py) beserta router di `aegis_backend/routers/`:

| No | Method | Path Endpoint | Autentikasi | Fungsi & Deskripsi Lengkap |
| :-: | :---: | :--- | :---: | :--- |
| **1** | `GET` | `/` | Public | Informasi dasar layanan backend AEGIS & versi API. |
| **2** | `GET` | `/api/health` | Public | Pemeriksaan kesehatan proses FastAPI (`status: ok`). |
| **3** | `GET` | `/api/health/database` | Public | Pemeriksaan konektivitas dan latensi (ms) ke database Supabase PostgreSQL. |
| **4** | `GET` | `/api/system-status` | Public | Status komponen inti (`collector`, `rules_engine`, `ai_provider`). |
| **5** | `GET` | `/api/system/pipeline-health` | Public | Metrik kesehatan *stream* telemetri per sumber (`ssh-auth`, `auditd`, `systemd`). |
| **6** | `GET` | `/api/system/ai-roles` | Public | Status alokasi 3 API Key (`AEGIS1`, `AEGIS2`, `AEGIS3`), peran agen, dan rantai *failover*. |
| **7** | `POST` | `/api/telemetry/ingest` | `X-Agent-Token` | Menerima batch log mentah dari agen Linux, menjalankan sanitasi rahasia, mem-parsing log, meng-upsert host, menyimpan event, dan mengevaluasi 13 rule deterministik. |
| **8** | `POST` | `/api/telemetry/heartbeat` | `X-Agent-Token` | Menerima ping *heartbeat* periodik dari agen Linux dan memperbarui `last_data_at` serta `agent_status = online`. |
| **9** | `POST` | `/api/telemetry/posture` | `X-Agent-Token` | Menerima hasil pemindaian langsung 12 modul CIS + DISA STIG dari agen Linux (`send_posture`). |
| **10** | `GET` | `/api/hosts` | Operator | Daftar seluruh host yang dipantau dengan paginasi (`limit`, `offset`) dan filter `status`. |
| **11** | `GET` | `/api/hosts/{host_id}` | Operator | Detail metadata satu host spesifik. |
| **12** | `GET` | `/api/alerts` | Operator | Daftar seluruh *alert* deterministik dengan filter `host_id` dan `severity`. |
| **13** | `GET` | `/api/alerts/{alert_id}` | Operator | Detail satu *alert* spesifik. (Catatan: `PUT`/`PATCH` sengaja tidak disediakan demi imutabilitas `severity`). |
| **14** | `GET` | `/api/alerts/{alert_id}/evidence` | Operator | Daftar event telemetri pendukung (`trigger` & `supporting`) untuk suatu *alert* dengan sensor kredensial otomatis. |
| **15** | `POST` | `/api/alerts/{alert_id}/analyze` | Operator | Menjalankan **RM Analysis Agent (`AEGIS1`)** pada *alert* dan menyimpan hasilnya. |
| **16** | `GET` | `/api/alerts/{alert_id}/handoff` | Operator | Menghasilkan dokumen **Portable AI Investigation & Remediation Handoff Markdown**. |
| **17** | `POST` | `/api/alerts/{alert_id}/verify` | Operator | Menjalankan **Automatic Recovery Verification** & menghasilkan **Before/After Remediation Diff**. |
| **18** | `GET` | `/api/alerts/{alert_id}/investigation` | Operator | Mengambil status alur kerja investigasi operator & riwayat catatan pada suatu *alert*. |
| **19** | `POST` | `/api/alerts/{alert_id}/investigation` | Operator | Memperbarui status investigasi (`investigating`, `resolved`, dll.) dan menambahkan catatan operator. |
| **20** | `GET` | `/api/alerts/{alert_id}/replay` | Operator | Menghasilkan **Chronological Incident Replay** langkah demi langkah. |
| **21** | `GET` | `/api/alerts/{alert_id}/context` | Operator | Menghasilkan **6-Stage MITRE Kill-Chain Correlation** dan **Entity Blast Radius Summary**. |
| **22** | `GET` | `/api/alerts/{alert_id}/evidence-bundle` | Operator | Mengunduh **Signed SHA-256 Forensic Evidence Bundle** JSON. |
| **23** | `GET` | `/api/timeline` | Operator | Mengambil gabungan kronologis *events*, *alerts*, dan *telemetry gaps* lintas host. |
| **24** | `GET` | `/api/gaps` | Operator | Mendeteksi dan mengembalikan daftar *Telemetry Gaps* berdasarkan ketiadaan *heartbeat*/data. |
| **25** | `GET` | `/api/findings` | Operator | Mengambil daftar 12 modul pemeriksaan postur (`8 CIS` + `4 DISA STIG`) untuk seluruh atau satu host. |
| **26** | `POST` | `/api/findings/scan` | Operator | Memicu pemindaian langsung (*live read-only scan*) 12 kontrol CIS + DISA STIG pada host. |
| **27** | `GET` | `/api/findings/{finding_id}` | Operator | Detail satu temuan pemeriksaan postur spesifik. |
| **28** | `POST` | `/api/findings/{finding_id}/analyze` | Operator | Menjalankan **SC Analysis Agent (`AEGIS2`)** pada temuan postur. |
| **29** | `GET` | `/api/evidence` | Operator | Daftar sesi **Emergency Evidence Mode** beserta pemeriksaan kedaluwarsa otomatis. |
| **30** | `POST` | `/api/evidence` | Operator | Memulai sesi **Emergency Evidence Mode** baru yang dibatasi waktu. |
| **31** | `POST` | `/api/evidence/{session_id}/stop` | Operator | Menghentikan sesi **Emergency Evidence Mode** lebih awal. |
| **32** | `GET` | `/api/reports` | Operator | Daftar seluruh laporan keamanan harian & insiden yang telah dibuat. |
| **33** | `POST` | `/api/reports` | Operator | Menyusun laporan baru menggunakan **Reporting Agent (`AEGIS3`)**. |
| **34** | `GET` | `/api/reports/{report_id}/pdf` | Operator | Mengunduh file biner **PDF (`application/pdf`)** dari laporan yang dipilih. |
| **35** | `GET` | `/api/audit-logs` | Operator | Mengambil seluruh catatan **Operator Action Audit Log**. |

---

## BAB 13: ARSITEKTUR DATABASE POSTGRESQL (SUPABASE), ROW-LEVEL SECURITY (RLS) & TRANSAKSI RPC ATOMIK

Diimplementasikan di [`supabase/migrations/`](file:///d:/Projects/School/aegis/supabase/migrations) dan [`aegis_backend/repository.py`](file:///d:/Projects/School/aegis/aegis_backend/repository.py):

1. **Tabel Utama Database**:
   - `public.hosts`: Menyimpan identitas node Linux (`id`, `hostname`, `ip_address`, `os`, `agent_version`, `agent_status`, `last_data_at`, `last_sc_run_at`, `is_archived`).
   - `public.telemetry_events`: Menyimpan log hasil normalisasi & sanitasi (`id`, `host_id`, `source_id`, `event_type`, `event_timestamp`, `message`, `source_ip`, `user_name`, `details` JSONB).
   - `public.alerts`: Menyimpan *alert* deterministik (`id`, `host_id`, `rule_id`, `rule_version`, `title`, `severity`, `detected_at`, `reason`). Dilengkapi *trigger* PostgreSQL yang menolak pembaruan kolom `severity`!
   - `public.alert_evidence`: Tabel penghubung *many-to-many* antara `alerts` dan `telemetry_events` (`alert_id`, `event_id`, `citation_role` `trigger`/`supporting`).
   - `public.system_status`: Menyimpan status komponen sistem.
2. **Transaksi RPC Atomik (`fn_ingest_alert_with_evidence`)**:
   - Memastikan penyimpanan *alert* beserta tautan bukti `alert_evidence`-nya terjadi secara atomik dalam satu transaksi database. Tidak boleh ada *alert* yang tersimpan tanpa bukti pendukung (*orphan alert*), dan tidak boleh ada bukti lintas-host (*cross-host evidence binding check*).
3. **Security Headers Middleware (`aegis_backend/main.py`)**:
   - Setiap respons HTTP dilengkapi header keamanan ketat:
     - `X-Content-Type-Options: nosniff`
     - `X-Frame-Options: DENY`
     - `Referrer-Policy: no-referrer`
     - `Cache-Control: no-store`

---

## BAB 14: KATALOG LENGKAP 113 PENGUJIAN OTOMATIS (`pytest`) & JAMINAN KUALITAS

Seluruh fitur di atas diuji secara ketat menggunakan **113 pengujian otomatis (`pytest`)** yang terbagi ke dalam 12 modul pengujian di direktori [`tests/`](file:///d:/Projects/School/aegis/tests):

1. **`tests/test_backend_api.py` (20 Tests)**:
   - Menguji seluruh endpoint REST API, paginasi host/alert, penyensoran kredensial pada bukti log, perilaku *fallback* Supabase RPC, imutabilitas `severity` (`PUT`/`PATCH` ditolak dengan `404`/`405`), tidak adanya kebocoran kunci rahasia, header keamanan HTTP, pembuatan Handoff Markdown, verifikasi pemulihan otomatis & kejujuran saat host *offline* (`unverified`), alur kerja investigasi & *replay*, alokasi 3 kunci AI (`AEGIS1`, `AEGIS2`, `AEGIS3`), 12 modul CIS + DISA STIG (`GET /api/findings` & `POST /api/findings/scan`), korelasi *Kill-Chain* 6 tahap, bundel bukti bertanda tangan SHA-256, dan ekspor laporan PDF biner (`%PDF-`).
2. **`tests/test_collector.py` (7 Tests)**:
   - Menguji sanitasi rahasia pada agen kolektor, pengiriman batch telemetri, pengiriman *heartbeat*, ketahanan saat jaringan terputus, dan komitmen kursor dua fase (*Two-Phase Cursor Commit*).
3. **`tests/test_linux_parser.py` (16 Tests)**:
   - Menguji parsing seluruh format log Linux: SSH gagal/sukses, sesi PAM, syscall & execve Auditd, sudo & kegagalan sudo, *snapshot* koneksi jaringan `ss`, pembuatan akun `useradd` & eskalasi grup `usermod`, blokir firewall UFW & *segfault* kernel, persistensi cron & penghentian layanan systemd, *smart filtering* log web Nginx/Apache, modifikasi `authorized_keys`, serta 3 parser pertahanan APT (`anti_forensics_execution`, `data_exfiltration_attempt`, `rootkit_or_sniff_activity`).
4. **`tests/test_rules_engine.py` (15 Tests)**:
   - Menguji seluruh 13 aturan deterministik: ambang batas brute-force SSH, isolasi lintas-IP dan lintas-host, login gagal diikuti sukses (`RULE-AUTH-003`), eksekusi sudo shell & `chmod 777` (`RULE-SUSP-SUDO`), idempotensi pembuatan *alert*, ketahanan terhadap log yang datang tidak berurutan (*out-of-order events*), serangan web & akun *backdoor*, port scan firewall & *segfault* kernel, persistensi cron, penghentian layanan keamanan, perusakan `authorized_keys`, serta aturan pertahanan APT (`RULE-ANTI-FORENSICS`, `RULE-DATA-EXFIL`, `RULE-ROOTKIT-SNIFF`).
5. **`tests/test_telemetry_ingest.py` (12 Tests)**:
   - Menguji autentikasi token agen (`X-Agent-Token`) dengan perbandingan waktu konstan (`hmac.compare_digest`), karantina baris berpanjang ekstrem (>4096 karakter), karantina kunci privat/password, deduplikasi event, dan penolakan *heartbeat* dari host tak dikenal (`404`).
6. **`tests/test_sc_validator.py` (10 Tests)**:
   - Menguji validator *Security Checker*: karantina bukti fiktif (*phantom evidence*), penolakan bukti lintas-host, penolakan status `PASS` pada kontrol yang tidak diperiksa, dan redaksi rahasia.
7. **`tests/test_rm_hardening.py` (10 Tests)**:
   - Menguji ketahanan validator *Runtime Monitor* terhadap injeksi prompt, pembekuan tingkat `severity`, dan validasi rentang waktu ekstrem.
8. **`tests/test_investigation.py` (6 Tests)**:
   - Menguji skenario investigasi end-to-end dan *Backend Gatekeeper* (pembatasan anggaran pemanggilan *tool* dan larangan perpindahan konteks host).
9. **`tests/test_services_and_provider.py` (7 Tests)**:
   - Menguji `RealLLMAdapter`, redaksi API key pada pesan error, penanganan *timeout* & JSON rusak, serta ketiga layanan agen (`RuntimeMonitorService`, `SecurityCheckerService`, `ReportingAgentService`).
10. **`tests/test_evidence.py`, `tests/test_evidence_grounding.py`, `tests/test_evaluation_regression.py`, `tests/test_schema.py` (10 Tests)**:
    - Menguji akurasi kuantitatif klaim AI, pembekuan *severity*, regresi kualitas AI, dan validasi skema Pydantic.

