# AEGIS — Zero-Trust Linux Security Monitoring, Hard Multi-Tenant Defense & Incident Forensics Platform (v2.0)

[![Tests: 223 Passed](https://img.shields.io/badge/pytest-223%20passed-brightgreen.svg)](tests/)
[![Architecture: Multi--Tenant Zero--Trust](https://img.shields.io/badge/security-hard%20multi--tenant-blue.svg)](aegis_backend/tenancy.py)
[![Compliance: CIS + DISA STIG](https://img.shields.io/badge/compliance-CIS%20%7C%20DISA%20STIG-orange.svg)](aegis_agent/security_checker.py)
[![PWA: Installable APK Ready](https://img.shields.io/badge/mobile-PWA%20%2F%20APK%20ready-purple.svg)](dashboard/public/manifest.webmanifest)
[![License: Defense Grade](https://img.shields.io/badge/license-Proprietary%20Defense-red.svg)](#)

**AEGIS** adalah platform pemantauan keamanan server Linux (*Ubuntu 22.04 / 24.04 LTS*), deteksi ancaman deterministik MITRE ATT&CK, audit postur kepatuhan militer **CIS Benchmark + DISA STIG**, isolasi multi-satuan **Hard Multi-Tenant Zero-Trust**, dan investigasi insiden berbantuan AI yang dirancang dengan filosofi **Zero Autonomous Remediation** serta konsumsi memori ultra-rendah (*Ultra-Low RAM Footprint* < 135 MB total).

---

## 1. Keunggulan & Prinsip Arsitektur Utama

### 1. Zero Autonomous Remediation (100% Read-Only & Aman untuk Infrastruktur Kritis)
AEGIS **tidak pernah** memblokir IP, mematikan layanan, atau mengubah konfigurasi OS server secara otonom/sepihak. Seluruh rekomendasi mitigasi disajikan kepada operator manusia lengkap dengan estimasi dampak layanan (*service impact*), perintah verifikasi, serta langkah *rollback* terdokumentasi.

### 2. Hard Multi-Tenant Isolation & Autentikasi Zero-Trust
Memastikan pemisahan data absolut antar divisi, unit operasional (misal: Unit Alpha vs Unit Bravo), maupun tenant industri:
- **Server-Side Enforcement**: Pengamanan diterapkan di lapisan backend gateway dan database access layer (`TenantScopedRepository`), bukan sekadar filter UI.
- **Anti-Enumeration 404**: Jika operator Unit Alpha mencoba mengakses ID server milik Unit Bravo (`/api/hosts/server-bravo-01`), sistem mengembalikan respon **404 Not Found** (bukan 403), sehingga pihak luar tidak dapat memetakan keberadaan aset unit lain.
- **Agent First-Claim & Anti-Spoofing**: Host terikat secara permanen ke tenant token saat telemetri pertama kali diterima. Upaya agen lain melakukan *spoofing* identitas server ditolak langsung (**403 Forbidden**).
- **Anti-Brute-Force Rate Limiter**: Kunci akun otomatis selama 60 detik jika terjadi $\ge 5$ kali kegagalan login berturut-turut.
- **Role-Based Access Control (RBAC)**:
  - `superadmin`: Akses lintas unit (Pusat Komando / HQ Command).
  - `engineer`: Hak baca dan operasional penuh terbatas pada unit miliknya.
  - `viewer`: Hak baca mutlak (*read-only*), seluruh aksi mutasi diblokir (**403 Forbidden**).

### 3. Deterministic Detection Engine (`RulesEngine` — 15 Aturan MITRE ATT&CK)
Deteksi ancaman berjalan 100% deterministik tanpa ketergantungan pada model AI eksternal:
- `RULE-SSH-BRUTE` (`T1110.001`) — SSH Password Brute Force Burst
- `RULE-SSH-SPRAY` (`T1110.003`) — Multi-Account Password Spraying
- `RULE-ROOT-LOGIN` (`T1078.003`) — Direct Root SSH Login
- `RULE-SUDO-ABUSE` (`T1548.003`) — Repeated Sudo Authentication Failures
- `RULE-SUDO-ESCALATION` (`T1548.003`) — Suspicious Sudo Privilege Escalation (`chmod 777`, interactive root shell, `/etc/shadow`)
- `RULE-USER-BACKDOOR` (`T1136.001`) — Backdoor Account Creation (`UID 0` / `usermod -aG sudo`)
- `RULE-PORT-SCAN` (`T1046`) — Network Port Scanning (`UFW BLOCK` burst)
- `RULE-KERNEL-EXPLOIT` (`T1068`) — Binary Segmentation Fault / Memory Corruption Probe
- `RULE-CRON-PERSIST` (`T1053.003`) — Suspicious Cron Job Persistence
- `RULE-DEFENSE-EVASION` (`T1562.001`) — Stopping Critical Security Services (`ufw`, `auditd`, `ssh`, `aegis-collector`)
- `RULE-WEB-PROBES` (`T1190`) — Web Server SQLi, Path Traversal, Command Injection & Scanner Probes
- `RULE-SSH-KEY-BACKDOOR` (`T1098.004`) — Tampering with `authorized_keys`, `/etc/ssh/sshd_config`, or `/etc/sudoers`
- `RULE-ANTI-FORENSICS` (`T1070`) — Log Wiping & Command History Erasure (`history -c`, `shred`, `truncate -s 0`, `rm -rf /var/log`)
- `RULE-DATA-EXFIL` (`T1041` / `T1560`) — Sensitive Directory Archiving & Outbound Transfer (`tar`, `scp`, `rsync`, `curl -F`)
- `RULE-ROOTKIT-SNIFF` (`T1547.006` / `T1040`) — Unauthorized Kernel Module Loading (`insmod`/`modprobe`) & Promiscuous Network Sniffing

### 4. 12-Module Read-Only Security Checker (CIS Benchmark + DISA STIG)
- **8 Kontrol CIS Ubuntu Benchmark**: `CIS-SSH-5.2.8` (`PermitRootLogin`), `CIS-PERM-6.1.2` (`/etc/shadow` mode `0640`), `CIS-PRIV-5.3.4` (`NOPASSWD` sudoers audit), `CIS-SUID-6.1.12` (SUID/SGID binary tracking), `CIS-NET-3.5.1` (UFW & open listening ports), `CIS-SYSCTL-3.3.1` (ASLR & kernel network parameters), `CIS-PKG-1.9` (pending security patches), `CIS-PERSIST-5.1.8` (cron & systemd persistence checks).
- **4 Kontrol Militer DISA STIG**: `STIG-BANNER-8.1` (Mandatory Defense Login Banner), `STIG-CRYPTO-5.2` (SSH Strong Ciphers & FIPS-Grade KEX), `STIG-AUDIT-4.1` (Kernel `auditd` Immutability `-e 2`), `STIG-MEDIA-1.1` (USB Mass Storage Kernel Blacklist).

### 5. Arsitektur 3 API Key AI Terpisah dengan Failover Otomatis
- **`AEGIS1` (Runtime Monitor Agent)**: Analisis insiden, korelasi hipotesis forensik, dan pembuatan dokumen *Shift Handoff* `.md`.
- **`AEGIS2` (Security Checker Agent)**: Analisis postur kepatuhan CIS & STIG serta panduan remediasi konfigurasi.
- **`AEGIS3` (Reporting Agent)**: Penyusunan laporan eksekutif harian & forensik insiden lengkap dengan generator dokumen PDF biner.

### 6. PWA & Mobile APK Ready (Android)
- Dilengkapi Web App Manifest (`manifest.webmanifest`), Service Worker offline caching (`sw.js`), dan Web Push Alerts.
- GitHub Actions CI/CD Workflow (`.github/workflows/build-apk.yml`) untuk kompilasi otomatis file `.apk` mandiri.

---

## 2. Profil & Penggunaan Sumber Daya (RAM)

AEGIS dirancang ringan dan tangguh untuk dijalankan pada mini server atau edge device:

| Komponen / Container | Base Image | RAM (Idle) | RAM (Beban Puncak) | Batas Memori (`mem_limit`) |
| :--- | :--- | :---: | :---: | :---: |
| **`aegis-backend`** (FastAPI + Uvicorn) | `python:3.12-slim` | **~55 – 75 MB** | **~90 – 115 MB** | `192 MB` |
| **`aegis-dashboard`** (Static SPA + Nginx) | `nginx:1.27-alpine` | **~8 – 14 MB** | **~15 – 22 MB** | `64 MB` |
| **`aegis-collector`** (Agent di Host Target) | Python Native Systemd | **~16 – 24 MB** | **~25 – 35 MB** | `48 MB` |
| **TOTAL KONSUMSI LENGKAP** | **Full Stack** | **~75 – 110 MB** | **~130 – 170 MB** | **256 MB Total** |

---

## 3. Manajemen Multi-Tenant & Otorisasi Pengguna (CLI Admin)

AEGIS menyertakan alat administrasi command-line [`scripts/manage_auth.py`](file:///d:/Projects/School/aegis/scripts/manage_auth.py) untuk mengelola unit, kredensial operator, dan rotasi token agent secara mandiri.

### Inisialisasi Unit & Pengguna Default
```bash
python scripts/manage_auth.py init-defaults
```
Perintah ini otomatis mengonfigurasi akun awal untuk pengujian multi-tenant:
1. **Pusat Komando (HQ Command)**: Username `admin` / Password `Aegis@CommandHQ2026!` (Role: `superadmin`, Tenant: `*` — melihat seluruh server dari semua unit).
2. **Unit Alpha**: Username `operator_alpha` / Password `Alpha@Aegis2026!` (Role: `engineer`, Tenant: `unit_alpha`).
3. **Unit Bravo**: Username `operator_bravo` / Password `Bravo@Aegis2026!` (Role: `engineer`, Tenant: `unit_bravo`).

### Perintah Operasional CLI Tambahan
```bash
# Tambah unit/tenant baru (misal: Sektor Industri atau Wilayah lain)
python scripts/manage_auth.py add-tenant industri_migas "PT Industri Migas Energi"
# Output memberikan token agent: aegis_agt_...

# Tambah akun teknisi/operator
python scripts/manage_auth.py add-user teknisi1 "PasswordKuat123!" --tenant industri_migas --role engineer

# Lihat seluruh daftar unit & server yang terikat
python scripts/manage_auth.py list-tenants

# Lihat seluruh daftar pengguna aktif
python scripts/manage_auth.py list-users

# Rotasi token agent jika terjadi kompromi keamanan
python scripts/manage_auth.py rotate-token unit_alpha
```

---

## 4. Tiga Cara Menjalankan AEGIS

AEGIS dapat dijalankan dalam 3 skenario deployment sesuai kebutuhan operasional:

---

### METODE 1: Full Docker Containerized (Paling Praktis — Rekomendasi Demo)
> **Skenario:** Sangat direkomendasikan untuk demonstrasi fitur, evaluasi dewan juri, simulasi serangan, audit postur CIS/STIG, dan ekspor laporan PDF.

1. **Konfigurasi Environment Variable (`.env`):**
   ```bash
   cp .env.example .env
   # Pastikan kredensial database dan API Key AI (AEGIS1, AEGIS2, AEGIS3) terisi
   ```
2. **Jalankan Container via Docker Compose:**
   ```bash
   docker compose up -d --build
   ```
3. **Akses Layanan:**
   - **Dashboard Web UI & Gateway Utama:** `http://localhost:1708`
   - **Swagger API Docs:** `http://localhost:1708/docs`
   - **Direct Backend Health Check:** `http://localhost:1709/api/health`

---

### METODE 2: Mode Hibrida (Docker Backend + Native Host Agent — Rekomendasi Server Nyata)
> **Skenario:** Direkomendasikan untuk **server Linux produksi / mini server Ubuntu nyata** agar telemetri `journalctl`, `systemctl`, `ufw`, dan socket jaringan terpantau 100% tanpa batas isolasi container.

1. **Jalankan Backend & Dashboard di Docker:**
   ```bash
   docker compose up -d --build
   ```
2. **Pasang Host Collector (1-Click Systemd Installer):**
   ```bash
   # Di server Linux target yang ingin dipantau:
   sudo bash scripts/install_agent.sh \
     --server-url http://<IP_SERVER_AEGIS>:8000 \
     --tenant-id unit_alpha \
     --auth-token aegis_agt_6_GULjT3yz20fgkK3ocCzZfqxTslOxN-lVRCNbNTWSM
   ```
   *Skrip otomatis membuat virtualenv terisolasi di `/opt/aegis-agent`, mengonfigurasi `/etc/aegis/agent.env`, mendaftarkan service `/etc/systemd/system/aegis-collector.service`, dan mengunci permission file `600`.*

3. **Perintah Kontrol Agen Host:**
   - Cek status agent: `sudo systemctl status aegis-collector`
   - Pantau streaming log: `sudo journalctl -u aegis-collector -f`
   - Restart agent: `sudo systemctl restart aegis-collector`
   - Copot pemasangan: `sudo bash scripts/uninstall_agent.sh`

---

### METODE 3: Bare Metal / Native Development (Tanpa Docker)
> **Skenario:** Direkomendasikan untuk pengembangan kode (*development*), penambahan fitur, dan pengujian cepat di laptop developer.

1. **Jalankan Backend FastAPI (Port `1709`):**
   ```bash
   # Windows PowerShell:
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   python -m uvicorn aegis_backend.main:app --host 127.0.0.1 --port 1709 --reload

   # Linux / macOS Bash:
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python3 -m uvicorn aegis_backend.main:app --host 127.0.0.1 --port 1709 --reload
   ```
2. **Jalankan Frontend Dashboard (Port `1708`):**
   ```bash
   cd dashboard
   npm install
   npm run dev
   ```
   Buka peramban di: `http://localhost:1708`

---

## 5. Pengujian Otomatis & Verifikasi Kualitas

Seluruh suite pengujian otomatis telah diverifikasi dan lulus **100%**:

### A. Menjalankan Backend Unit, Integration & Tenancy Test Suite (223 Pengujian)
```powershell
python -m pytest -v
```
*Mencakup 214 pengujian deteksi MITRE ATT&CK, parser log, rules engine, security checker, database fallback, sanitasi rahasia, serta 9 pengujian isolasi multi-tenant (anti-brute force, token revocation, anti-spoofing agent, dan anti-enumeration 404).*

### B. Menjalankan AI Evaluation Harness (Offline Benchmark)
```powershell
python evaluation/run_evaluation.py
```

### C. Memvalidasi TypeScript & Build Produksi Frontend
```powershell
npm --prefix dashboard run build
```
*Memvalidasi seluruh 13 layar antarmuka pengguna (termasuk Login Guard & Scope Satuan) dengan 0 error TypeScript dan 0 error linting.*

---

## 6. Struktur Direktori Proyek

```
aegis/
├── aegis_backend/            # Core FastAPI Gateway & Layanan Backend
│   ├── tenancy.py            # Modul Isolasi Multi-Tenant, RBAC, Rate Limiter & Token Session
│   ├── repository.py         # Abstraksi Basis Data SSoT (Supabase PostgreSQL + Mock fallback)
│   ├── incident_service.py   # State Store, AI Correlator, Audit Logging & PDF Generator
│   ├── sanitizer.py          # Inspeksi Regex Pre-Storage & Karantina Kredensial Sensitif
│   ├── main.py               # Inisialisasi FastAPI, Gateway Middleware & Routing
│   └── routers/              # Endpoint REST API (auth, hosts, telemetry, alerts, incidents, ops)
├── aegis_agent/              # Modul Pemantauan & Analisis Host Target
│   ├── collector.py          # Telemetry Ingest Collector & Cursor Tracker
│   ├── pipeline_adapter.py   # Normalisasi Syslog, Auth, UFW, Nginx, Auditd
│   ├── rules_engine.py       # Deterministic Detection Engine (15 Aturan MITRE ATT&CK)
│   ├── security_checker.py   # 12 Modul Audit Postur Kepatuhan (8 CIS + 4 DISA STIG)
│   └── services.py           # Provider AI 3-Key Failover (AEGIS1, AEGIS2, AEGIS3)
├── dashboard/                # Antarmuka Pengguna React 18 + TypeScript + Vite
│   ├── public/               # Asset Brand, Web Manifest (PWA), Service Worker (sw.js)
│   └── src/
│       ├── screens/          # 13 Layar Operasional (Login, Overview, Hosts, Incidents, Dll)
│       ├── components/       # AppShell, Sidebar dengan Badge Satuan, UI Controls
│       ├── data/api.ts       # Client API Gateway dengan Token Authorization Header
│       └── styles/           # Desain Dark/Light Mode Standar Militer (tokens.css, app.css)
├── scripts/                  # Skrip Otomasi DevOps & Administrasi
│   ├── manage_auth.py        # CLI Manajemen Multi-Tenant, Pengguna & Token Agent
│   ├── install_agent.sh      # 1-Click Native Host Installer (Systemd Daemon)
│   └── uninstall_agent.sh    # Pembersih Bersih Service & Virtualenv Agent
├── .github/workflows/        # CI/CD Pipeline & GitHub Actions APK Builder (TWA)
├── tests/                    # 223 Pengujian Otomatis (Pytest)
└── docs/                     # Dokumentasi Spesifikasi & Cetak Biru Arsitektur
```
