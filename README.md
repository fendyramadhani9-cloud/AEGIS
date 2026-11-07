# AEGIS — Linux Security Monitoring, Incident Investigation & Defense Posture Platform (v1.0)

**AEGIS** adalah platform pemantauan keamanan server Linux (*Ubuntu 22.04 / 24.04 LTS*), deteksi ancaman deterministik, audit postur keamanan **CIS Benchmark + DISA STIG**, dan investigasi insiden berbantuan AI yang dirancang dengan filosofi **Zero Autonomous Remediation** serta konsumsi sumber daya ultra-rendah (*Ultra-Low RAM Footprint*).

---

## 1. Keunggulan & Prinsip Arsitektur Utama

1. **Zero Autonomous Remediation (100% Read-Only & Aman untuk Infrastruktur Kritis / Pertahanan)**
   - AEGIS tidak pernah memblokir IP, mematikan layanan, atau mengubah konfigurasi server secara sepihak. Seluruh keputusan mitigasi berada di tangan operator manusia dengan panduan *rollback* dan analisis dampak layanan.
2. **Deterministic Detection Engine (`RulesEngine` — 13 Aturan MITRE ATT&CK)**
   - Deteksi ancaman berjalan 100% deterministik tanpa ketergantungan pada AI:
     - `RULE-SSH-BRUTE` (`T1110.001`) — SSH Password Brute Force Burst
     - `RULE-SSH-SPRAY` (`T1110.003`) — Multi-Account Password Spraying
     - `RULE-ROOT-LOGIN` (`T1078.003`) — Direct Root SSH Login
     - `RULE-SUDO-ABUSE` (`T1548.003`) — Repeated Sudo Authentication Failures
     - `RULE-SUDO-ESCALATION` (`T1548.003`) — Suspicious Sudo Privilege Escalation (`chmod 777`, root shell, `/etc/shadow`)
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
3. **12-Module Read-Only Security Checker (8 CIS Ubuntu Benchmark + 4 DISA STIG Military Controls)**
   - **8 Kontrol CIS**: `CIS-SSH-5.2.8` (`PermitRootLogin`), `CIS-PERM-6.1.2` (`/etc/shadow` permissions), `CIS-PRIV-5.3.4` (`NOPASSWD` sudoers), `CIS-SUID-6.1.12` (SUID/SGID binaries), `CIS-NET-3.5.1` (UFW & open ports), `CIS-SYSCTL-3.3.1` (ASLR & kernel network hardening), `CIS-PKG-1.9` (pending security patches), `CIS-PERSIST-5.1.8` (cron & systemd persistence).
   - **4 Kontrol DISA STIG (Defense-Grade)**: `STIG-BANNER-8.1` (Mandatory DoD/TNI Login Banner), `STIG-CRYPTO-5.2` (SSH Strong Ciphers & FIPS-Grade KEX), `STIG-AUDIT-4.1` (Kernel `auditd` Immutability `-e 2`), `STIG-MEDIA-1.1` (USB Mass Storage Kernel Blacklist).
4. **Arsitektur 3 API Key AI Terpisah dengan Failover Otomatis (`AEGIS1`, `AEGIS2`, `AEGIS3`)**
   - **`AEGIS1` (RM Analysis Agent)**: Investigasi insiden runtime, pemisahan ketat `FACT` vs `HYPOTHESIS`, dan pembuatan dokumen *Shift Handoff* `.md`.
   - **`AEGIS2` (SC Analysis Agent)**: Analisis postur konfigurasi CIS & DISA STIG beserta rekomendasi pengerasan.
   - **`AEGIS3` (Reporting Agent)**: Agen khusus penyusun laporan eksekutif harian & insiden (dengan ekspor PDF biner).
5. **Status Kesiapan Siber (`SIAGA I / SIAGA II / SIAGA III`) & Forensik Rantai Bukti (SHA-256)**
   - Indikator kesiapan komando real-time di halaman Overview, *Incident Replay* kronologis, *Blast Radius*, *Automatic Recovery Verification* (host offline tidak pernah dianggap pulih), dan bundel bukti bersegel SHA-256.

---

## 2. Profil & Prediksi Penggunaan RAM (Docker & Native)

AEGIS dirancang sangat hemat memori karena tidak menjalankan JVM, Elasticsearch, atau model LLM lokal di dalam server:

| Komponen / Container | Base Image | Penggunaan RAM (Idle) | Penggunaan RAM (Aktif / Beban Puncak) | Batas Memori (`mem_limit`) |
| :--- | :--- | :---: | :---: | :---: |
| **`aegis-backend`** (FastAPI + Uvicorn 1 Worker) | `python:3.12-slim` | **~55 – 75 MB** | **~90 – 115 MB** | `192 MB` |
| **`aegis-dashboard`** (Static SPA + Reverse Proxy) | `nginx:1.27-alpine` | **~8 – 14 MB** | **~15 – 22 MB** | `64 MB` |
| **`aegis-collector`** (Agent di Host Linux Target) | `python:3.12-slim` / Native | **~16 – 24 MB** | **~25 – 35 MB** | `48 MB` |
| **TOTAL (`backend` + `dashboard`)** | **Multi-Stage Docker** | **~65 – 90 MB** | **~105 – 135 MB** | **256 MB Total** |

---

## 3. Tiga Cara Menjalankan AEGIS (Setup & Perbandingan Kelebihan)

AEGIS dirancang fleksibel sehingga dapat dijalankan dalam **3 skenario deployment** yang berbeda sesuai kebutuhan: untuk demo lomba, monitoring server nyata, atau pengembangan kode lokal.

---

### METODE 1: Full Docker Containerized (Paling Praktis — Rekomendasi Demo Lomba)
> **Skenario:** Sangat direkomendasikan untuk **presentasi ke dewan juri, demonstrasi fitur, simulasi serangan (Incident Replay), audit postur CIS/STIG, dan ekspor laporan PDF.**

Semua layanan (Frontend Dashboard di port `1708` dan Backend FastAPI di port `1709`) dikemas dalam container multi-stage berukuran sangat kecil dengan penggunaan RAM terukur (< 135 MB total).

#### Langkah Setup:
1. **Konfigurasi Environment Variable (`.env`):**
   ```bash
   cp .env.example .env
   # Buka .env dan pastikan kredensial Supabase serta 3 API Key AI (AEGIS1, AEGIS2, AEGIS3) terisi
   ```
2. **Jalankan Container via Docker Compose:**
   ```bash
   docker compose up -d --build
   ```
3. **Akses Layanan:**
   - **Dashboard Web UI & Gateway Utama:** `http://localhost:1708` (atau ganti `localhost` dengan IP mini server kamu)
   - **Swagger API Docs:** `http://localhost:1708/docs`
   - **Direct Backend Health Check:** `http://localhost:1709/api/health`
4. **Pantau Penggunaan RAM:**
   ```bash
   docker stats aegis-backend aegis-dashboard
   ```

#### Kelebihan Metode 1:
- ✅ **Cukup Satu Perintah:** Seluruh platform langsung aktif tanpa perlu menginstall Python, Node.js, atau Nginx di OS host server.
- ✅ **Sudah Terintegrasi Read-Only Host Mount:** Konfigurasi `/etc/ssh`, `/etc/issue.net`, `/etc/modprobe.d`, dan `/var/log` dari host sudah di-mount secara aman (`:ro`), sehingga pemeriksaan postur CIS/STIG berbasis file tetap dapat membaca konfigurasi asli server.
- ✅ **Isolasi Penuh & Aman:** Layanan web tidak memiliki hak modifikasi ke sistem host (`read-only`), mencegah resiko kerusakan sistem.
- ✅ **Konsumsi RAM Sangat Rendah:** Total konsumsi RAM container hanya ~65 MB (idle) hingga ~135 MB (beban puncak).

---

### METODE 2: Mode Hibrida (Docker Core + Native Host Agent — Rekomendasi Monitoring Server Nyata)
> **Skenario:** Sangat direkomendasikan untuk **server Linux produksi / mini server nyata** yang ingin dipantau kondisi log dan layanannya secara 100% *real-time* tanpa batasan abstraksi container.

Backend FastAPI dan Dashboard UI tetap berjalan rapi di dalam Docker container, sedangkan script `collector.py` dijalankan langsung sebagai *native process* atau *systemd service* pada OS Ubuntu host.

#### Langkah Setup:
1. **Jalankan Backend & Dashboard di Docker:**
   ```bash
   docker compose up -d --build
   ```
2. **Jalankan Collector di Host Linux (Ubuntu 22.04 / 24.04):**
   ```bash
   # Di terminal server host (luar docker):
   sudo python3 -m aegis_agent.collector --backend-url http://127.0.0.1:1708/api
   ```
3. *(Opsional)* **Jadikan Systemd Service Otomatis:**
   Buat file `/etc/systemd/system/aegis-collector.service`:
   ```ini
   [Unit]
   Description=AEGIS Security Telemetry Collector
   After=network.target docker.service

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/aegis
   ExecStart=/usr/bin/python3 -m aegis_agent.collector --backend-url http://127.0.0.1:1708/api
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```
   Aktifkan service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now aegis-collector
   ```

#### Kelebihan Metode 2:
- ✅ **Visibilitas Sistem 100% Tanpa Hambatan:** Collector berjalan langsung di OS host sehingga memiliki akses instan dan akurat ke `journalctl`, `systemctl is-active auditd`, `ufw status`, `dpkg -s`, serta socket jaringan `/proc/net` tanpa terhalang isolasi container.
- ✅ **Infrastruktur Bersih & Rapi:** Web server, API gateway, dan database client tetap terisolasi di dalam Docker container tanpa mengotori package manager host.
- ✅ **Overhead di Host Sangat Minim:** Native agent collector hanya membutuhkan Python standar dan memakan RAM **~20 MB** saja di OS host.
- ✅ **Toleransi Gangguan Jaringan (Two-Phase Cursor):** Jika container backend sedang direstart, collector di host akan menyimpan kursor log terakhir dan melanjutkan pengiriman otomatis saat backend kembali aktif tanpa ada log yang hilang.

---

### METODE 3: Bare Metal / Native Development (Tanpa Docker)
> **Skenario:** Sangat direkomendasikan untuk **pengembangan kode (development), penambahan fitur baru, debugging, dan pengujian cepat di laptop/PC developer.**

Semua komponen dijalankan langsung dari terminal lokal menggunakan lingkungan Python Virtualenv dan Node.js Vite dev server dengan dukungan *Hot Module Replacement (HMR)*.

#### Langkah Setup:
1. **Menjalankan Backend FastAPI (Port `1709`):**
   ```bash
   # Windows (PowerShell):
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   python -m uvicorn aegis_backend.main:app --host 127.0.0.1 --port 1709 --reload

   # Linux / macOS (Bash):
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python3 -m uvicorn aegis_backend.main:app --host 127.0.0.1 --port 1709 --reload
   ```
2. **Menjalankan Frontend Dashboard (Port `1708`):**
   ```bash
   cd dashboard
   npm install
   npm run dev
   ```
   Buka peramban di: `http://localhost:1708`
3. **Menjalankan Telemetry Collector (Opsional jika ingin ingest log langsung):**
   ```bash
   python -m aegis_agent.collector --backend-url http://127.0.0.1:1709/api
   ```

#### Kelebihan Metode 3:
- ✅ **Hot-Reload Instan (HMR):** Perubahan pada kode React/TypeScript langsung ter-update di layar tanpa perlu rebuild container atau reload halaman secara manual.
- ✅ **Auto-Reload Backend:** Perubahan pada file Python backend langsung di-reload secara otomatis oleh Uvicorn (`--reload`).
- ✅ **Kemudahan Debugging Mendalam:** Pesan log terminal, stack trace Python, console inspect browser, dan breakpoint debugger IDE dapat diakses secara langsung tanpa perantara container.
- ✅ **Tanpa Ketergantungan Docker Engine:** Dapat dijalankan di mesin atau laptop yang tidak memiliki Docker Desktop / daemon aktif.

---

## 5. Pengujian Otomatis & Verifikasi Kualitas

### A. Menjalankan Seluruh Unit, Integration & Regression Test Suite (122 Pengujian)
```powershell
python -m pytest -v
```

### B. Menjalankan AI Evaluation Harness (Offline Benchmark)
```powershell
python evaluation/run_evaluation.py
```

### C. Memvalidasi TypeScript & Build Produksi Frontend
```powershell
npm --prefix dashboard run build
```

---

## 6. Struktur Direktori Proyek

- `aegis_backend/` — FastAPI API Gateway, endpoint operasional, PDF generator, sanitizer, dan `OperationalStateStore`.
- `aegis_agent/` — `LinuxTelemetryParser`, `RulesEngine`, `ReadOnlySecurityChecker` (12 modul CIS + DISA STIG), `AegisTelemetryCollector`, dan layanan AI (`AEGIS1`, `AEGIS2`, `AEGIS3`).
- `dashboard/` — Aplikasi antarmuka pengguna React 18 + TypeScript + Vite (12 layar operasional, tema terang/gelap, responsif desktop & mobile).
- `supabase/migrations/` — Migrasi skema PostgreSQL, trigger imutabilitas severity & audit log, serta kebijakan RLS.
- `tests/` — 122 pengujian otomatis mencakup parser, rules engine, collector, validator AI, dan endpoint REST API.
- `docs/` — Dokumentasi cetak biru lengkap (`AEGIS_MASTER_BLUEPRINT_LENGKAP.md`) dan laporan audit QA (`AEGIS_FULL_QA_SECURITY_AUDIT_REPORT.md` & `BUG_FIX_REPORT.md`).
