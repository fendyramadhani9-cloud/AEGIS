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

## 3. Cara Menjalankan AEGIS dengan Docker (Direkomendasikan)

### A. Persiapan Konfigurasi `.env`
Salin `.env.example` menjadi `.env` dan isi kredensial Supabase serta 3 API Key AI (`AEGIS1`, `AEGIS2`, `AEGIS3`):
```bash
cp .env.example .env
```

### B. Menjalankan Backend + Dashboard via Docker Compose
```bash
docker compose up -d --build
```
- **Dashboard Web UI & Gateway Utama (Port `1708`):** `http://localhost:1708`
- **Swagger API Docs (via Gateway `1708`):** `http://localhost:1708/docs`
- **Direct FastAPI Backend (Port `1709`):** `http://localhost:1709/api/health`

*(Opsional)* Jika dijalankan langsung di server Linux yang ingin dipantau sekaligus oleh container collector:
```bash
docker compose --profile collector up -d --build
```

### C. Memantau Penggunaan RAM Container Secara Real-Time
```bash
docker stats aegis-backend aegis-dashboard
```

---

## 4. Cara Menjalankan Secara Lokal (Tanpa Docker)

### A. Menjalankan FastAPI Backend (Port `1709`)
```powershell
python -m pip install -r requirements.txt
python -m uvicorn aegis_backend.main:app --host 127.0.0.1 --port 1709 --reload
```

### B. Menjalankan Frontend Dashboard (Port `1708`)
```powershell
cd dashboard
npm install
npm run dev
```
Buka dashboard di: `http://localhost:1708`

### C. Menjalankan Linux Telemetry Collector (Pada Server Ubuntu Target)
```bash
python3 aegis_agent/collector.py
```
Collector membaca `journalctl` serta melakukan *incremental file tailing* pada `/var/log/nginx/access.log`, `/var/log/apache2/access.log`, dan `/var/log/audit/audit.log` dengan mekanisme **Two-Phase Cursor & Offset Commit** (nol kehilangan log saat jaringan terputus) dan **Pre-Transmission Credential Sanitizer**.

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
