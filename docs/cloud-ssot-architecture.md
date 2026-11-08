# AEGIS CLOUD SSoT ARCHITECTURE & DATA FLOW SPECIFICATION

**Dokumen:** `docs/cloud-ssot-architecture.md`  
**Sistem:** AEGIS — AI-Powered Linux Security Monitoring and Incident Investigation  
**Status:** Unified Cloud Single Source of Truth (SSoT)  
**Versi:** 1.0.0 (Production Cutover Ready)  
**Tanggal:** 8 November 2026  
**Penulis:** Apri (Senior Software Engineer, Database Architect, DevSecOps Lead)

---

## 1. Ikhtisar Arsitektur

AEGIS beralih dari arsitektur transisional **Hybrid Mode** (penyimpanan primer lokal SQLite dengan sinkronisasi parsial ke Cloud) menuju **Unified Cloud Single Source of Truth (SSoT)** di mana Supabase Cloud PostgreSQL bertindak sebagai basis data operasional tunggal dan otoritatif untuk seluruh subsistem.

```
+--------------------------------------------------------------------------------------------------+
|                                    AEGIS UNIFIED CLOUD SSoT                                      |
+--------------------------------------------------------------------------------------------------+
                                                                                                    
   [Linux OS / Auth.log / Journald / Auditd / Syslog]                                              
                               |                                                                    
                               v                                                                    
               +-------------------------------+                                                    
               |    aegis-collector.service    |  (Daemon mandiri, Systemd, user 'adm')             
               +---------------+---------------+                                                    
                               | (HTTP/1.1 POST /api/telemetry/ingest via Reverse Proxy)            
                               v                                                                    
               +-------------------------------+                                                    
               |     aegis-backend.service     |  (FastAPI / Uvicorn, port 8000)                    
               |  (AEGIS_DATABASE_MODE=        |                                                    
               |       cloud_ssot)             |                                                    
               +---------------+---------------+                                                    
                               |                                                                    
           +-------------------+-------------------+                                                
           |                                       |                                                
           | (Primary HTTPS HTTP/2 Service Role)   | (Async Mirrored Replica / Disaster Recovery)   
           v                                       v                                                
+------------------------------------+   +------------------------------------+                     
|      SUPABASE CLOUD POSTGRES       |   |       LOCAL SQLITE REPLICA         |                     
|   (Primary Canonical SSoT)         |   |    (Arsip Forensik & Cold Backup)  |                     
|------------------------------------|   |------------------------------------|                     
| - hosts & system_status            |   | - mirror_sync_log (audit trail)    |                     
| - telemetry_events (> 1,550+)      |   | - read-only disaster cache         |                     
| - alerts & alert_evidence          |   | - asynchronous write replay        |                     
| - security_check_runs & findings   |   +------------------------------------+                     
| - incidents & incident_alerts      |                                                              
| - incident_risk_factors & timeline |                                                              
| - ai_analyses                      |                                                              
| - incident_status_history          |                                                              
| - fn_ingest_alert_with_evidence    |                                                              
+-----------------+------------------+                                                              
                  ^                                                                                 
                  | (REST API /api/...)                                                             
+-----------------+------------------+                                                              
|        REACT 19 DASHBOARD          |                                                              
| (Vite Bundle, TypeScript, NGINX)   |                                                              
+------------------------------------+                                                              
```

---

## 2. Prinsip Inti Arsitektur Cloud SSoT

### 2.1 Single Source of Truth (SSoT) Otoritatif
- Seluruh endpoint baca (`GET`) dan tulis (`POST`, `PATCH`) membaca dan menulis langsung ke Supabase Cloud PostgreSQL.
- Tidak ada data operasional yang disimpan atau dibaca dari SQLite secara eksklusif.

### 2.2 Eliminasi Silent Fallback (Fail-Loud Guarantee & Strict Fail-Closed)
- Jika Supabase Cloud mengalami gangguan (network timeout, authentication failure, DNS issue), backend **DILARANG KERAS** beralih diam-diam (*silent fallback*) ke SQLite sebagai primary database.
- Backend segera menolak permintaan dengan `HTTP 500 / 503` dan memunculkan `RuntimeError` pada logging internal.
- Tidak ada mekanisme perpindahan otomatis (*automatic fallback*) ke SQLite saat Cloud mati. Failover ke SQLite lokal hanya dilakukan secara manual dan terencana oleh operator sistem melalui runbook rollback.
- Hal ini mencegah fragmentasi data (*split-brain*) di mana sebagian operasi tersimpan di SQLite dan sebagian di Cloud.

### 2.3 Peran SQLite: Local Forensic Archive & Cold Replica dengan Durable Mirror Queue
- SQLite diturunkan fungsinya menjadi **asynchronous read-only forensic replica**.
- Setiap operasi penulisan yang berhasil di Cloud akan dimirrorkan secara asinkron ke SQLite via `_execute_mirror(...)`.
- **Durable Payload Queue:** Jika penulisan mirror ke SQLite gagal (misalnya lock timeout atau I/O busy), serialisasi payload JSON lengkap disimpan di disk dalam kolom `mirror_sync_log.payload`.
- **Offline Replay:** `PeriodicMirrorWorker` dan `replay_failed_mirrors()` memproses antrean gagal langsung dari payload lokal tanpa bergantung pada koneksi jaringan Cloud.
- **Startup Catch-Up:** Pada saat boot, backend memindai rekonsiliasi record Cloud terbaru via `catch_up_unmirrored_from_cloud()` untuk menjamin tidak ada record yang hilang akibat crash proses sebelum mirror dijadwalkan.

---

## 3. Matriks Subsistem dan Jalur Database

| Subsistem | Endpoint API | Repository Method | Tabel Supabase Cloud | Operasi | Perilaku Saat Cloud Error |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **Telemetry Ingestion** | `POST /api/telemetry/ingest` | `insert_telemetry_events` | `telemetry_events`, `hosts` | Write | HTTP 500, collector retry (cursor aman) |
| **Collector Heartbeat** | `POST /api/telemetry/heartbeat` | `upsert_host` | `hosts` | Write | HTTP 500, host status un-updated |
| **Host Management** | `GET /api/hosts`, `GET /api/hosts/{id}` | `list_hosts`, `get_host_by_id` | `hosts` | Read | HTTP 500, fail loud |
| **System Status** | `GET /api/system/status` | `get_system_status` | `system_status` | Read | HTTP 500, fail loud |
| **Alert Management** | `GET /api/alerts`, `GET /api/alerts/{id}` | `list_alerts`, `get_alert_by_id` | `alerts` | Read | HTTP 500, fail loud |
| **Alert Ingestion** | Rules Engine (internal) | `insert_alerts` | `fn_ingest_alert_with_evidence` (RPC) | Write | Atomic rollback, fail loud |
| **Alert Evidence** | `GET /api/alerts/{id}/evidence` | `get_alert_evidence` | `alert_evidence`, `telemetry_events` | Read | HTTP 500, host isolation enforce |
| **Security Checker** | `POST /api/security/runs`, `GET ...` | `insert_security_check_run` | `security_check_runs`, `security_findings` | Write/Read | RuntimeError, fail loud |
| **Incident Creation** | `POST /api/incidents/correlate` | `upsert_incident` | `incidents`, `incident_alerts`, `incident_risk_factors` | Write | Multi-table atomic, fail loud |
| **Incident Query** | `GET /api/incidents`, `GET .../{id}` | `list_incidents`, `get_incident_by_id` | `incidents`, `incident_alerts`, `incident_risk_factors` | Read | HTTP 500, fail loud |
| **Incident Status** | `PATCH /api/incidents/{id}/status` | `update_incident_status` | `incidents`, `incident_status_history` | Write | Audit trail persisted, fail loud |
| **Incident Timeline** | `GET /api/incidents/{id}/timeline` | `get_incident_timeline` | `incident_timeline`, `alert_evidence` | Read | Sorted chronological, fail loud |
| **AI Investigation** | `POST /api/incidents/{id}/analyze` | `save_ai_analysis` | `ai_analyses` | Write | Grounded, SSoT risk locked |
| **AI Query** | `GET /api/incidents/{id}/analysis/latest` | `get_latest_ai_analysis` | `ai_analyses` | Read | HTTP 404 if missing, 500 on err |
| **Incidents Summary** | `GET /api/incidents/summary` | `get_incidents_summary` | `incidents` (aggregates) | Read | Real-time Cloud metrics |
| **Security Summary** | `GET /api/security/summary` | `get_security_summary` | `security_findings`, `security_check_runs` | Read | Real-time Cloud metrics |

---

## 4. Keamanan dan Kontrol Akses (RLS & Service Role)

1. **Row Level Security (RLS):** Diaktifkan di seluruh tabel database Supabase Cloud.
2. **Revocation Akses Publik/Anonim:** Seluruh hak akses `SELECT`, `INSERT`, `UPDATE`, `DELETE` dicabut (`REVOKE ALL`) dari role `anon` dan `authenticated`. Akses tanpa token resmi mengembalikan `HTTP 401 Unauthorized`.
3. **Least Privilege Backend Service Role:** Backend berkomunikasi secara privat menggunakan `SUPABASE_SERVICE_ROLE_KEY` melalui HTTPS terenkripsi. Key ini tidak pernah diekspos ke frontend atau browser.
4. **Proteksi Fungsi Atomik (RPC):** `fn_ingest_alert_with_evidence` didefinisikan dengan `SECURITY DEFINER` dan membatasi `search_path = public, pg_temp` untuk mengeliminasi kerentanan search path hijacking.

