# AEGIS PRODUCTION CUTOVER RUNBOOK: HYBRID TO CLOUD SSoT

**Dokumen:** `docs/cloud-ssot-deployment-runbook.md`  
**Sistem:** AEGIS — AI-Powered Linux Security Monitoring and Incident Investigation  
**Target:** VM `host-fenn-ubuntu` (`192.168.193.129`, user `ubuntu`) & Supabase Cloud  
**Otorisasi:** **MENUNGGU PERSETUJUAN EKSPLISIT PROJECT OWNER (GATE 2)**  
**Penulis:** Apri (Senior Software Engineer, DevSecOps Lead)

---

## 1. Persyaratan Awal (Preflight Checklist)

Sebelum memulai eksekusi cutover, pastikan seluruh kondisi berikut terpenuhi:
- [ ] Otorisasi tertulis dari Project Owner telah diterima.
- [ ] Konektivitas jaringan VM `fenn` ke Supabase Cloud (`https://hiwfbmwgnpnwaszltqwb.supabase.co`) terverifikasi aktif (HTTP/2 200).
- [ ] Status layanan saat ini: `aegis-backend.service` (ACTIVE), `aegis-collector.service` (ACTIVE).
- [ ] Repository remote GitHub sinkron pada commit target.

---

## 2. Langkah-Langkah Eksekusi Cutover

### Langkah 1: Snapshot Backup SQLite Terkini di VM
*Tujuan: Mengamankan kondisi database lokal sesaat sebelum cutover dimulai.*
```bash
ssh ubuntu@192.168.193.129
BACKUP_TS=$(date +%Y%m%d_%H%M%S)
cp /home/ubuntu/aegis/data/aegis_incidents.db /home/ubuntu/aegis/data/backups/cutover_snapshot_${BACKUP_TS}.db
sha256sum /home/ubuntu/aegis/data/backups/cutover_snapshot_${BACKUP_TS}.db > /home/ubuntu/aegis/data/backups/cutover_snapshot_${BACKUP_TS}.db.sha256
```
**Expected Output:** File backup terbuat dengan ukuran ~299,008 bytes dan hash SHA256 tercatat.  
**Abort Criteria:** Pembuatan backup gagal atau disk penuh.

---

### Langkah 2: Rekonsiliasi Delta Pre-Cutover (Dry-Run Audit)
*Tujuan: Memverifikasi keselarasan seluruh data operasional antara SQLite dan Supabase Cloud.*
```bash
cd /home/ubuntu/aegis
python3 scripts/reconcile_delta_cutover.py --db-path /home/ubuntu/aegis/data/aegis_incidents.db
```
**Expected Output:** `Foreign Key Audit: 0 violations` dan seluruh tabel operasional terkonfirmasi selaras.  
**Abort Criteria:** Ditemukan foreign key corruption atau missing host link.

---

### Langkah 3: Deploy Kode Git Terbaru ke VM
*Tujuan: Memperbarui kode backend ke commit final yang mendukung fail-loud routing.*
```bash
cd /home/ubuntu/aegis
git fetch origin main
git pull origin main
```
**Expected Output:** Git HEAD berada pada target commit dengan working tree bersih (`nothing to commit, working tree clean`).  
**Abort Criteria:** Git merge conflict atau branch mismatch.

---

### Langkah 4: Pembaruan Konfigurasi Lingkungan (`.env`)
*Tujuan: Mengaktifkan mode Unified Cloud SSoT pada konfigurasi backend.*
```bash
# Tambahkan atau perbarui baris konfigurasi berikut di /home/ubuntu/aegis/.env:
sed -i 's/^AEGIS_DATABASE_MODE=.*/AEGIS_DATABASE_MODE=cloud_ssot/' /home/ubuntu/aegis/.env || echo "AEGIS_DATABASE_MODE=cloud_ssot" >> /home/ubuntu/aegis/.env
sed -i 's/^AEGIS_STORAGE_BACKEND=.*/AEGIS_STORAGE_BACKEND=supabase/' /home/ubuntu/aegis/.env || echo "AEGIS_STORAGE_BACKEND=supabase" >> /home/ubuntu/aegis/.env
```
**Expected Output:** File `.env` memuat `AEGIS_DATABASE_MODE=cloud_ssot` dan `AEGIS_STORAGE_BACKEND=supabase`.  
**Abort Criteria:** File `.env` corrupt atau izin file terganggu.

---

### Langkah 5: Restart Terencana Layanan Backend
*Tujuan: Me-reload aplikasi FastAPI dengan konfigurasi Cloud SSoT.*
> [!NOTE]
> Layanan `aegis-collector.service` **TIDAK DIRESTART** dan terus berjalan normal untuk menjamin zero telemetry loss.
```bash
sudo systemctl restart aegis-backend.service
```
**Estimasi Downtime:** ~5 hingga 10 detik (hanya reload proses FastAPI Uvicorn).  
**Abort Criteria:** Layanan gagal restart (`systemctl is-active aegis-backend` != `active`).

---

### Langkah 6: Protokol Verifikasi Pasca-Cutover (Smoke Tests)
Jalankan verifikasi fungsional segera setelah restart:
1. **Periksa Status Layanan:**
   ```bash
   systemctl status aegis-backend.service --no-pager
   systemctl status aegis-collector.service --no-pager
   ```
2. **Uji Endpoint API Health & Database:**
   ```bash
   curl -s http://127.0.0.1:8000/api/health | jq .
   curl -s http://127.0.0.1:8000/api/health/database | jq .
   ```
   *Expected:* `status: "healthy"`, `connected: true`.
3. **Uji Akses Data Insiden Cloud:**
   ```bash
   curl -s http://127.0.0.1:8000/api/incidents | jq '.total'
   ```
   *Expected:* Total insiden menampilkan jumlah record Cloud secara akurat.
4. **Verifikasi Stream Kolektor Telemetri:**
   ```bash
   journalctl -u aegis-collector.service -n 20 --no-pager
   ```
   *Expected:* Log mencatat `Successfully ingested X events` tanpa `Delivery failed`.

---

## 3. Matriks Keputusan Cutover (GO / NO-GO)

- **Kondisi GO:** Semua 4 verifikasi pasca-cutover bernilai sukses dalam waktu < 2 menit sejak restart.
- **Kondisi ABORT & ROLLBACK:** Terjadi kegagalan koneksi Cloud, health check berstatus degraded, atau API tidak merespon dalam waktu > 30 detik.

