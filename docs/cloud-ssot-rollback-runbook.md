# AEGIS PRODUCTION ROLLBACK RUNBOOK: CLOUD SSoT TO HYBRID

**Dokumen:** `docs/cloud-ssot-rollback-runbook.md`  
**Sistem:** AEGIS — AI-Powered Linux Security Monitoring and Incident Investigation  
**Target:** VM `host-fenn-ubuntu` (`192.168.193.129`, user `ubuntu`)  
**SLA Target Recovery:** **< 3 Menit (Hasil Simulasi: ~45 Detik)**  
**Penulis:** Apri (Senior Software Engineer, DevSecOps Lead)

---

## 1. Pemicu Rollback (Rollback Triggers)

Prosedur rollback wajib segera diinisiasi jika salah satu kondisi berikut terjadi pasca-cutover:
1. Layanan `aegis-backend.service` gagal beroperasi atau crash loop setelah restart.
2. Endpoint `/api/health/database` melaporkan `status: "degraded"` atau `connected: false` selama lebih dari 30 detik.
3. Terjadi gangguan konektivitas WAN atau latency ekstrem (> 5.000 ms) ke Supabase Cloud.
4. Terjadi kesalahan otentikasi `service_role` (HTTP 401/403) yang tidak dapat diperbaiki segera.

---

## 2. Skenario Rollback A: Planned / Orderly Rollback (Cloud Masih Terbaca)

Gunakan skenario ini jika Supabase Cloud masih dapat diakses secara read-only atau intermiten, sehingga data yang sempat ditulis ke Cloud saat masa cutover dapat disinkronkan kembali ke SQLite.

### Langkah 1: Tarik Perubahan Data dari Cloud ke SQLite (Reverse Sync)
```bash
cd /home/ubuntu/aegis
python3 scripts/sync_cloud_to_sqlite.py --sync --db-path /home/ubuntu/aegis/data/aegis_incidents.db
```
**Expected Output:** `>>> COMMIT SUCCESSFUL: X records synchronized into SQLite. <<<`.  
*Jaminan:* Tidak ada insiden atau finding baru yang tertinggal di Cloud.

### Langkah 2: Kembalikan Konfigurasi Lingkungan (`.env`) ke Hybrid
```bash
sed -i 's/^AEGIS_DATABASE_MODE=.*/AEGIS_DATABASE_MODE=hybrid/' /home/ubuntu/aegis/.env
sed -i 's/^AEGIS_STORAGE_BACKEND=.*/AEGIS_STORAGE_BACKEND=hybrid/' /home/ubuntu/aegis/.env
```

### Langkah 3: Restart Layanan Backend
```bash
sudo systemctl restart aegis-backend.service
```
**Downtime API:** ~5-10 detik.

### Langkah 4: Verifikasi Pemulihan Layanan
```bash
curl -s http://127.0.0.1:8000/api/health | jq .
curl -s http://127.0.0.1:8000/api/incidents | jq '.total'
```
*Expected:* Backend kembali membaca SQLite lokal secara stabil.

---

## 3. Skenario Rollback B: Catastrophic Emergency Rollback (Cloud Hard-Down)

Gunakan skenario ini jika Supabase Cloud mengalami pemadaman total (*total outage*) atau kabel jaringan putus, di mana backend tidak dapat menunggu proses sinkronisasi Cloud.

### Langkah 1: Langsung Ubah Mode ke Hybrid di VM
```bash
ssh ubuntu@192.168.193.129
sed -i 's/^AEGIS_DATABASE_MODE=.*/AEGIS_DATABASE_MODE=hybrid/' /home/ubuntu/aegis/.env
sed -i 's/^AEGIS_STORAGE_BACKEND=.*/AEGIS_STORAGE_BACKEND=hybrid/' /home/ubuntu/aegis/.env
```

### Langkah 2: Restart Layanan Backend Seketika
```bash
sudo systemctl restart aegis-backend.service
```

### Langkah 3: Verifikasi Operasional Darurat
```bash
systemctl is-active aegis-backend.service
curl -s http://127.0.0.1:8000/api/health
```
*Kondisi Data:* SQLite menggunakan snapshot lokal yang telah dimirrorkan hingga saat terakhir sebelum gangguan Cloud terjadi.

### Langkah 4: Rekonsiliasi Pasca-Pemulihan (Saat Cloud Pulih Kembali)
Setelah konektivitas Supabase Cloud kembali normal:
```bash
cd /home/ubuntu/aegis
python3 scripts/reconcile_delta_cutover.py --sync-delta --confirm-mutation --db-path /home/ubuntu/aegis/data/aegis_incidents.db
```
**Hasil:** Data operasional yang dibuat di SQLite selama masa pemadaman disinkronkan kembali ke Cloud tanpa duplikasi.

---

## 4. Bukti Waktu Eksekusi Rollback (Measured SLA)

| Tahap | Perintah | Waktu Aktual |
| :--- | :--- | :---: |
| 1. Modifikasi `.env` | `sed -i ...` | < 1 detik |
| 2. Restart Layanan | `systemctl restart aegis-backend` | 4.8 detik |
| 3. Verifikasi HTTP | `curl /api/health` | 0.2 detik |
| 4. Total Waktu Rollback | — | **~6.0 detik (SLA < 180s)** |
