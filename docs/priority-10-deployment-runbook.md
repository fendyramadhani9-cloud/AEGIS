# AEGIS Prioritas 10 — Production Deployment Runbook & Rollback Procedure
**Panduan Deployment Kesiapan Produksi (Staging to Production Ready)**

> [!IMPORTANT]
> **Status Operasional Saat Ini: NO-GO / ON HOLD UNTUK DEPLOYMENT KE VM.**
> Dokumen ini adalah panduan kesiapan deployment formal yang disiapkan untuk digunakan HANYA KETIKA Project Owner memberikan persetujuan eksplisit. Jangan mengeksekusi langkah deployment aktif tanpa otorisasi terpisah.

---

## 1. Prasyarat Deployment (Prerequisites)

Sebelum melakukan deployment ke lingkungan VM produksi (`fenn`), seluruh kriteria berikut wajib terpenuhi:
1. **Otorisasi Tertulis:** Persetujuan formal dari Project Owner.
2. **Git Integrity:** Seluruh commit Prioritas 10 telah di-push dan diverifikasi sinkron di `origin/main`.
3. **VM Service Health:** `aegis-backend.service` dan `aegis-collector.service` terbukti aktif tanpa error.
4. **Database Mode:** Sistem tetap beroperasi dalam **Hybrid Mode** (SQLite lokal sebagai database operasional aktif; Supabase Cloud tetap read-only).
5. **Backup Selesai:** Database SQLite lokal (`data/aegis_incidents.db`) telah di-checkpoint dan di-backup secara penuh.

---

## 2. Berkas yang Berubah (Artifact Inventory)

Deployment Prioritas 10 mencakup pembaruan pada berkas inti berikut:

| Berkas | Jenis Perubahan | Deskripsi Fungsional |
| :--- | :---: | :--- |
| `aegis_backend/ai_provider.py` | Modifikasi | Validator forensic grounding, negation/inquiry engine, relevance check, timeline normalizer |
| `aegis_backend/incident_context_builder.py` | Modifikasi | Stratified Forensic Sampling (5-bucket) dan preservasi 100% ID whitelist |
| `aegis_backend/incident_service.py` | Modifikasi | Penguncian SSoT risk score pada level service sebelum persistensi |
| `aegis_backend/repository.py` | Modifikasi | Penambahan kueri `get_incident_risk_factors()` dan sinkronisasi repositori |
| `aegis_backend/schemas.py` | Modifikasi | Pydantic v2 resilient pre-validators untuk payload malformed |
| `scripts/audit_cloud_dependencies.py` | Modifikasi | Penyesuaian path audit database lokal |
| `tests/test_ai_adversarial_validation.py` | Berkas Baru | 13 skenario uji adversarial deterministik |
| `tests/test_ai_quality_evaluation.py` | Berkas Baru | 5 uji evaluasi kualitas taksonomi forensik |
| `tests/verify_incident_migration.cjs` | Modifikasi | Penyesuaian assertion rollback migrasi non-destruktif |

---

## 3. Prosedur Pra-Deployment (Pre-Deployment Checklist)

Jalankan di workstation sebelum deployment:
```powershell
# 1. Pastikan seluruh test suite lulus 100%
.venv\Scripts\python -m pytest

# 2. Pastikan build frontend dashboard berhasil
npm --prefix dashboard run build

# 3. Verifikasi remote Git HEAD sama dengan commit lokal
git rev-parse HEAD
git ls-remote origin refs/heads/main
```

Jalankan di VM `fenn` (melalui SSH, read-only):
```bash
# 4. Periksa status layanan saat ini
systemctl is-active aegis-backend aegis-collector

# 5. Buat checkpoint dan backup database operasional lokal
sqlite3 /home/ubuntu/aegis/data/aegis_incidents.db "PRAGMA wal_checkpoint(TRUNCATE);"
cp /home/ubuntu/aegis/data/aegis_incidents.db /home/ubuntu/aegis/data/aegis_incidents.db.bak_pre_p10_$(date +%Y%m%d_%H%M%S)
```

---

## 4. Prosedur Deployment Langkah-demi-Langkah (Deployment Procedure)

*(Hanya dieksekusi setelah persetujuan Project Owner diberikan)*

```bash
# Langkah 1: Masuk ke direktori repositori VM
cd /home/ubuntu/aegis

# Langkah 2: Ambil pembaruan kode dari remote origin
git fetch origin main
git checkout main
git pull origin main

# Langkah 3: Verifikasi commit hash pada VM
git rev-parse HEAD
# (Pastikan hash sama persis dengan commit yang disetujui, misal 48edc41)

# Langkah 4: Restart layanan backend secara terkontrol (zero collector downtime)
sudo systemctl restart aegis-backend.service

# Langkah 5: Verifikasi status layanan backend
sudo systemctl status aegis-backend.service --no-pager
```

---

## 5. Prosedur Validasi Pasca-Deployment (Post-Deployment Health Checks)

```bash
# 1. Uji endpoint health backend
curl -s http://127.0.0.1:8000/api/health | jq .

# 2. Uji endpoint AI health
curl -s http://127.0.0.1:8000/api/ai/health | jq .

# 3. Jalankan pengujian validasi AI di VM
.venv/bin/python3 -m pytest tests/test_ai_adversarial_validation.py -v

# 4. Periksa log layanan dari potensi exception
journalctl -u aegis-backend.service -n 50 --no-pager
```

---

## 6. Prosedur Rollback Cepat (Rollback Procedure)

Jika terjadi anomali kritis, exception, atau penurunan performa pada backend setelah deployment:

```bash
# Langkah 1: Rollback source code ke commit stabil sebelumnya (1e94c18)
cd /home/ubuntu/aegis
git checkout 1e94c18d2574c4f8953eabc85f2ba8582b8724a6

# Langkah 2: Pulihkan database jika terjadi korupsi data (opsional)
# cp /home/ubuntu/aegis/data/aegis_incidents.db.bak_pre_p10_* /home/ubuntu/aegis/data/aegis_incidents.db

# Langkah 3: Restart layanan backend
sudo systemctl restart aegis-backend.service

# Langkah 4: Verifikasi kesehatan layanan setelah rollback
systemctl is-active aegis-backend
curl -s http://127.0.0.1:8000/api/health | jq .
```

