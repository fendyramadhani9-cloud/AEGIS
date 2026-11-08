# AEGIS Prioritas 10 — Release Notes
**AI Investigation Quality Hardening, Forensic Grounding, and Adversarial Defense**

---

## 1. Ikhtisar Rilis (Release Overview)

Pembaruan AEGIS Prioritas 10 mengubah kapabilitas investigasi insiden dari sekadar penyusun narasi menjadi mesin analisis forensik berbasis bukti yang dapat dipertanggungjawabkan (*grounded, evidence-backed forensic reasoning*). 

Sistem ini menyelesaikan masalah utama halusinasi LLM pada operasi investigasi Linux: klaim ancaman fiktif tanpa bukti (seperti eksfiltrasi data atau komunikasi C2 yang tidak pernah terjadi), manipulasi skor risiko oleh model, ketiadaan pemisahan antara fakta dan hipotesis, serta penggusuran bukti penting pada badai log bervolume tinggi.

---

## 2. Fitur Baru & Peningkatan Utama

### A. 4-Tier Forensic Taxonomy
- **Facts (Tier 1):** Pengamatan langsung telemetri log dengan bukti ID yang terverifikasi.
- **Inferences (Tier 2):** Kesimpulan logis berbasis korelasi fakta dengan bukti semantik yang relevan.
- **Hypotheses (Tier 3):** Dugaan potensial yang secara otomatis dikarantina dengan status `unverified` dan langkah verifikasi audit konkret.
- **Unknowns (Tier 4):** Penjelasan eksplisit mengenai blind spot dan data gap forensik yang belum tersedia di host.

### B. Single Source of Truth (SSoT) Risk Score Defense
- Skor risiko (0–100) dan level risiko (`low`, `medium`, `high`, `critical`) secara mutlak dikendalikan oleh formula deterministik `RiskAssessmentEngine`.
- Model AI dilarang mengubah skor risiko; manipulasi nilai `NaN`, negatif, atau skor ekstrem otomatis ditolak dan dipulihkan ke nilai resmi.

### C. Negation & Inquiry Engine
- Mengenali konstruksi negasi forensik (*"No evidence of data exfiltration"*, *"Tidak ditemukan bukti eksfiltrasi"*) sebagai temuan forensik negatif yang valid, mencegah karantina yang keliru.
- Mengenali pertanyaan investigatif (*"Investigate whether lateral movement occurred"*) sebagai panduan operasional analis.

### D. Semantic Evidence Relevance Checking
- Memvalidasi bahwa isi telemetri bukti yang dirujuk benar-benar mendukung teknik serangan yang ditegaskan (misalnya klaim eskalasi privilese/sudo wajib merujuk log dengan marker `sudo:`, `COMMAND=`, atau `uid=0`, bukan sekadar log kegagalan login).

### E. Stratified Forensic Sampling (1,000+ Events)
- Algoritma sampling cerdas 5-bucket yang membatasi prompt maksimal 15 event tanpa mengorbankan milestone penting (autentikasi sukses, eksekusi sudo, anchor awal dan akhir serangan).
- Preservasi 100% ID bukti pada database whitelist.

### F. Normalisasi Timeline & Pemulihan Payload Malformed
- Mengurutkan entri timeline secara kronologis ascending dan menomori ulang langkah secara deterministik.
- Pre-validator Pydantic v2 yang tangguh terhadap respons model mentah yang tidak sesuai tipe data.

---

## 3. Catatan Kompatibilitas (Compatibility Notes)

- **Mode Operasional:** Sepenuhnya kompatibel dengan arsitektur **Hybrid Mode**. Berjalan di atas SQLite lokal tanpa mengubah skema Supabase Cloud.
- **Kompatibilitas API:** Skema HTTP API pada endpoint `/api/incidents/:id` dan `/api/incidents/:id/analyze` mempertahankan backward compatibility penuh.
- **Kompatibilitas Frontend:** Antarmuka dashboard React/Vite telah diperbarui untuk merender keempat tier taksonomi secara visual dan interaktif.

---

## 4. Hasil Verifikasi Pengujian

- **Total Test Suite:** 191/191 Lulus (100% PASS).
- **Adversarial Suite:** 13/13 Skenario Adversarial Lulus.
- **Security Scan:** 0 secret/kredensial pada seluruh perubahan kode.
- **Frontend Build:** Sukses tanpa peringatan tipe data (`tsc -b && vite build`).

---

## 5. Ringkasan Commit Git

- **Branch:** `main`
- **Target Remote:** `origin/main`
- **Status Produksi:** Deployment Ready (Menunggu persetujuan Project Owner).

