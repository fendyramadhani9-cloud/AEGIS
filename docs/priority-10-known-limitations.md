# AEGIS Prioritas 10 — Known Limitations & Epistemological Boundaries

Dokumen ini mendokumentasikan secara transparan batasan teknis, keterbatasan deterministik, dan asumsi operasional sistem AI Investigation AEGIS.

---

## 1. Batasan Regex dalam Grounding Semantik

- **Karakteristik:** Validator forensic grounding menggunakan ekspresi reguler terstruktur (regex) untuk membedakan istilah ancaman (*exfiltration*, *C2*, *lateral movement*, *persistence*), mendeteksi klausa negasi, dan memverifikasi relevansi isi bukti.
- **Keterbatasan:**
  - Regex mengevaluasi pola leksikal pada jendela teks (60 karakter sekitar kata kunci). Pola ini efektif untuk mendeteksi konstruksi standar bahasa Indonesia dan Inggris, tetapi tidak dapat memahami metafora sastra yang ambigu, sarkasme, atau negasi terselubung bersarang kompleks yang tidak biasa dalam log teknis.
  - Jika seorang analis atau model menggunakan ejaan yang mengalami salah ketik ekstrem pada kata kunci negasi (misalnya *"tidakkk adaa buktiii"*), validator mungkin memperlakukannya sebagai klaim afirmatif.
- **Mitigasi:** Standar pelaporan keamanan pada antarmuka AEGIS menyertakan anotasi bahwa hasil AI adalah alat bantu investigasi awal dan keputusan status final tetap berada di tangan analis keamanan (Human-in-the-Loop).

---

## 2. Batasan Verifikasi Relevansi Semantik Bukti

- **Karakteristik:** Validator memeriksa apakah bukti yang dirujuk oleh inferensi teknik memuat penanda spesifik (misalnya `sudo:`, `COMMAND=`, `uid=0` untuk eskalasi privilese, atau `accepted`, `session opened` untuk autentikasi sukses).
- **Keterbatasan:**
  - Jika attacker mengeksekusi eskalasi privilese melalui teknik *kernel exploit* atau eksploitasi SUID biner kustom yang tidak memanggil sudo/PAM, log auth standar mungkin tidak memunculkan string `sudo:`. Dalam kasus tersebut, klaim model akan diklasifikasikan sebagai *unverified hypothesis* karena ketiadaan telemetri langsung, meskipun secara realita eksploitasi benar-benar terjadi.
- **Mitigasi:** Klasifikasi ke Tier 3 (Hypotheses) bukanlah penghapusan; sistem menyertakan langkah verifikasi auditd konkret (`EXECVE uid=0`) di dashboard sehingga analis dapat memeriksa biner kustom secara langsung.

---

## 3. Batasan Non-Deterministik LLM & Konsistensi Provider

- **Karakteristik:** Model bahasa komersial (Google Gemini, OpenAI GPT, atau LLM lokal) memiliki sifat probabilistik inheren bahkan pada parameter temperatur rendah (`temperature=0.1`).
- **Keterbatasan:**
  - Meskipun prompt mewajibkan JSON skema tertentu, format narasi pada `executive_summary` dan `attack_scenario` dapat sedikit bervariasi antar-pemanggilan.
  - Perbedaan kemampuan penalaran antar-model (misalnya Gemini 1.5 Flash vs GPT-4o-mini vs model lokal 8B) dapat menghasilkan rincian narasi yang berbeda tingkat kedalamannya.
- **Mitigasi:** Skor risiko (`risk_score`) dan level risiko (`risk_level`) **100% deterministik** karena dihitung oleh `RiskAssessmentEngine`, bukan oleh LLM. Nilai risiko tidak pernah terpengaruh oleh non-determinisme model.

---

## 4. Risiko Sampling Telemetri pada Serangan Skala Masif

- **Karakteristik:** Serangan brute-force masif dapat menghasilkan ribuan event dalam beberapa menit. Context builder menerapkan *Stratified Forensic Sampling* maksimal 15 event untuk prompt LLM.
- **Keterbatasan:**
  - Dari 1,000+ event, hanya 15 event terpilih yang dikirimkan ke dalam prompt model (mencakup pemicu alert, autentikasi sukses, eksekusi privilese, dan anchor batas waktu).
  - Meskipun `allowed_evidence_ids` mempertahankan 100% ID di database, model hanya dapat membaca konten teks dari 15 event sampel tersebut. Event yang berada di luar sampel hanya dapat dirujuk jika analis memeriksanya secara manual.
- **Mitigasi:** Dashboard antarmuka menyediakan tab *Correlated Alerts & Supporting Telemetry Evidence* yang menampilkan seluruh dataset telemetri lengkap kepada analis tanpa batasan sampling.

---

## 5. Keharusan Human-in-the-Loop (Analisis Manusia)

- **Prinsip Operasional:** AI Investigation pada AEGIS dirancang sebagai sistem pendukung keputusan (*decision support system*), bukan pengambil keputusan otonom tunggal (*autonomous actor*).
- **Aturan Operasional:** Perubahan status insiden menjadi `confirmed`, `contained`, `false_positive`, atau `resolved` **wajib** dilakukan melalui konfirmasi analis manusia melalui tombol *Update Status* pada dashboard.

