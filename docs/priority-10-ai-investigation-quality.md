# AEGIS Prioritas 10 — AI Investigation Quality & Forensic Grounding Architecture

Dokumen ini mendefinisikan arsitektur final, spesifikasi teknis, dan jaminan keabsahan forensik untuk sistem investigasi berbasis kecerdasan buatan (AI Incident Investigation) pada platform AEGIS.

---

## 1. Arsitektur Alur Data End-to-End

Sistem investigasi insiden AEGIS menerapkan arsitektur *unidirectional data flow* yang terlindungi oleh batas sanitasi dan validasi grounding:

```text
[ Raw Telemetry & Detection Alerts ]
                 │
                 ▼
     [ TelemetrySanitizer ]  (Masking token, secret, kredensial)
                 │
                 ▼
  [ IncidentContextBuilder ] (Stratified Forensic Sampling, Budget: 15 events)
                 │            (Whitelists 100% allowed_evidence_ids)
                 │
                 ├───────────────────────────────┐
                 ▼                               ▼
    [ RiskAssessmentEngine ]            [ AI Provider ]
    (Deterministik SSoT: 0-100)       (Gemini / OpenAI / Mock)
                 │                               │
                 │                    [ Raw AI Output JSON ]
                 │                               │
                 ▼                               ▼
  ┌─────────────────────────────────────────────────────────────┐
  │         Forensic Grounding & Semantic Quality Validator     │
  │  1. SSoT Immutability (Risk score & level locked)           │
  │  2. Evidence Whitelisting (Anti-hallucination ID filter)    │
  │  3. Negation & Inquiry Guard (Preserves negative findings)  │
  │  4. Technique Semantic Relevance (Sudo/Auth verification)   │
  │  5. 4-Tier Taxonomy Separation (Facts/Inferences/Hypotheses)│
  │  6. Quantitative Fidelity (Single vs multiple verification) │
  │  7. Timeline Chronology Normalization & Sequential Steps    │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
                     [ Validated AIAnalysisItem ]
                                 │
                                 ▼
                [ IncidentService & SQLite Storage ]
                                 │
                                 ▼
               [ FastHTTP API (/api/incidents/:id) ]
                                 │
                                 ▼
                  [ Dashboard: IncidentDetail.tsx ]
```

---

## 2. Single Source of Truth (SSoT) untuk Penilaian Risiko

AEGIS menegakkan pemisahan mutlak antara kalkulasi risiko deterministik dan penalaran naratif LLM:

1. **Otoritas Tunggal:** `RiskAssessmentEngine` adalah satu-satunya entitas yang berhak menghitung `risk_score` (0–100) dan menentukan `risk_level` (`low`, `medium`, `high`, `critical`).
2. **Formula Transparan:**
   $$\text{RiskScore} = \min\left(100, \text{BaseSeverity} + \text{MultiAlert} + \text{Progression} + \text{EvidenceWeight} + \text{PostureDeduction}\right)$$
3. **Immutability Enforcement:**
   - LLM dilarang memanipulasi skor risiko. Jika model mengembalikan nilai sembarang (seperti 999, -50, `NaN`, atau string), validator grounding secara otomatis menimpa skor tersebut dengan nilai resmi dari `context.risk_score`.
   - Lapisan servis `IncidentService.analyze_incident()` secara independen mengunci kembali `analysis_dict["risk_score"] = incident_data["risk_score"]` sebelum persistensi database.
4. **Faktor Risiko (Risk Factors):**
   - Seluruh rincian poin dan kategori faktor risiko (`severity`, `multi_alert`, `progression`, `evidence`, `posture`) disuntikkan ke dalam prompt LLM sebagai fakta matematis dan disimpan ke tabel `incident_risk_factors`.

---

## 3. Four-Tier Forensic Taxonomy

Untuk mencegah halusinasi yang menyamar sebagai kesimpulan pasti, AEGIS membagi hasil investigasi ke dalam 4 tier ketat:

| Tier | Kategori | Definisi & Batasan Forensik | Perilaku Jika Tidak Terbukti |
| :---: | :--- | :--- | :--- |
| **Tier 1** | **FACTS** (Empirical Observations) | Pernyataan yang mencerminkan telemetri langsung atau entri log konkret. Wajib memiliki `evidence_id` valid yang terdaftar pada `context.allowed_evidence_ids`. Tidak boleh memuat spekulasi. | Jika evidence ID fiktif atau klaim memuat kata kunci ancaman tanpa bukti, entri disaring atau diturunkan. |
| **Tier 2** | **INFERENCES** (Logical Deductions) | Kesimpulan logis yang ditarik dari korelasi dua atau lebih fakta telemetri. Wajib mencantumkan `supporting_evidence_ids` yang relevan secara semantik serta narasi `rationale`. | Jika bukti yang dirujuk tidak relevan secara semantik (misal klaim sudo berdasar auth failure), inferensi diturunkan ke Tier 3. |
| **Tier 3** | **HYPOTHESES** (Working Theories) | Dugaan atau skenario potensial yang belum didukung bukti langsung. **Wajib** berstatus `unverified` dan **wajib** menyertakan `investigation_step` konkret (langkah audit verifikasi). | Merupakan wadah penampung non-destruktif untuk klaim ancaman yang belum tervalidasi. |
| **Tier 4** | **UNKNOWNS** (Forensic Limitations) | Keterbatasan telemetri dan data gap yang tidak tersedia pada host (misalnya ketiadaan jejak pohon proses atau log NetFlow). Wajib menjelaskan `data_gap` dan `impact`. | Memastikan analis memahami batas visibilitas sebelum mengambil keputusan remediasi. |

---

## 4. Mekanisme Semantic Grounding & Evidence Relevance

### A. Negation & Inquiry Parsing Engine
Sistem mendeteksi apakah penyebutan istilah ancaman (*exfiltration*, *C2*, *lateral movement*, *persistence*) berada dalam konteks negasi atau pertanyaan investigatif:
- **Negation:** Pernyataan seperti *"No evidence of data exfiltration"* atau *"Tidak ditemukan bukti eksfiltrasi"* diakui sebagai **honest negative finding** dan dipertahankan di Tier 2 Inferences tanpa disinsentif atau caveat palsu.
- **Inquiry:** Pernyataan seperti *"Investigate whether lateral movement occurred"* atau *"Periksa apakah terdapat mekanisme persistensi"* diakui sebagai panduan investigasi operasional.
- **Affirmative Assertion:** Pernyataan seperti *"Adversary completed sensitive data exfiltration"* yang tidak didukung telemetri akan langsung diturunkan ke Tier 3 Hypotheses (`unverified`) dengan pencatatan gap di Tier 4 Unknowns.

### B. Semantic Evidence Relevance
Memastikan bahwa bukti yang dikutip secara semantik mendukung teknik yang diklaim:
- **Eskalasi Privilese / Sudo:** Jika inferensi mengklaim eksekusi perintah sudo atau eskalasi privilese, telemetri bukti yang dikutip wajib mengandung penanda relevan (`sudo:`, `COMMAND=`, `uid=0`, `root:`, `session opened for user root`). Jika hanya berupa kegagalan autentikasi SSH (`Failed password`), klaim dianggap tidak relevan dan didemosikan ke hipotesis.
- **Autentikasi Berhasil:** Jika inferensi mengklaim login berhasil, bukti yang dikutip tidak boleh hanya memuat log kegagalan (`Failed password`, `Invalid user`).

---

## 5. Stratified Forensic Sampling (1,000+ Events)

Pada serangan berskala masif (seperti badai brute-force dengan ribuan percobaan login), token budgeting membatasi telemetri yang dikirim ke LLM maksimal 15 event:
- **Algoritma 5-Bucket Sampling:**
  1. **Bucket 1 (Alert Triggers):** Event yang memicu alert deteksi (hingga 4 event).
  2. **Bucket 2 (Critical Milestones):** Event perubahan status penting: autentikasi sukses (`accepted`, `session opened`) dan eksekusi sudo (`sudo:`, `COMMAND=`, `uid=0`).
  3. **Bucket 3 (Temporal Boundaries):** Event paling awal (awal serangan) dan event paling akhir (kulminasi).
  4. **Bucket 4 & 5 (Telemetry Anomalies):** Sampel representatif kegagalan login dan anomali lainnya.
- **Jaminan Integritas:**
  - Event penting tidak akan pernah tereliminasi oleh ratusan log kegagalan berulang.
  - Seluruh item yang dipilih diurutkan secara kronologis untuk menjaga narasi serangan yang koheren.
  - Whitelist `allowed_evidence_ids` tetap mencakup **100% ID dari seluruh event yang ada di database**, sehingga jika model merujuk event valid di luar sampel, ID tersebut tidak disaring secara salah.

---

## 6. Integrasi Multi-Provider & Penanganan Error

Validator grounding berlaku universal dan identik pada seluruh provider yang didukung:
1. **Google Gemini (`GeminiProvider`):** Menggunakan REST API langsung dengan key rotation otomatis (AEGIS_LLM_API_KEY, AEGIS1–3) dan prompt anti-halusinasi JSON mode.
2. **OpenAI-Compatible (`OpenAICompatibleProvider`):** Mendukung endpoint eksternal atau gateway lokal (Nine Router, vLLM, Ollama) dengan validasi skema identik.
3. **Mock Provider (`MockAIProvider`):** Evaluator deterministik offline untuk pengujian unit dan CI/CD tanpa ketergantungan jaringan.
4. **Fallback Provider (`NullAIProvider`):** Menangani kondisi offline dengan playbook fallback deterministik terstruktur tanpa membocorkan kredensial.
5. **Honest Failure Status:** Jika terjadi kegagalan jaringan, timeout, atau HTTP error (401, 403, 429, 500), status dilaporkan sebagai `failed`, tidak pernah dimanipulasi sebagai `completed`.

