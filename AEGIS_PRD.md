# AEGIS — Product Requirements Document (PRD)

**Status:** Draft untuk pengembangan MVP  
**Versi:** 1.0  
**Fokus MVP:** Monitoring keamanan Linux dan investigasi insiden secara ringan

## 1. Ringkasan Produk

AEGIS adalah aplikasi monitoring keamanan Linux yang mengumpulkan sinyal keamanan dari host, mendeteksi aktivitas mencurigakan menggunakan aturan deterministik, membantu investigasi melalui analisis AI, dan menyusun laporan berdasarkan temuan yang benar-benar tercatat.

MVP berfokus pada Ubuntu Server dengan sumber log awal berupa log autentikasi SSH dan log Nginx. Agent berjalan di host Linux, sedangkan pemrosesan, penyimpanan, dashboard, analisis AI, dan pembuatan laporan dilakukan oleh backend.

### Prinsip utama
- Monitoring dan rule-based detection tetap berjalan meskipun layanan AI gagal.
- Agent bersifat read-only: tidak mengubah konfigurasi, menghentikan layanan, atau melakukan blocking otomatis.
- AI membantu menjelaskan dan mengontekstualisasikan data; AI bukan sumber utama deteksi.
- Data sensitif harus disaring sebelum dikirim ke layanan AI.
- Klaim “ringan” harus dibuktikan melalui pengukuran resource, bukan asumsi.

## 2. Masalah yang Ingin Diselesaikan

Administrator atau pelajar yang mengelola server Linux membutuhkan cara yang lebih mudah untuk:
- Mengetahui kondisi keamanan dasar host.
- Memantau aktivitas autentikasi dan web server.
- Menghubungkan event menjadi alert dan timeline insiden.
- Memahami alasan sebuah alert muncul dan bukti yang mendukungnya.
- Menghasilkan laporan harian atau laporan insiden tanpa merangkai data secara manual.

## 3. Tujuan MVP

1. Mengumpulkan data keamanan yang dipilih dari Ubuntu Server.
2. Menyediakan pemeriksaan konfigurasi keamanan dasar melalui Security Checker (SC).
3. Memantau log terpilih secara incremental melalui Runtime Monitor (RM).
4. Mendeteksi pola yang didukung menggunakan Rules Engine.
5. Menampilkan status host, temuan, alert, timeline, dan status pengumpulan data.
6. Menyediakan analisis AI terbatas untuk temuan SC dan alert RM.
7. Membuat laporan PDF dari data terstruktur yang tersimpan.
8. Menyediakan Emergency Evidence Mode yang terbatas, berizin, dan memiliki masa berlaku.

## 4. Non-Goals

MVP tidak bertujuan untuk:
- Memblokir IP, menghentikan proses, atau melakukan remediation otomatis.
- Mengklaim mendeteksi seluruh jenis serangan.
- Mendukung seluruh distribusi Linux sejak versi pertama.
- Mengirim seluruh isi log secara terus-menerus ke AI.
- Memberikan AI akses shell atau akses langsung ke object storage.
- Memulihkan log yang tidak pernah dikumpulkan atau sudah tidak tersedia.
- Menjadikan AI sebagai satu-satunya mekanisme deteksi.
- Mengoptimalkan demo sebelum aplikasi dan tool inti berfungsi.

## 5. Pengguna dan Peran

### Operator / Administrator
- Mendaftarkan dan memantau host.
- Melihat status agent, temuan, alert, dan timeline.
- Memulai atau menghentikan Emergency Evidence Mode.
- Membaca dan mengunduh laporan.

### Developer / Maintainer
- Mengembangkan agent, backend, parser, rules, dashboard, dan integrasi AI.
- Menambahkan sumber log dan aturan deteksi yang teruji.
- Memastikan data sensitif tidak bocor ke penyimpanan atau layanan eksternal.

## 6. Arsitektur Tingkat Tinggi

```text
Ubuntu Server
  └── AEGIS Agent
       ├── Security Checker (SC)
       └── Runtime Monitor (RM)
              │
              ▼
       Collector / API
              │
       Parser & Normalizer
              │
       Rules Engine ───────► Alerts / Findings
              │
       Database & Evidence Manager
              │
       AI Orchestrator ────► SC Analysis Agent
              │             RM Analysis Agent
              │             Reporting Agent
              ▼
          Dashboard / PDF Reports

Evidence files ──► Private S3-compatible Object Storage
                   (MinIO untuk development)
```

### Batas tanggung jawab
- SC dan RM adalah modul software pada agent Linux.
- SC Analysis Agent, RM Analysis Agent, dan Reporting Agent adalah tiga peran analisis berbasis AI di backend.
- Agent Linux tidak menjalankan model AI.
- AI tidak mengakses bucket secara langsung. Backend memilih, menyaring, dan mengirim konteks yang diperlukan.

## 7. Persyaratan Fungsional

### 7.1 Linux Agent
- Agent dapat dikonfigurasi dengan endpoint backend dan identitas host.
- Agent membaca sumber data yang diizinkan saja.
- Agent mengirim event secara aman melalui koneksi terautentikasi.
- Agent memiliki mekanisme retry yang tidak membuat antrean tumbuh tanpa batas.
- Agent mencatat status operasional tanpa menyimpan rahasia.
- Agent tidak mengubah konfigurasi host atau melakukan tindakan remediation.

### 7.2 Security Checker (SC)
Memeriksa kondisi keamanan dasar host secara read-only.

Pemeriksaan awal yang dapat dipertimbangkan:
- Konfigurasi SSH yang relevan.
- Layanan dan port yang sedang aktif.
- Permission terpilih pada file atau direktori penting.
- Indikator pembaruan paket yang tersedia, jika dapat diperoleh dengan aman.

Setiap hasil memuat host dan waktu pemeriksaan, ID pemeriksaan, status/tingkat temuan, indikator pendukung, dan batas pemeriksaan. SC tidak boleh mengklaim pemeriksaan berhasil jika data tidak tersedia atau izin tidak mencukupi.

### 7.3 Runtime Monitor (RM)
Memantau log terpilih secara incremental.

Sumber awal:
- Log autentikasi SSH.
- Log Nginx.

Persyaratan:
- Mendukung pembacaan incremental dan menangani rotasi log.
- Menghasilkan event ternormalisasi dengan timestamp, host, sumber, dan tipe event.
- Mencatat telemetry gap atau kegagalan membaca sumber.
- Tidak mengumpulkan sumber log di luar konfigurasi yang disetujui.
- Tidak mengirim isi log mentah tanpa kebutuhan yang jelas.

### 7.4 Parser dan Normalizer
- Mengubah format log yang didukung menjadi skema event internal.
- Menangani baris malformed tanpa menghentikan seluruh pipeline.
- Menyertakan informasi sumber dan waktu event.
- Memisahkan parsing dari keputusan deteksi.
- Memiliki test fixture dan unit test untuk format yang didukung.

### 7.5 Rules Engine
- Menjalankan aturan deterministik terhadap event yang telah dinormalisasi.
- Menghasilkan alert dengan rule ID, severity, waktu, host, dan event pendukung.
- Menyimpan versi aturan atau identitas rule yang digunakan.
- Tidak bergantung pada ketersediaan AI.
- Menyediakan pengujian positive case dan negative case.

### 7.6 Dashboard
Dashboard MVP menampilkan:
- Daftar host dan status agent.
- Waktu terakhir data diterima.
- Temuan SC.
- Alert RM.
- Timeline event/alert yang relevan.
- Status telemetry gap.
- Status Emergency Evidence Mode.
- Daftar dan status laporan.

### 7.7 Emergency Evidence Mode
Mode pengumpulan bukti tambahan yang diaktifkan operator untuk investigasi tertentu.

Persyaratan:
- Diaktifkan secara eksplisit oleh operator.
- Memiliki durasi terbatas dan otomatis berakhir.
- Mengumpulkan hanya jenis data yang telah dikonfigurasi dan diizinkan.
- Menampilkan status aktif, waktu mulai, dan waktu berakhir.
- Menyimpan evidence di object storage privat.
- Mencatat metadata evidence dan alasan pengumpulan.
- Menyaring rahasia dan data sensitif sebelum konteks dikirim ke AI.
- Tidak memberikan AI akses langsung ke bucket.
- Tidak menjanjikan pengambilan data secara retroaktif dari periode yang tidak pernah disimpan.

### 7.8 Evidence Manager dan Object Storage
- Menyimpan evidence pada storage privat, bukan public bucket.
- Menggunakan MinIO untuk development lokal; desain tetap kompatibel dengan storage S3.
- Mengatur metadata, referensi, retensi, dan akses evidence.
- Membatasi akses hanya untuk backend/identitas yang diperlukan.
- Menghindari penyimpanan kredensial atau rahasia yang tidak dibutuhkan.
- Mendukung penghapusan sesuai kebijakan retensi yang ditetapkan.

### 7.9 AI Orchestrator dan Tiga Peran AI
AI dipanggil oleh backend hanya ketika dibutuhkan. Input AI harus berupa data terstruktur dan konteks minimum yang telah disaring.

#### SC Analysis Agent
- Menjelaskan arti dan kemungkinan dampak temuan SC.
- Merujuk pada bukti yang tersedia.
- Menyampaikan ketidakpastian dan keterbatasan pemeriksaan.
- Memberikan rekomendasi investigasi yang aman.
- Tidak menjalankan scan atau mengarang temuan.

#### RM Analysis Agent
- Membantu triage alert dari Rules Engine.
- Menghubungkan event terkait jika bukti mendukung.
- Menjelaskan alasan alert dan konteks yang tersedia.
- Menyarankan langkah investigasi yang aman.
- Tidak menggantikan Rules Engine dan tidak membaca seluruh log secara terus-menerus.

#### Reporting Agent
- Menyusun laporan harian atau laporan insiden dari temuan SC, alert RM, hasil triage, timeline, dan referensi evidence.
- Menyertakan rentang waktu dan sumber data.
- Menandai data yang tidak tersedia atau telemetry gap.
- Tidak membuat temuan, angka, atau kesimpulan yang tidak didukung data.

### 7.10 Provider AI
- Gunakan satu provider aktif untuk MVP.
- Provider dipanggil dari backend; API key tidak boleh berada di agent atau frontend.
- Integrasi 9Router atau Gemini harus diverifikasi terhadap endpoint, model, format request, dan batas penggunaan aktual.
- Kegagalan provider harus menghasilkan status error yang jelas, bukan menghentikan monitoring atau Rules Engine.
- Jangan menerapkan routing 50/50 antar-provider pada MVP.

### 7.11 Reporting dan PDF
- Laporan dibuat dari data yang tersimpan, bukan dari ingatan atau asumsi AI.
- Laporan memuat periode, host, ringkasan, temuan/alert, timeline relevan, dan keterbatasan data.
- Laporan dapat diunduh sebagai PDF.
- Kegagalan pembuatan laporan tidak boleh menghapus data monitoring.

## 8. Persyaratan Data dan Keamanan

### Data yang perlu dikecualikan
Jangan mengumpulkan atau mengirim ke AI:
- Password dan password hash.
- Private SSH keys.
- Access token, API key, dan credential lain.
- Data sensitif lain yang tidak diperlukan untuk tujuan deteksi.

### Prinsip pengolahan data
- Terapkan allowlist sumber dan field.
- Minimalkan data yang dikirim.
- Redaksi dilakukan sebelum data diteruskan ke AI.
- Simpan evidence di storage privat dengan akses terbatas.
- Catat siapa yang mengaktifkan Emergency Evidence Mode dan kapan.
- Hindari menampilkan rahasia di dashboard, log aplikasi, atau laporan.

## 9. Persyaratan Non-Fungsional

### Resource usage
Target “ringan” perlu ditetapkan dan diuji. Ukur setidaknya CPU agent, RAM agent, disk I/O, network usage, dan latency dari event masuk hingga alert tersedia.

### Reliability
- Monitoring dan rules tetap berjalan saat AI tidak tersedia.
- Parser menangani event malformed.
- Agent dapat pulih dari koneksi backend yang terputus.
- Kegagalan satu sumber log tidak menghentikan sumber lain.

### Security
- Komunikasi agent-backend harus terautentikasi.
- Secret hanya disimpan di backend atau secret store yang sesuai.
- Object storage bersifat privat.
- Hak akses dibuat berdasarkan kebutuhan minimum.
- Tidak ada auto-remediation pada MVP.

### Maintainability
- Parser, rules, dan provider AI dipisahkan sebagai modul.
- Skema event memiliki versi.
- Konfigurasi dapat diuji dan didokumentasikan.
- Unit test dan integration test menjadi bagian dari pengembangan.

## 10. Rekomendasi Stack MVP

| Komponen | Rekomendasi awal |
|---|---|
| Agent Linux | Python |
| Backend API | FastAPI |
| Database development | SQLite |
| Jalur database produksi | PostgreSQL |
| Object storage development | MinIO |
| Dashboard | React + TypeScript |
| Deployment development | Docker Compose |
| AI | Satu provider aktif melalui adapter backend |
| Laporan | PDF dari data terstruktur |

Stack ini merupakan rekomendasi awal dan dapat disesuaikan berdasarkan keputusan tim.

## 11. Acceptance Criteria MVP

1. Agent Ubuntu dapat terhubung ke backend dan melaporkan status.
2. SC menjalankan pemeriksaan yang disepakati dan menyimpan hasil dengan bukti pendukung.
3. RM membaca log SSH dan Nginx yang dikonfigurasi serta menghasilkan event ternormalisasi.
4. Rules Engine menghasilkan alert untuk skenario uji yang ditentukan.
5. Dashboard menampilkan host, temuan, alert, timeline, dan telemetry gap.
6. Monitoring dan rules tetap berjalan ketika provider AI gagal.
7. AI hanya menerima konteks yang telah dipilih dan disaring oleh backend.
8. Emergency Evidence Mode memiliki batas waktu dan menyimpan evidence secara privat.
9. Reporting Agent membuat PDF dari data yang tersimpan tanpa mengarang temuan.
10. Unit test dan integration test untuk alur inti lulus.

## 12. Testing

- Unit test parser untuk format log yang didukung.
- Unit test Rules Engine untuk positive dan negative cases.
- Test rotasi log dan event malformed.
- Integration test agent → collector → normalizer → rules → database.
- Test provider AI timeout/error.
- Test redaction untuk data sensitif.
- Test Emergency Evidence Mode expiry dan akses storage.
- Test pembuatan PDF dari dataset yang diketahui.
- Pengukuran resource pada host uji dengan beban yang dicatat.

## 13. Risiko dan Mitigasi

| Risiko | Mitigasi |
|---|---|
| Data sensitif terkirim ke AI | Allowlist, minimisasi, redaksi, dan review payload |
| AI menghasilkan kesimpulan tidak didukung | Batasi input ke data terstruktur; wajibkan referensi bukti dan ketidakpastian |
| Agent membebani host | Pengumpulan incremental, batas antrean, dan pengukuran resource |
| Log tidak lengkap atau terputus | Tampilkan telemetry gap dan status sumber |
| Provider AI tidak tersedia | Monitoring dan Rules Engine tetap berjalan tanpa AI |
| Evidence tersimpan terbuka | Private storage, akses minimum, dan kebijakan retensi |
| Ruang lingkup melebar | Kunci MVP pada Ubuntu, SSH auth log, dan Nginx log |

## 14. Prioritas Implementasi

### P0 — Fondasi dan alur inti
- Skema event dan identitas host.
- Agent dasar.
- Collector/API.
- Parser SSH dan Nginx.
- Database.
- Rules Engine awal.
- Dashboard status host, findings, dan alerts.
- Test alur end-to-end.

### P1 — Investigasi dan AI
- SC checks awal.
- SC Analysis Agent.
- RM Analysis Agent.
- AI provider adapter dengan satu provider aktif.
- Evidence Manager dan storage privat.
- Emergency Evidence Mode dengan expiry.

### P2 — Reporting dan hardening
- Reporting Agent dan PDF.
- Retensi dan penghapusan evidence.
- Peningkatan observability dan telemetry gap.
- Pengukuran resource dan tuning.
- Dokumentasi konfigurasi dan deployment.

## 15. Keputusan yang Perlu Dikunci Tim

- Pembagian ownership repo dan modul.
- Skema event internal dan versi skema.
- Daftar pemeriksaan SC pertama.
- Daftar rule RM pertama beserta skenario test.
- Durasi maksimum Emergency Evidence Mode dan retensi evidence.
- Provider AI aktif dan model yang digunakan.
- Target resource usage yang akan diukur.
- Kriteria kelulusan acceptance test.

---

**Catatan:** Dokumen ini adalah PRD draft untuk membangun produk. Detail yang belum diputuskan tim ditandai sebagai keputusan yang perlu dikunci, bukan dianggap sudah final.
