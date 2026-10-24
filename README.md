<div align="center">

# SiteAudit

Ketik satu alamat situs. Beberapa detik kemudian kamu dapat rapor nilai A sampai F, daftar celah keamanannya, dan satu perbaikan konkret untuk tiap celah, lengkap dengan buktinya.

![PHP 8.1+](https://img.shields.io/badge/PHP-8.1%2B-777bb4?style=flat-square&logo=php&logoColor=white)
![Pemeriksaan pasif](https://img.shields.io/badge/scan-pasif-4d7c0f?style=flat-square)
![Tanpa dependency](https://img.shields.io/badge/dependency-0-333?style=flat-square)
![MIT](https://img.shields.io/badge/license-MIT-333?style=flat-square)

[Cara pakai](#cara-pakai) · [Yang diperiksa](#yang-diperiksa) · [Mode aktif](#mode-aktif) · [Cara kerjanya](#cara-kerjanya) · [Keamanan](#keamanan--batasan) · [English](#english)

<img src="docs/hero.png" alt="Halaman utama SiteAudit" width="860" />

</div>

## Kenapa ada

Kebanyakan situs bocor diam-diam. Pemiliknya baru sadar setelah `.env`-nya terindeks Google, atau setelah ada yang clone `.git`-nya. Padahal sebagian besar masalah itu kelihatan dari luar tanpa perlu menyerang apa pun: header keamanan yang kosong, sertifikat yang mau habis, cookie sesi tanpa flag, folder yang bisa di-listing.

SiteAudit menarik satu halaman situs, membaca respons dan beberapa path umum, lalu menilainya. Kamu tidak dapat daftar istilah yang bikin pusing, tapi kalimat jelas: apa yang salah, kenapa itu bahaya, dan baris konfigurasi apa yang harus kamu ubah.

<img src="docs/report.png" alt="Contoh laporan" width="860" />

## Cara pakai

Butuh PHP 8.1 atau lebih baru dengan ekstensi **openssl** (wajib, untuk situs https) dan sebaiknya **curl**. Tidak ada `composer install`, tidak ada build. Satu perintah.

```bash
git clone https://github.com/b3n3d1ck/web-security-auditor.git
cd web-security-auditor
php -S localhost:8000 router.php
```

Buka `http://localhost:8000`, ketik alamat situsmu, centang pernyataan izin, klik **Periksa**.

> **Windows:** kalau `php` tidak dikenali, panggil lewat path lengkap, mis. `C:\php\php.exe -S localhost:8000 router.php`. Kalau muncul error soal ekstensi, buka `php.ini` lalu hilangkan tanda `;` di depan `extension=openssl` dan `extension=curl`, dan pastikan `extension_dir = "ext"` aktif.

Tanpa tampilan web, langsung dari terminal:

```bash
php bin/scan.php situsku.com
```

Menjalankan tes (butuh PHP saja, tanpa framework tes apa pun):

```bash
php tests/run.php
```

## Yang diperiksa

Semua pemeriksaan di bawah ini **pasif**: hanya request HTTP biasa, sama seperti browser membuka situsmu. Tidak ada brute force, tidak ada payload serangan.

**Enkripsi**
- Situs melayani HTTPS atau masih HTTP polos
- Versi TLS lama (1.0 / 1.1), sertifikat kedaluwarsa atau hampir habis, sertifikat self-signed
- Mixed content: halaman https yang masih memuat gambar atau skrip lewat http

**Header keamanan**
- Header yang hilang: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **Analisis isi CSP**, bukan sekadar ada atau tidak: `unsafe-inline`, `unsafe-eval`, sumber wildcard, dan direktif penting yang hilang (`object-src`, `base-uri`)

**File & direktori**
- Path sensitif yang terbuka: `.env`, `.git/config`, `phpinfo.php`, `.htaccess`, `server-status`, berbagai file backup. Buktinya ikut ditampilkan, dan nilai rahasia (password, key) otomatis disensor
- **Penemuan direktori tanpa wordlist**: path dibaca dari `robots.txt`, `sitemap.xml`, dan link di halaman, lalu dicek apakah ada directory listing yang terbuka
- Path "rahasia" yang justru bocor karena ditulis di `robots.txt`

**Kode frontend**
- Rahasia yang ikut ter-bundle di JavaScript: pola AWS access key, Google API key, Stripe, Slack token, dan `api_key`/`secret` hardcoded. Nilainya disensor sebelum ditampilkan
- Skrip pihak ketiga tanpa Subresource Integrity

**Server & metode**
- Versi yang bocor lewat header `Server` / `X-Powered-By`, tag `generator`, deteksi WordPress
- Metode HTTP berbahaya lewat satu request OPTIONS: `TRACE` (serangan XST) dan metode tulis yang terbuka

**Jaringan**
- Keamanan email lewat DNS: ada atau tidaknya SPF dan DMARC, dan apakah keduanya tegas, supaya orang tidak gampang memalsukan email atas nama domainmu
- Konfigurasi CORS yang berbahaya: Origin yang dipantulkan mentah, atau wildcard dengan kredensial
- `security.txt` (RFC 9116): kontak untuk peneliti yang menemukan celah

Nilai hurufnya dihitung dari bobot tiap temuan: satu celah kritis menjatuhkan nilai jauh lebih dalam daripada beberapa catatan rendah.

## Mode aktif

Secara default SiteAudit hanya pasif. Ada mode aktif opsional yang benar-benar mengirim payload uji untuk **membuktikan** celah, seperti yang dilakukan pentester:

| Uji | Cara kerja | Bukti yang ditunjukkan |
|---|---|---|
| Reflected XSS | Menyisipkan penanda unik berisi `< > " '` ke parameter, lalu cek apakah dipantulkan tanpa di-escape | Penanda muncul mentah di HTML |
| SQL injection | Menambah satu petik ke parameter, lalu cari pesan error database | Potongan error SQL dari server |
| Open redirect | Mengisi parameter redirect dengan URL canary, lalu cek header `Location` | `Location:` yang mengarah ke domain canary |

Payload-nya **mendeteksi, bukan mengeksploitasi**: penanda dan pemicu error, bukan kode yang merusak atau mencuri data.

Mode ini terkunci ganda supaya tidak disalahgunakan. Pertama, operator harus menyalakannya di server lewat `AUDITOR_ACTIVE=1`. Kedua, pengguna harus mencentang pernyataan izin terpisah untuk tiap scan. Kalau salah satu tidak terpenuhi, mode aktif ditolak.

```bash
# nyalakan mode aktif — hanya untuk target yang kamu miliki atau kamu diizinkan
AUDITOR_ACTIVE=1 php -S localhost:8000 router.php
```

Di Windows (cmd): `set AUDITOR_ACTIVE=1` lalu jalankan server di baris berikutnya.

## Cara kerjanya

Beberapa keputusan desain yang bikin hasilnya lebih bisa dipercaya:

- **Baseline anti soft-404.** Sebelum menebak file sensitif terbuka, SiteAudit meminta satu path acak. Kalau situs membalas `200` untuk apa pun, pemeriksaan file menuntut isi file cocok dengan tanda tangannya dulu, supaya tidak asal menandai halaman 404 yang menyamar jadi 200.
- **Penilaian berbobot.** Tiap severity punya bobot. Nilai akhir dipotong dari 100, jadi F benar-benar berarti banyak masalah serius, bukan sekadar beberapa header rapi yang hilang.
- **Bukti yang disensor.** Saat isi file atau JS ditampilkan sebagai bukti, nilai yang terlihat seperti password atau key diganti dengan `***` sebelum sampai ke layar.

## Keamanan & batasan

Memindai situs orang lain tanpa izin bisa melanggar hukum. SiteAudit dibuat untuk situs milikmu sendiri atau yang kamu diberi izin memeriksanya, dan beberapa hal dibangun untuk menjaga itu:

- **Butuh pernyataan izin** sebelum scan jalan.
- **Proteksi SSRF.** Target yang mengarah ke `localhost`, jaringan privat (`10.x`, `192.168.x`, dsb.), alamat link-local, atau endpoint metadata cloud (`169.254.169.254`) ditolak. IP hasil resolusi di-pin supaya tidak bisa di-rebind di tengah jalan. Situs publik yang kebetulan juga punya alamat IPv6 internal tetap bisa dipindai lewat alamat publiknya.
- **Memperkenalkan diri** lewat User-Agent, tidak menyamar.
- **Rate limit** per IP di endpoint web.

Batasannya jujur: ini pendeteksi berbasis aturan, bukan AI yang memahami aplikasimu. Konfigurasi yang tidak biasa bisa lolos, dan pola yang mirip bisa salah tanda. Anggap hasilnya sebagai titik awal pemeriksaan, bukan sertifikat aman.

> `AUDITOR_ALLOW_PRIVATE=1` hanya untuk menguji target lokal saat pengembangan. **Jangan** menyalakannya di server publik: itu membuka celah SSRF ke jaringan internalmu.

## Struktur

```
public/           tampilan web (HTML, CSS, JS) — tanpa build
api/scan.php      endpoint JSON
src/Http.php      klien HTTP dengan guard SSRF (curl, fallback streams)
src/Tls.php       inspeksi sertifikat & versi TLS
src/Checks.php    pemeriksaan pasif inti
src/Advanced.php  CSP, rahasia di JS, metode HTTP, DNS email, SRI
src/Active.php    uji aktif (XSS / SQLi / open redirect), opsional
src/Grade.php     penilaian A–F
bin/scan.php      penjalan via terminal
tests/run.php     tes tanpa dependency
```

## Kontribusi

Yang paling berguna: **pola pemeriksaan pasif baru**, misalnya path sensitif lain atau deteksi versi rentan. Tambahkan di `src/Checks.php` atau `src/Advanced.php`, tambahkan tesnya di `tests/run.php`, pastikan `php tests/run.php` lolos, lalu kirim pull request. Jangan menambah apa pun yang menyerang target di luar mode aktif yang sudah terkunci. Detail di [CONTRIBUTING.md](CONTRIBUTING.md).

## English

**SiteAudit** is a web security auditor with a PHP backend and zero dependencies. Enter a URL and get an A–F report of its issues, each with a concrete fix and evidence: missing or weak security headers (including real CSP analysis), TLS and certificate problems, exposed files like `.env` and `.git`, directories discovered from the site's own `robots.txt`/`sitemap`/links (no wordlist), secrets leaked in JavaScript, risky HTTP methods, SPF/DMARC gaps, and CORS misconfiguration. An optional active mode — double-gated behind an env flag and a per-scan opt-in — adds non-destructive detection probes for reflected XSS, SQL injection and open redirect. Every check is passive by default, the scanner identifies itself, and it refuses private, loopback and cloud-metadata targets to prevent SSRF. Built for sites you own or are authorized to test. Run it with `php -S localhost:8000 router.php`.

## Lisensi

[MIT](LICENSE) © 2026 Mas Bram. Kalau berguna, kasih bintang di GitHub.
