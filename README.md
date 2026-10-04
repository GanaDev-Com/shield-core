<p align="center">
  <img src="docs/logo.svg" width="96" height="96" alt="Logo Ganadev Shield">
</p>

<h1 align="center">Shield Core</h1>

<p align="center">
  Inti firewall aplikasi untuk PHP — seluruh logika keamanan, tanpa bergantung pada framework apa pun.
</p>

<p align="center">
  <a href="https://packagist.org/packages/ganadev/shield-core"><img src="https://img.shields.io/packagist/v/ganadev/shield-core?style=flat-square&label=packagist&color=22d3ee" alt="Versi di Packagist"></a>
  <a href="https://github.com/GanaDev-Com/shield-core/actions/workflows/ci.yml"><img src="https://github.com/GanaDev-Com/shield-core/actions/workflows/ci.yml/badge.svg" alt="Status CI"></a>
  <img src="https://img.shields.io/badge/PHP-%5E8.2-22d3ee?style=flat-square&logo=php&logoColor=white" alt="Butuh PHP 8.2 atau lebih baru">
  <img src="https://img.shields.io/badge/dependensi-nol-22d3ee?style=flat-square" alt="Tanpa dependensi tambahan">
  <img src="https://img.shields.io/badge/Lisensi-MIT-22d3ee?style=flat-square" alt="Lisensi MIT">
  <a href="https://shield.ganadev.com"><img src="https://img.shields.io/badge/dokumentasi-shield.ganadev.com-22d3ee?style=flat-square" alt="Dokumentasi resmi"></a>
</p>

---

## Apa ini?

Ganadev Shield terdiri dari dua package terpisah, dan ini adalah bagian intinya.

**Shield Core** adalah otak yang berpikir. Di sini ada semua logika keamanan: membaca dan merapikan permintaan, mengenali tanda-tanda serangan, menghitung skor bahaya, lalu memutuskan apa yang harus terjadi — diteruskan, diminta captcha, diblokir, atau diberi ban sementara.

Package ini **tidak tahu apa itu Laravel**, dan tidak memanggil satu pun kelas Laravel. Ia juga tidak butuh database, framework, atau pustaka pihak ketiga — hanya PHP `^8.2`.

> **Kalau Anda memakai Laravel, jangan pasang ini secara manual.**
> Gunakan [`ganadev/laravel-shield`](https://github.com/GanaDev-Com/laravel-shield), yang sudah menarik Shield Core untuk Anda.
>
> Shield Core yang tepat dibutuhkan kalau Anda membangun adapter sendiri untuk framework lain — misalnya CodeIgniter, Symfony, atau PSR-15 — atau sedang menguji logika firewall tanpa framework sama sekali.

### Alurnya

Setiap permintaan yang masuk melewati lima tahap, berurutan:

```
Permintaan  ->  Rapi  ->  Cocokkan aturan  ->  Perilaku  ->  Skor  ->  Keputusan
```

1. **Rapi** — URL dan isi request dibersihkan lalu di-decode sampai kedalaman tertentu, supaya payload yang disamarkan tidak lolos.
2. **Cocokkan aturan** — cari pola yang cocok, misalnya `.env` atau `union select`.
3. **Perilaku** — lihat pola antar request: terlalu banyak URL berbeda, terlalu banyak 404, atau terlalu sering menyentuh `/login`.
4. **Skor** — semua temuan dijumlahkan jadi satu angka, ditambah riwayat pelanggaran IP tersebut.
5. **Keputusan** — angka itu dipetakan ke satu dari lima hasil: `ALLOW`, `OBSERVE`, `CHALLENGE`, `BLOCK_REQUEST`, atau `TEMP_BAN`.

Beberapa aturan ditandai **critical**, misalnya yang menyentuh file kredensial. Aturan seperti ini selalu memblokir, apa pun skor akhirnya — dan tidak bisa dilewati oleh allowlist yang Anda buat.

### Yang dilindungi

- Percobaan membaca file rahasia: `.env`, `.git/config`, `.git-credentials`, `wp-config.php`, dan kredensial AWS.
- Path traversal, termasuk varian yang di-encode berkali-kali sampai tidak terbaca sebagai path.
- Percobaan remote code execution: `php://input`, `auto_prepend_file`, file backup, dan kode PHP yang disembunyikan di folder statis.
- SQL injection, XSS, LFI, dan command injection, baik di URL maupun isi request.
- Penelusuran file: enumerasi 404, ledakan URL, dan rate limit pada path sensitif seperti `/login`.
- Bot palsu yang mengaku sebagai Googlebot atau Bingbot.

### Tiga paket aturan

| Paket | Isi | Default |
|---|---|---|
| `definitions()` | Aturan dasar: file sensitif, traversal, RCE, kredensial, backup file, honeypot | Aktif |
| `injectionDefinitions()` | SQLi, XSS, LFI, dan command injection di URL dan body | Aktif |
| `wordpressDefinitions()` | Aturan khusus WordPress seperti `xmlrpc.php` dan probe plugin | **Nonaktif** |

Paket WordPress sengaja nonaktif karena hanya relevan untuk situs WordPress. Nyalakan hanya kalau aplikasinya memang menjalankan WordPress — kalau tidak, ini bisa menambah false positive pada path yang kebetulan mirip.

---

## Instalasi

```bash
composer require ganadev/shield-core
```

Tidak ada langkah lain. Tidak perlu publish apa pun, tidak ada migration, tidak ada konfigurasi yang wajib diisi.

Untuk integrasi Laravel, pakai [`ganadev/laravel-shield`](https://github.com/GanaDev-Com/laravel-shield) — middleware, penyimpanan database, halaman captcha, dan perintah CLI sudah tersedia di sana.

---

## Pakai langsung

Shield Core menunggu beberapa kontrak dari lingkungan yang memanggilnya. Semuanya berupa interface, jadi Anda bebas mengimplementasikan sendiri:

| Kontrak | Untuk apa | Wajib? |
|---|---|---|
| `EventRepositoryInterface` | Mencatat setiap kejadian keamanan | Wajib |
| `ClockInterface` | Waktu sekarang — berguna agar tes bisa memakai waktu palsu | Wajib |
| `BanRepositoryInterface` | Menyimpan dan membaca daftar IP yang sedang diblokir | Opsional |
| `CrawlerVerifierInterface` | Verifikasi bot lewat DNS | Opsional |
| `TrustedCookieInterface` | Cookie pengenal setelah captcha berhasil | Opsional |

Tiga kontrak terakhir boleh dikosongkan (`null`) kalau aplikasinya belum punya fitur ban, verifikasi bot, atau captcha alike. Core akan tetap berjalan, hanya fitur itu yang dilewati.

Ada juga `CacheAdapterInterface` dan `ChallengeDriverInterface` — kontrak untuk lapisan adapter, bukan untuk engine. Adapter Laravel sudah mengimplementasikan keduanya.

Contoh paling sederhana:

```php
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Decision\DecisionEngine;
use Ganadev\Shield\Core\Detection\BehaviorDetector;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\RiskDecay;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Core\Scoring\RiskScorer;

$engine = new ShieldEngine(
    config: ShieldConfig::fromArray(['mode' => 'enforce']),
    normalizer: new Normalizer,
    signatures: new ThreatSignatureEngine(
        RuleRepository::fromArray(DefaultRules::definitions()),
    ),
    behavior: new BehaviorDetector,
    scorer: new RiskScorer,
    decisionEngine: new DecisionEngine,
    banPolicy: new BanPolicy,
    riskDecay: new RiskDecay,
    events: $repositoryAnda,
    clock: $jamAnda,
    bans: $banRepositoryAnda,
);
```

Hasilnya adalah objek `EngineResult` yang berisi keputusan, skor, aturan yang cocok, dan ban aktif.

---

## Perkakas Pengembang

Repo ini punya beberapa alat untuk memastikan firewall-nya benar-benar bekerja, bukan sekadar terlihat benar:

```bash
composer test        # Pest
composer analyse     # PHPStan level 8
composer format-test # Pint

php tools/scanner-simulator/simulate.php   # pemutaran ulang corpus scanner
php tools/scanner-simulator/benchmark.php  # latensi allow-path (harus di bawah 2 ms)
php tools/replay.php                       # deteksi dari log kejadian nyata
composer mutate                           # mutation testing (butuh xdebug atau pcov)
```

Folder `fixtures/` berisi lima corpus JSON yang berasal dari log serangan dunia nyata: `waf-corpus`, `bot-corpus`, `scanner-corpus`, `seo-corpus`, dan `normal-traffic`. Semua dipakai sebagai regression test, jadi perubahan aturan yang membuat deteksi turun akan langsung terlihat di CI.

---

## Dokumentasi

Dokumentasi lengkap ada di **[shield.ganadev.com](https://shield.ganadev.com)**:

| Halaman | Isi |
|---|---|
| [Package](https://shield.ganadev.com/packages/) | Perbedaan Shield Core dan Laravel Shield |
| [Instalasi](https://shield.ganadev.com/installation/) | Setup langkah demi langkah |
| [Arsitektur](https://shield.ganadev.com/architecture/) | Alur pipeline dan pembagian tanggung jawab |
| [Konfigurasi](https://shield.ganadev.com/configuration/) | Semua kunci config beserta artinya |
| [Aturan](https://shield.ganadev.com/rules/) | Aturan bawaan dan paket injection |
| [Perilaku & Bot](https://shield.ganadev.com/bots/) | Verifikasi crawler dan dampaknya ke SEO |
| [Ban & Reputasi](https://shield.ganadev.com/bans/) | Durasi ban, eskalasi, dan riwayat |
| [Model Keamanan](https://shield.ganadev.com/security/) | Batas dan اعتبار desain |
| [Upgrade ke v1.2.2](https://shield.ganadev.com/upgrade/) | Panduan naik versi dari 1.0.x |

---

## Open Source

Shield Core adalah proyek **open source** berlisensi MIT. Kode dan dokumentasinya bebas dibaca, diubah, dan dipakai ulang.

Kami terbuka pada masukan dan revisi apa pun — laporan bug, usulan fitur, perbaikan dokumentasi, sampai pull request. Semua itu membantu Shield menjadi lebih baik untuk semua orang, dan tidak ada yang perlu izin lebih dulu.

- Laporkan bug lewat [Issues](https://github.com/GanaDev-Com/shield-core/issues)
- Usulkan fitur lewat [Discussions](https://github.com/GanaDev-Com/shield-core/discussions)
- Temukan celah keamanan lewat [Security Advisory](https://github.com/GanaDev-Com/shield-core/security/advisories/new), jangan lewat Issues publik
- Koreksi dokumentasi lewat pull request langsung — sekecil apa pun tetap berharga

Yang membuat package ini dapat dipercaya adalah pengujiannya, jadi kontribusi pada bagian itu sangat dihargai: menambah kasus uji, menambah entri corpus, atau menemukan kasus yang belum ter-cover adalah sumbangan yang berharga.

Sebelum contribute, jalankan dulu:

```bash
composer test        # Pest
composer analyse     # PHPStan level 8
composer format-test # Pint
```

Ketiganya harus hijau sebelum pull request dikirim.

---

## Lisensi

MIT — © 2026 [Ganadev](https://ganadev.com) / PT Ganadev Multi Solusi
