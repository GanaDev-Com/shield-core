# Changelog

Semua perubahan penting `ganadev/shield-core` didokumentasikan di sini. Format mengikuti
[Keep a Changelog](https://keepachangelog.com/) dan proyek ini mematuhi
[Semantic Versioning](https://semver.org/).

## [1.1.0 - 2026-10-01]

### Changed

- **Default `bots.mode` berubah dari `challenge` menjadi `observe`.** Default sebelumnya
  bisa merusak SEO/AI-crawler: begitu reverse-DNS atau CIDR gagal — DNS bermasalah,
  resolver diblokir, atau domain crawler belum terdaftar — crawler resmi diklaim palsu
  lalu mendapat `403/419`, padahal `/robots.txt` dan `/sitemap.xml` harus selalu bisa
  diakses. `mode` global sudah `observe` sejak awal, jadi ini juga menyelaraskan
  `bots.mode` dengan falsafah dan dokumentasi package.

  Perilaku opt-in tetap tersedia: set `bots.mode` ke `challenge` untuk mengembalikan
  challenge pada crawler tak terverifikasi. Naikkan hanya setelah verifikasi crawler
  terbukti bekerja, karena kegagalan DNS akan menandai crawler sah sebagai palsu.

  Yang berubah: crawler tak terverifikasi sekarang dilayani dan hanya dicatat
  (`SIGNAL_UNVERIFIED_CRAWLER_CLAIM` tetap masuk skor), bukan di-challenge.

### Ditambahkan

- **Validasi `allowlist.paths`.** Nilai `''` dan `'/'` ditolak saat boot dengan
  `InvalidConfigException`. Keduanya membuat **seluruh request ter-allowlist** karena
  pencocokan memakai `str_starts_with()`, jadi satu karakter salah tulis mematikan
  seluruh proteksi secara senyap. Entri juga harus diawali `/` dan bebas query string.
  Host/IP/paths kini di-trim agar whitespace tidak mengubah apa yang ter-allowlist.
  Critical signature tetap tidak bisa di-bypass (guard `hasCriticalMatch`).

## [1.0.1 - 2026-10-01]

Perubahan pada rilis ini semuanya bersifat aditif: tidak ada verdict, threshold, atau
semantik matcher yang berubah. Tidak ada breaking change pada API publik.

### Ditambahkan

- **`request_id` pada security event.** `ShieldEngine::inspect()` kini meneruskan
  `$options['request_id']` ke event yang disimpan (sebelumnya selalu `null`), sehingga
  request dari aplikasi bisa dikorelasikan dengan baris `security_events`. Nilai kosong
  atau bukan string tetap disimpan sebagai `null`.
- **Event allowlist & fail-closed.** Jalur pintas `allowlist` dan `fail_closed` sekarang
  menulis security event. Keduanya adalah keputusan keamanan yang sebelumnya tidak
  meninggalkan jejak audit sama sekali. Toggle baru `logging.bypass_events`
  (default `true`) untuk mematikan pencatatan ini; `logging.events` tidak terpengaruh.
- **`ShieldConfig::$rulesPacksWordpress`.** Kunci config `rules.packs.wordpress` kini
  benar-benar dipetakan ke properti, sebelumnya diabaikan core (hanya dibaca adapter).

### Diperbaiki

- **Bypass masking parameter sensitif.** `UriMasker` kini men-decode key query dengan
  `rawurldecode()` sebelum mencocokkan. `?access%5Ftoken=...` sebelumnya lolos masking
  dan menulis token dalam plaintext ke database — persis encoding yang dipakai untuk
  melewati masking. Pencocokan tetap case-insensitive.
- **Race condition pada counter cache Laravel.** `LaravelCacheAdapter::increment()`
  memakai `add()` atomik alih-alih `has()` + `put()` + `increment()`, yang bisa
  kehilangan hitungan pada request bersamaan.

### Dibersihkan

- **`DecodedContainsMatcher` dideduplikasi.** Semantiknya identik dengan
  `ContainsMatcher` (keduanya sudah membaca `decodedVariants`), jadi sekarang mendelegasikan
  alih-alih menyalin logika. Tipe matcher `decoded_contains` tetap dipertahankan karena
  dipakai 15 rule terkirim dan merupakan bagian dari vocabulary rule.
- **`phpunit.coverage-core.xml.dist` dihapus.** Isinya identik dengan `phpunit.xml.dist`;
  CI sekarang memakai konfigurasi tunggal.

### Ditambahkan (tooling)

- `tools/replay.php` dijalankan di CI dengan `--pack-wordpress`. Corpus replay memuat
  fixture plugin WordPress, jadi pack opsional harus aktif agar target detection rate
  tercapai. Tanpa flag: 96.5% (167/173). Dengan flag: 100% (173/173).