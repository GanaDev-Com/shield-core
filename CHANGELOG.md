# Changelog

Semua perubahan penting `ganadev/shield-core` didokumentasikan di sini. Format mengikuti
[Keep a Changelog](https://keepachangelog.com/) dan proyek ini mematuhi
[Semantic Versioning](https://semver.org/).

## [1.2.0 - 2026-10-01]

Nomor `1.1.0` dilewati: rilis itu disiapkan tapi tidak pernah diberi tag Git, jadi tidak pernah terbit dan tidak
ada versi yang perlu di-deprecate.

Rilis ini menutup sebelas temuan audit internal. Semuanya bersifat aditif atau
pengetatan default, tidak ada perubahan pada threshold global maupun semantik
signature.

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
- **`logging.events` (boolean) diganti `logging.level` (string).** Recorder
  sebelumnya menulis **setiap request** ke `security_events`, sehingga tabel tumbuh
  tanpa batas dan baris yang justru dibutuhkan untuk menyetel ambang batas ikut
  tenggelam. `ShieldConfig::$logEvents` (bool) menjadi `$loggingLevel` (string) dengan
  konstanta `LOG_ALL`, `LOG_SUSPICIOUS`, dan `LOG_BLOCKED`.

  | Level | Yang disimpan |
  | --- | --- |
  | `suspicious` (default) | Semua keputusan selain `ALLOW`. |
  | `blocked` | Hanya blokir dan ban sementara. |
  | `all` | Setiap request, termasuk yang diizinkan. Untuk debugging singkat. |

  Nilai di luar tiga itu ditolak saat boot dengan `InvalidConfigException`.
  **Catatan upgrade:** file config yang sudah di-publish tidak ikut berubah, sehingga
  `'events' => true` diabaikan dan `level` jatuh ke default `suspicious`. Tambahkan
  `'level' => 'all'` eksplisit bila Anda memang mengandalkan pencatatan tiap request.
- **Default `branding.show_rule_id` `true` menjadi `false`.** Config bawaan core dan
  default adapter/page renderer ikut menyesuaikan, sehingga halaman blokir tidak lagi
  membuka detail signature ke penyerang. Header `X-Shield-Blocked` tetap membawa rule id
  karena itu sinyal operator.
- **`bots.mode=observe` tidak lagi bisa di-eskalasi oleh sinyal perilaku.** Selama ini
  `observe` hanya mencegah challenge yang dipaksakan, bukan challenge berbasis skor.
  Crawl deras (`unique_uri_burst` +12) memakai UA bot gagal terverifikasi menghasilkan
  skor 16, dan selama `mode` global `challenge`/`enforce` crawler itu tetap
  di-challenge — hilang dari indeks tanpa penyerang yang terlihat.

  Sekarang klaim crawler yang gagal diverifikasi tidak dapat menaikkan verdict ke
  challenge atau ban atas infrastruktur perilaku saja. Yang tetap ditegakkan: signature
  yang cocok (termasuk critical) dan ban aktif yang sudah tercatat.

### Ditambahkan

- **Validasi `allowlist.paths`.** Nilai `''` dan `'/'` ditolak saat boot dengan
  `InvalidConfigException`. Keduanya membuat **seluruh request ter-allowlist** karena
  pencocokan memakai `str_starts_with()`, jadi satu karakter salah tulis mematikan
  seluruh proteksi secara senyap. Entri juga harus diawali `/` dan bebas query string.
  Host/IP/paths kini di-trim agar whitespace tidak mengubah apa yang ter-allowlist.
  Critical signature tetap tidak bisa di-bypass (guard `hasCriticalMatch`).
- **`rules.skip_paths`.** Daftar prefix path yang menonaktifkan pemindaian body dan
  penilaian perilaku, dipakai untuk mengurangi false positive pada rich text editor,
  webhook, dan traffic M2M/NAT yang berbagi satu IP. Signature pada URI tetap aktif,
  dan critical signature tidak pernah di-bypass. Path divalidasi dengan aturan yang
  sama seperti `allowlist.paths` (leading `/`, tanpa query string).
- **Dukungan klien API/M2M pada config.** `api.paths` dan `api.detect_accept` dibawa
  ke core sebagai metadata keputusan supaya adapter dapat memilih bentuk respons tanpa
  menebak-nebak. Default core `api.paths` adalah `[]` (tidak ada path yang dianggap
  API) dan `api.detect_accept` `true` menghormati negosiasi `Accept`, sehingga aplikasi
  yang hanya berisi browser tidak ikut terpengaruh.
- **`logging.bypass_events` kini dipetakan di core.** Sebelumnya hanya ada sebagai
  default internal dan tidak pernah diekspos lewat `fromArray()`.

### Diperbaiki

- **Daftar prefix path di-trim.** `skip_paths` dan `api.paths` kini melewati normalisasi
  yang sama seperti `allowlist.paths`, jadi whitespace di sekitar entri tidak lagi
  mengubah path mana yang cocok. Entri tanpa leading `/` tetap ditolak saat boot.
- **Perbandingan logging level** kini berbasis konstanta `ShieldConfig::LOG_*`, bukan
  string literal yang tersebar di beberapa tempat.

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