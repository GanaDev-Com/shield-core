# Ganadev Shield Core

**Inti (framework-agnostik) dari Ganadev Shield** — adaptive application firewall untuk PHP.

Package ini berisi semua logika keamanan: normalisasi request, mesin aturan (signature), deteksi perilaku,
skor risiko, pengambilan keputusan, kebijakan ban, dan kontrak (interface). **Nol dependensi** selain PHP `^8.2` —
tidak bergantung pada Laravel atau framework apa pun.

## Install

```bash
composer require ganadev/shield-core
```

Untuk integrasi Laravel, gunakan `ganadev/laravel-shield` (middleware, penyimpanan database, cache, halaman
challenge, perintah CLI).

## Fitur inti

- Normalisasi dengan decode terbatas (anti-ReDoS, bound `decode_depth`).
- Aturan data-driven (`DefaultRules`) + matcher `exact`/`prefix`/`contains`/`regex`/`query_contains`/
  `decoded_contains`/`body_contains`/`body_regex`.
- Deteksi perilaku: burst URI, enumerasi 404, rate-limit path sensitif, User-Agent mencurigakan, verifikasi crawler.
- Skor risiko + eskalasi offense, kebijakan ban dengan durasi naik, risk decay.
- Decision engine deterministik: `ALLOW | OBSERVE | CHALLENGE | BLOCK_REQUEST | TEMP_BAN`.
- Rule critical (`.env`, `.git`, AWS credentials, `php://input`, `/proc/self/environ`) selalu diblok.

## Development

```bash
composer install
composer test        # Pest
composer analyse     # PHPStan level 8
composer format-test # Pint
php tools/scanner-simulator/simulate.php   # replay corpus scanner
php tools/scanner-simulator/benchmark.php  # latensi allow-path (< 2 ms)
composer mutate      # mutation testing core (butuh xdebug/pcov)
```

## Lisensi

MIT. Dibuat oleh [Ganadev](https://ganadev.com).