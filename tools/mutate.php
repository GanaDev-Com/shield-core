<?php

declare(strict_types=1);

/**
 * Menjalankan mutation testing bawaan Pest (`pestphp/pest-plugin-mutate`,
 * bagian dari Pest 3) untuk logika keamanan core.
 *
 * Scope dibatasi ke namespace Decision/Scoring/Reputation (kode bernilai
 * tertinggi, sama seperti scope Infection lama) dan dijalankan paralel,
 * sehingga selesai dalam beberapa menit alih-alih melebihi timeout CI.
 *
 * Butuh driver coverage (xdebug/pcov) untuk `--covered-only`. Laporan bersifat
 * advisory (report-only): `--min=0` sehingga tidak pernah gagal karena skor
 * (naikkan `--min=80` setelah baseline MSI terukur).
 */
$bin = __DIR__.'/../vendor/bin/pest';

if (! is_file($bin)) {
    fwrite(STDERR, "Pest tidak terpasang. Jalankan: composer install\n");
    exit(1);
}

$command = 'php '.escapeshellarg($bin)
    .' --mutate'
    .' --class=Ganadev\Shield\Core\Decision,Ganadev\Shield\Core\Scoring,Ganadev\Shield\Core\Reputation'
    .' --covered-only --min=0 --ignore-min-score-on-zero-mutations'
    .' --parallel'
    .' --configuration phpunit.xml.dist --testsuite "Shield Core"';

passthru($command, $code);

exit($code);
