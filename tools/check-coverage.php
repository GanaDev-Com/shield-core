<?php

declare(strict_types=1);

/**
 * Memeriksa persentase baris ter-cover (Lines) pada laporan coverage Pest/PHPUnit
 * format --coverage-text, lalu keluar non-zero jika di bawah threshold.
 *
 * Usage: php tools/check-coverage.php build/coverage-core.txt 90
 */
$file = $argv[1] ?? '';
$threshold = (float) ($argv[2] ?? 0);

if ($file === '' || ! is_file($file)) {
    fwrite(STDERR, "File laporan coverage tidak ditemukan: {$file}\n");
    exit(2);
}

$text = (string) file_get_contents($file);

if (! preg_match('/^  Lines:\s+([0-9.]+)%/m', $text, $m)) {
    fwrite(STDERR, "Tidak bisa membaca baris 'Lines:' dari laporan coverage: {$file}\n");
    exit(2);
}

$pct = (float) $m[1];

printf("Lines coverage: %.2f%% (threshold %.2f%%)\n", $pct, $threshold);

exit($pct >= $threshold ? 0 : 1);
