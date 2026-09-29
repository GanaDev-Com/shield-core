<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Exceptions\InvalidConfigException;

it('applies safe defaults', function () {
    $config = coreConfig();

    expect($config->enabled)->toBeTrue();
    expect($config->mode)->toBe('observe');
    expect($config->decodeDepth)->toBe(2);
    expect($config->failMode)->toBe('open');
    expect($config->thresholdChallenge)->toBe(10);
    expect($config->thresholdBan)->toBe(20);
    expect($config->thresholdStrongBan)->toBe(30);
    expect($config->banDurations)->toBe([15, 60, 360, 1440]);
});

it('merges nested overrides', function () {
    $config = coreConfig([
        'thresholds' => ['challenge' => 15],
        'ban' => ['durations' => [30, 120, 360, 1440]],
        'logging' => ['events' => false],
    ]);

    expect($config->thresholdChallenge)->toBe(15);
    expect($config->thresholdBan)->toBe(20);
    expect($config->banDurations)->toBe([30, 120, 360, 1440]);
    expect($config->logEvents)->toBeFalse();
});

it('rejects invalid modes and fail modes', function () {
    expect(fn () => coreConfig(['mode' => 'nope']))->toThrow(InvalidConfigException::class);
    expect(fn () => coreConfig(['fail_mode' => 'nope']))->toThrow(InvalidConfigException::class);
});

it('rejects unsafe decode depths', function () {
    expect(fn () => coreConfig(['decode_depth' => 4]))->toThrow(InvalidConfigException::class);
    expect(fn () => coreConfig(['decode_depth' => -1]))->toThrow(InvalidConfigException::class);
});

it('rejects non-increasing thresholds', function () {
    expect(fn () => coreConfig(['thresholds' => ['challenge' => 30, 'ban' => 20, 'strong_ban' => 35]]))
        ->toThrow(InvalidConfigException::class);
});

it('rejects invalid response codes', function () {
    expect(fn () => coreConfig(['response_code' => 42]))->toThrow(InvalidConfigException::class);
});

it('defaults to challenge bot mode with verification enabled', function () {
    $config = coreConfig();

    expect($config->botMode)->toBe('challenge');
    expect($config->crawlerVerificationEnabled)->toBeTrue();
    expect($config->crawlerVerificationTtlHours)->toBe(24);
    expect($config->crawlerHostnames['googlebot'])->toContain('.googlebot.com');
    expect($config->unverifiedClaimSignal)->toBe(4);
});

it('defaults the injection pack and body inspection on', function () {
    $config = coreConfig();

    expect($config->rulesPacksInjection)->toBeTrue();
    expect($config->bodyInspectionEnabled)->toBeTrue();
    expect($config->bodyInspectionMaxBytes)->toBe(65536);
});

it('defaults the scanner tool user agent list and signal', function () {
    $config = coreConfig();

    expect($config->scannerUserAgents)->toContain('sqlmap');
    expect($config->scannerUaSignal)->toBe(4);
});

it('merges crawler verification overrides', function () {
    $config = coreConfig([
        'bots' => [
            'verification' => [
                'ttl_hours' => 12,
                'hostnames' => ['googlebot' => ['.custom-google.com']],
                'ip_ranges' => ['googlebot' => ['66.249.64.0/19']],
            ],
        ],
    ]);

    expect($config->crawlerVerificationTtlHours)->toBe(12);
    expect($config->crawlerHostnames['googlebot'])->toBe(['.custom-google.com']);
    expect($config->crawlerIpRanges['googlebot'])->toBe(['66.249.64.0/19']);
});

it('rejects invalid verification and inspection settings', function () {
    expect(fn () => coreConfig(['bots' => ['verification' => ['ttl_hours' => 0]]]))
        ->toThrow(InvalidConfigException::class);
    expect(fn () => coreConfig(['bots' => ['unverified_claim_signal' => -1]]))
        ->toThrow(InvalidConfigException::class);
    expect(fn () => coreConfig(['behavior' => ['scanner_ua_signal' => -1]]))
        ->toThrow(InvalidConfigException::class);
    expect(fn () => coreConfig(['inspection' => ['body' => ['max_bytes' => 512]]]))
        ->toThrow(InvalidConfigException::class);
});
