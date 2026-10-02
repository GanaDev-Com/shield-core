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
        'logging' => ['level' => 'blocked'],
    ]);

    expect($config->thresholdChallenge)->toBe(15);
    expect($config->thresholdBan)->toBe(20);
    expect($config->banDurations)->toBe([30, 120, 360, 1440]);
    expect($config->loggingLevel)->toBe('blocked');
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

it('defaults to observe bot mode with verification enabled', function () {
    $config = coreConfig();

    expect($config->botMode)->toBe('observe');
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

it('exposes the wordpress rules pack flag instead of dropping it', function () {
    expect(coreConfig()->rulesPacksWordpress)->toBeFalse();
    expect(coreConfig(['rules' => ['packs' => ['wordpress' => true]]])->rulesPacksWordpress)->toBeTrue();
});

it('keeps the wordpress pack off while the injection pack stays independent', function () {
    $config = coreConfig(['rules' => ['packs' => ['injection' => false]]]);

    expect($config->rulesPacksInjection)->toBeFalse();
    expect($config->rulesPacksWordpress)->toBeFalse();
});

it('defaults to suspicious logging and allows narrowing it', function () {
    expect(coreConfig()->loggingLevel)->toBe('suspicious');
    expect(coreConfig()->logBypassEvents)->toBeTrue();

    expect(coreConfig(['logging' => ['level' => 'all']])->loggingLevel)->toBe('all');
    expect(coreConfig(['logging' => ['level' => 'blocked']])->loggingLevel)->toBe('blocked');
});

it('keeps bypass event logging independent from the logging level', function () {
    $disabled = coreConfig(['logging' => ['bypass_events' => false, 'level' => 'blocked']]);

    expect($disabled->logBypassEvents)->toBeFalse();
    expect($disabled->loggingLevel)->toBe('blocked');
});

it('rejects an unknown logging level', function () {
    expect(fn () => coreConfig(['logging' => ['level' => 'verbose']]))
        ->toThrow(InvalidConfigException::class, 'Invalid logging.level: verbose');
});

it('hides the rule id on the blocked page by default', function () {
    expect(coreConfig()->branding['show_rule_id'])->toBeFalse();
    expect(coreConfig(['branding' => ['show_rule_id' => true]])->branding['show_rule_id'])->toBeTrue();
});

it('defaults the api and skip path lists to empty with accept detection on', function () {
    $config = coreConfig();

    expect($config->apiPaths)->toBe([]);
    expect($config->apiDetectAccept)->toBeTrue();
    expect($config->skipPaths)->toBe([]);
});

it('trims and normalizes the path prefix lists', function () {
    $config = coreConfig([
        'api' => ['paths' => ['  /oauth/token  ']],
        'rules' => ['skip_paths' => [' /api/webhooks ', '/admin/']],
    ]);

    expect($config->apiPaths)->toBe(['/oauth/token']);
    expect($config->skipPaths)->toBe(['/api/webhooks', '/admin/']);
});

it('rejects a path prefix list that would match every request', function (string $key, array $config) {
    expect(fn () => coreConfig($config))->toThrow(InvalidConfigException::class);
})->with([
    ['rules.skip_paths', ['rules' => ['skip_paths' => ['/']]]],
    ['api.paths', ['api' => ['paths' => ['/']]]],
]);

it('rejects path prefixes without a leading slash or with a query string', function (string $key, array $config) {
    expect(fn () => coreConfig($config))->toThrow(InvalidConfigException::class);
})->with([
    ['rules.skip_paths', ['rules' => ['skip_paths' => ['oauth/token']]]],
    ['rules.skip_paths query', ['rules' => ['skip_paths' => ['/oauth?x=1']]]],
    ['api.paths', ['api' => ['paths' => ['api']]]],
    ['api.paths query', ['api' => ['paths' => ['/api?x=1']]]],
]);

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

it('rejects an allowlist path that would allowlist every request', function (string $path) {
    expect(fn () => coreConfig(['allowlist' => ['paths' => [$path]]]))
        ->toThrow(InvalidConfigException::class, 'would allowlist every request');
})->with(['', '/', '   ']);

it('rejects an allowlist path without a leading slash', function () {
    expect(fn () => coreConfig(['allowlist' => ['paths' => ['admin']]]))
        ->toThrow(InvalidConfigException::class, 'must start with "/"');
});

it('rejects an allowlist path carrying a query string', function () {
    expect(fn () => coreConfig(['allowlist' => ['paths' => ['/admin?debug=1']]]))
        ->toThrow(InvalidConfigException::class, 'must not contain a query string');
});

it('accepts specific allowlist paths and trims surrounding whitespace', function () {
    $config = coreConfig(['allowlist' => [
        'paths' => [' /admin ', '/api/v2'],
        'hosts' => [' example.test '],
        'ips' => [' 203.0.113.9 '],
    ]]);

    expect($config->allowlist['paths'])->toBe(['/admin', '/api/v2']);
    expect($config->allowlist['hosts'])->toBe(['example.test']);
    expect($config->allowlist['ips'])->toBe(['203.0.113.9']);
});
