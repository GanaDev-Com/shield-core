<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Normalization\Normalizer;

it('normalizer is robust against fuzzed input', function () {
    $fuzz = [
        str_repeat('%', 1000),
        str_repeat('/\\', 500),
        '/'.str_repeat('a', 8192),
        '?'.str_repeat('k=v&', 2000),
        '%00%00%00',
        '/..%2f'.str_repeat('%2e', 100),
        "\x00\x01\x02",
        str_repeat('🔥', 200),
        '/'.str_repeat('%2525', 100),
        '//////'.'/',
        '/caf\u00e9',
    ];

    foreach ($fuzz as $input) {
        $normalized = (new Normalizer)->normalize(shieldRequest($input), coreConfig());
        expect($normalized->normalizedUri)->toBeString();
        expect(count($normalized->decodedVariants))->toBeLessThanOrEqual(3);
    }
});

it('decodes bounded payloads within memory limits', function () {
    $payload = '/'.str_repeat('%252e', 2000);

    $before = memory_get_usage();
    $normalized = (new Normalizer)->normalize(shieldRequest($payload), coreConfig());
    $after = memory_get_usage();

    expect($normalized->decodedVariants)->toHaveCount(2);
    expect($after - $before)->toBeLessThan(2 * 1024 * 1024);
});

it('represents ipv4 and ipv6 without loss', function () {
    $ctx4 = shieldRequest('/home', 'GET', '192.0.2.5');
    $ctx6 = shieldRequest('/home', 'GET', '2001:db8::1');

    expect($ctx4->ip)->toBe('192.0.2.5');
    expect($ctx6->ip)->toBe('2001:db8::1');
});
