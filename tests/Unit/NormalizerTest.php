<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Normalization\Normalizer;

/**
 * @param  array<string, mixed>  $config
 */
function normalize(string $uri, array $config = []): NormalizedRequest
{
    return (new Normalizer)->normalize(
        shieldRequest($uri),
        coreConfig($config),
    );
}

it('keeps raw path untouched and lowercases the matching copy', function () {
    $normalized = normalize('/Home/Page/About');

    expect($normalized->normalizedPath)->toBe('/home/page/about');
});

it('collapses repeated slashes only on the normalized copy', function () {
    $normalized = normalize('//etc//passwd');

    expect($normalized->normalizedPath)->toBe('/etc/passwd');
});

it('normalizes backslashes to slashes for matching', function () {
    $normalized = normalize('/..\\..\\etc\\passwd');

    expect($normalized->normalizedPath)->toBe('/../../etc/passwd');
});

it('decodes url encoded input up to the configured depth', function () {
    $normalized = normalize('/%252e%252e/%252e%252e/etc/passwd', ['decode_depth' => 2]);

    expect($normalized->decodedVariants)->toBe([
        '/%2e%2e/%2e%2e/etc/passwd',
        '/../../etc/passwd',
    ]);
});

it('bounded decode does not loop indefinitely on deeply nested encoding', function () {
    $uri = '/'.str_repeat('%25', 50).'2e';
    $normalized = normalize($uri, ['decode_depth' => 3]);

    expect(count($normalized->decodedVariants))->toBe(3);
});

it('splits path and query', function () {
    $normalized = normalize('/api/users?page=2&filter=admin');

    expect($normalized->normalizedPath)->toBe('/api/users');
    expect($normalized->normalizedQuery)->toContain('filter=admin');
    expect($normalized->normalizedUri)->toContain('?');
});

it('flags oversized uris instead of processing unbounded input', function () {
    $long = '/'.str_repeat('a', 5000);
    $normalized = normalize($long, ['performance' => ['max_uri_length' => 256]]);

    expect($normalized->isOversized())->toBeTrue();
    expect(strlen($normalized->normalizedPath))->toBeLessThanOrEqual(256);
});

it('handles empty path as root', function () {
    $normalized = normalize('');

    expect($normalized->normalizedPath)->toBe('/');
});

it('handles malformed uris without exceptions', function (string $uri) {
    $normalized = normalize($uri);

    expect($normalized->normalizedPath)->toBeString();
})->with([
    'null byte',
    '/%',
    '/%2',
    'http://',
    '///',
    'a?b?c',
    '/..%2f..%2f',
    '/\\..\\..\\',
    '?foo=bar',
    '/💥/emoji',
]);
