<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Support\IpCidrMatcher;

it('matches IPv4 addresses inside a CIDR range', function () {
    expect(IpCidrMatcher::inRange('66.249.79.12', '66.249.64.0/19'))->toBeTrue();
    expect(IpCidrMatcher::inRange('66.249.95.255', '66.249.64.0/19'))->toBeTrue();
});

it('rejects IPv4 addresses outside a CIDR range', function () {
    expect(IpCidrMatcher::inRange('66.249.96.1', '66.249.64.0/19'))->toBeFalse();
    expect(IpCidrMatcher::inRange('8.8.8.8', '66.249.64.0/19'))->toBeFalse();
});

it('matches an exact IP without a prefix', function () {
    expect(IpCidrMatcher::inRange('203.0.113.10', '203.0.113.10'))->toBeTrue();
    expect(IpCidrMatcher::inRange('203.0.113.11', '203.0.113.10'))->toBeFalse();
});

it('handles IPv6 CIDR ranges', function () {
    expect(IpCidrMatcher::inRange('2607:f8b0:4004::1', '2607:f8b0:4004::/48'))->toBeTrue();
    expect(IpCidrMatcher::inRange('2607:f8b0:4005::1', '2607:f8b0:4004::/48'))->toBeFalse();
});

it('supports a /0 range', function () {
    expect(IpCidrMatcher::inRange('203.0.113.10', '0.0.0.0/0'))->toBeTrue();
});

it('rejects malformed CIDR input without throwing', function () {
    expect(IpCidrMatcher::inRange('203.0.113.10', 'not-a-cidr'))->toBeFalse();
    expect(IpCidrMatcher::inRange('203.0.113.10', '10.0.0.0/33'))->toBeFalse();
});

it('checks membership across multiple ranges', function () {
    expect(IpCidrMatcher::inAnyRange('66.249.79.12', ['8.8.8.0/24', '66.249.64.0/19']))->toBeTrue();
    expect(IpCidrMatcher::inAnyRange('66.249.96.1', ['8.8.8.0/24', '66.249.64.0/19']))->toBeFalse();
});
