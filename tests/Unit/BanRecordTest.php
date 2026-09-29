<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;

function cachedBanRecord(): BanRecord
{
    $now = new DateTimeImmutable('2026-01-02 03:04:05', new DateTimeZone('UTC'));

    return new BanRecord(
        id: 'ban-7',
        ipAddress: '203.0.113.9',
        status: BanStatus::ManualBlock,
        reason: 'rce.ini_directives',
        lastRuleId: 'rce.ini_directives',
        riskScore: 91,
        violationCount: 4,
        offenseCount: 3,
        bannedAt: $now,
        expiresAt: $now->modify('+2 hours'),
        releasedAt: null,
        challengePassedAt: $now->modify('-1 minute'),
        lastSeenAt: $now->modify('-2 minutes'),
        metadata: ['source' => 'unit', 'count' => 3],
    );
}

it('round-trips through a plain array without losing any field', function () {
    $record = cachedBanRecord();
    $restored = BanRecord::fromArray($record->toArray());

    expect($restored->id)->toBe($record->id);
    expect($restored->ipAddress)->toBe($record->ipAddress);
    expect($restored->status)->toBe($record->status);
    expect($restored->reason)->toBe($record->reason);
    expect($restored->lastRuleId)->toBe($record->lastRuleId);
    expect($restored->riskScore)->toBe($record->riskScore);
    expect($restored->violationCount)->toBe($record->violationCount);
    expect($restored->offenseCount)->toBe($record->offenseCount);
    expect($restored->bannedAt->format(DateTimeInterface::ATOM))->toBe($record->bannedAt->format(DateTimeInterface::ATOM));
    expect($restored->expiresAt?->format(DateTimeInterface::ATOM))->toBe($record->expiresAt?->format(DateTimeInterface::ATOM));
    expect($restored->releasedAt)->toBeNull();
    expect($restored->challengePassedAt?->format(DateTimeInterface::ATOM))->toBe($record->challengePassedAt?->format(DateTimeInterface::ATOM));
    expect($restored->lastSeenAt->format(DateTimeInterface::ATOM))->toBe($record->lastSeenAt->format(DateTimeInterface::ATOM));
    expect($restored->metadata)->toBe($record->metadata);
    expect($restored->isActive())->toBeTrue();
});

it('produces a payload that survives a serialize round-trip and json encoding', function () {
    $payload = cachedBanRecord()->toArray();

    expect($payload)->toBeArray();
    expect(serialize($payload))->toBeString();
    expect(unserialize(serialize($payload)))->toBeArray();
    expect(json_encode($payload))->toBeString();

    // No object may appear anywhere in the cached payload.
    expect(array_filter($payload, is_object(...)))->toBe([]);

    $restored = BanRecord::fromArray(json_decode((string) json_encode($payload), true));
    expect($restored->ipAddress)->toBe('203.0.113.9');
    expect($restored->status)->toBe(BanStatus::ManualBlock);
});

it('keeps nullable columns null', function () {
    $now = new DateTimeImmutable;

    $restored = BanRecord::fromArray((new BanRecord(
        id: null,
        ipAddress: '198.51.100.4',
        status: BanStatus::Active,
        reason: 'test',
        lastRuleId: null,
        riskScore: 0,
        violationCount: 1,
        offenseCount: 1,
        bannedAt: $now,
        expiresAt: null,
        releasedAt: null,
        challengePassedAt: null,
        lastSeenAt: $now,
        metadata: null,
    ))->toArray());

    expect($restored->id)->toBeNull();
    expect($restored->lastRuleId)->toBeNull();
    expect($restored->expiresAt)->toBeNull();
    expect($restored->releasedAt)->toBeNull();
    expect($restored->challengePassedAt)->toBeNull();
    expect($restored->metadata)->toBeNull();
});

it('rejects a payload that is not a known ban record', function () {
    expect(fn () => BanRecord::fromArray(['ip_address' => '198.51.100.4', 'status' => 'nope']))->toThrow(ValueError::class);
    expect(fn () => BanRecord::fromArray([]))->toThrow(ValueError::class);
});
