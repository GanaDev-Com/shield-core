<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Decision\Decision;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;

function activeBan(string $ip = '203.0.113.10', int $offenseCount = 1): BanRecord
{
    $now = new DateTimeImmutable;

    return new BanRecord(
        id: 'ban-1',
        ipAddress: $ip,
        status: BanStatus::Active,
        reason: 'score_ban',
        lastRuleId: 'sensitive.env',
        riskScore: 25,
        violationCount: 1,
        offenseCount: $offenseCount,
        bannedAt: $now,
        expiresAt: $now->modify('+1 hour'),
        releasedAt: null,
        challengePassedAt: null,
        lastSeenAt: $now,
    );
}

it('allows low score requests', function () {
    expect(decide(breakdown(signature: 4))->decision)->toBe(Decision::Allowed);
});

it('observes scores 5-9', function () {
    expect(decide(breakdown(signature: 5))->decision)->toBe(Decision::Observe);
    expect(decide(breakdown(signature: 9))->decision)->toBe(Decision::Observe);
});

it('challenges at exactly the challenge boundary', function () {
    expect(decide(breakdown(signature: 10))->decision)->toBe(Decision::Challenge);
    expect(decide(breakdown(signature: 19))->decision)->toBe(Decision::Challenge);
});

it('temp bans at the ban boundary', function () {
    expect(decide(breakdown(signature: 20))->decision)->toBe(Decision::TempBan);
    expect(decide(breakdown(signature: 29))->decision)->toBe(Decision::TempBan);
});

it('strong ban at 30+', function () {
    expect(decide(breakdown(signature: 30))->decision)->toBe(Decision::TempBan);
    expect(decide(breakdown(signature: 45))->decision)->toBe(Decision::TempBan);
});

it('critical signatures always block even with a trusted cookie', function () {
    $verdict = decide(breakdown(signature: 30, critical: true), trusted: true);

    expect($verdict->decision)->toBe(Decision::BlockRequest);
});

it('banned ip on a normal route is challenged', function () {
    $verdict = decide(breakdown(signature: 0), ban: activeBan());

    expect($verdict->decision)->toBe(Decision::Challenge);
    expect($verdict->reason)->toBe('active_ban_challenge');
});

it('trusted cookie lets a banned ip through on normal routes', function () {
    $verdict = decide(breakdown(signature: 0), ban: activeBan(), trusted: true);

    expect($verdict->decision)->toBe(Decision::Allowed);
    expect($verdict->reason)->toBe('trusted_cookie');
});

it('trusted cookie bypasses a score challenge below the ban threshold', function () {
    $verdict = decide(breakdown(signature: 10), trusted: true);

    expect($verdict->decision)->toBe(Decision::Allowed);
});

it('trusted cookie does not protect against a ban-level violation', function () {
    $verdict = decide(breakdown(signature: 22), trusted: true);

    expect($verdict->decision)->toBe(Decision::TempBan);
});

it('observe mode downgrades every blocking decision for logging', function () {
    $verdict = decide(breakdown(signature: 20), mode: 'observe');

    expect($verdict->decision)->toBe(Decision::Observe);
    expect($verdict->intended)->toBe(Decision::TempBan);
    expect($verdict->downgraded())->toBeTrue();
});

it('observe mode also downgrades critical but records the intent', function () {
    $verdict = decide(breakdown(signature: 30, critical: true), mode: 'observe');

    expect($verdict->decision)->toBe(Decision::Observe);
    expect($verdict->intended)->toBe(Decision::BlockRequest);
});

it('challenge mode downgrades temp bans to challenges', function () {
    $verdict = decide(breakdown(signature: 22), mode: 'challenge');

    expect($verdict->decision)->toBe(Decision::Challenge);
});

it('challenge mode still blocks critical signatures', function () {
    $verdict = decide(breakdown(signature: 30, critical: true), mode: 'challenge');

    expect($verdict->decision)->toBe(Decision::BlockRequest);
});

it('verdict exposes blocking helpers', function () {
    $block = decide(breakdown(signature: 20));
    $challenge = decide(breakdown(signature: 10));

    expect($block->blocked())->toBeTrue();
    expect($block->challenged())->toBeFalse();
    expect($challenge->challenged())->toBeTrue();
    expect($challenge->blocked())->toBeFalse();
});
