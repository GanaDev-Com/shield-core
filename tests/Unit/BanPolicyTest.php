<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;
use Ganadev\Shield\Core\Reputation\RiskDecay;

it('escalates ban duration with offense count', function () {
    $policy = new BanPolicy;
    $durations = [15, 60, 360, 1440];

    expect($policy->durationFor(1, $durations))->toBe(15);
    expect($policy->durationFor(2, $durations))->toBe(60);
    expect($policy->durationFor(3, $durations))->toBe(360);
    expect($policy->durationFor(4, $durations))->toBe(1440);
});

it('clamps duration at the last configured value for 5+ offenses', function () {
    $policy = new BanPolicy;
    $durations = [15, 60, 360, 1440];

    expect($policy->durationFor(5, $durations))->toBe(1440);
    expect($policy->durationFor(12, $durations))->toBe(1440);
});

it('flags manual review from the fifth offense', function () {
    $policy = new BanPolicy;

    expect($policy->requiresManualReview(4))->toBeFalse();
    expect($policy->requiresManualReview(5))->toBeTrue();
    expect($policy->requiresManualReview(6))->toBeTrue();
});

it('increments offense count while keeping history after release', function () {
    $policy = new BanPolicy;
    $bans = makeBans();

    $clock = fakeClock();
    $ban = $bans->createBan(new BanRecord(
        id: null,
        ipAddress: '1.2.3.4',
        status: BanStatus::Active,
        reason: 'first',
        lastRuleId: null,
        riskScore: 20,
        violationCount: 1,
        offenseCount: 1,
        bannedAt: $clock->now(),
        expiresAt: $clock->now()->modify('+15 minutes'),
        releasedAt: null,
        challengePassedAt: null,
        lastSeenAt: $clock->now(),
    ));

    $released = $bans->release($ban, 'challenge passed', null);

    expect($released->status)->toBe(BanStatus::Released);

    $nextOffense = $policy->nextOffenseCount($released);

    expect($nextOffense)->toBe(2);
});

it('fresh ip starts at offense one', function () {
    $policy = new BanPolicy;

    expect($policy->nextOffenseCount(null))->toBe(1);
});

it('risk score and offense count decay after a quiet period', function () {
    $decay = new RiskDecay;
    $lastSeen = new DateTimeImmutable('2026-01-01 00:00:00');

    expect($decay->decayOffenseCount(5, $lastSeen, $lastSeen->modify('+2 days')))->toBe(3);
    expect($decay->decayScore(60, $lastSeen, $lastSeen->modify('+6 hours')))->toBe(0);
    expect($decay->decayOffenseCount(0, $lastSeen, $lastSeen->modify('+1 hour')))->toBe(0);
});
