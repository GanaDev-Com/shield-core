<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Decision\Decision;
use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Engine\EngineResult;
use Ganadev\Shield\Core\Events\SecurityEvent;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;
use Ganadev\Shield\Core\Tests\Support\StaticTrustedCookie;
use Ganadev\Shield\Core\Tests\Support\ThrowingBanRepository;

/**
 * @param  array<string, mixed>  $options
 * @param  array<string, int>  $counters
 * @param  array<string, string>  $headers
 */
function inspect(string $uri, array $options = [], array $counters = [], array $headers = []): EngineResult
{
    $engine = $options['engine'] ?? makeEngine($options['config'] ?? [], $options['deps'] ?? []);

    return $engine->inspect(
        shieldRequest($uri, $options['method'] ?? 'GET', $options['ip'] ?? '203.0.113.10', $headers),
        new BehaviorCounters($counters['unique'] ?? 0, $counters['not_found'] ?? 0),
        ['trusted_cookie' => $options['trusted_cookie'] ?? null],
    );
}

it('blocks a sensitive .env probe before any controller logic', function () {
    $result = inspect('/.env');

    expect($result->shouldBlock())->toBeTrue();
    expect($result->verdict->decision)->toBe(Decision::BlockRequest);
    expect($result->verdict->ruleId)->toBe('sensitive.env');
});

it('persists a temporary ban when enforcing', function () {
    $bans = makeBans();
    $events = makeEvents();
    $engine = makeEngine(['mode' => 'enforce'], ['bans' => $bans, 'events' => $events]);

    $engine->inspect(shieldRequest('/.env'), new BehaviorCounters);

    $active = $bans->findActiveByIp('203.0.113.10');

    expect($active)->not->toBeNull();
    assert($active instanceof BanRecord);
    expect($active->offenseCount)->toBe(1);
    expect($active->expiresAt)->not->toBeNull();
    expect($events->events)->not->toBeEmpty();
    expect($events->last())->not->toBeNull();
    assert($events->last() instanceof SecurityEvent);
    expect($events->last()->decision)->toBe(Decision::BlockRequest->value);
});

it('detects the same payload in the query string', function () {
    $result = inspect('/?file=/.env');

    expect($result->shouldBlock())->toBeTrue();
});

it('detects double encoded traversal at configured decode depth', function () {
    $result = inspect('/%252e%252e/%252e%252e/etc/passwd');

    expect($result->shouldBlock())->toBeTrue();
    expect($result->verdict->ruleId)->toBe('traversal.etcpasswd');
});

it('detects RCE probe php://input', function () {
    $result = inspect('/cgi-bin/php?x=php://input');

    expect($result->shouldBlock())->toBeTrue();
});

it('allows normal traffic without banning', function () {
    $bans = makeBans();
    $engine = makeEngine(['mode' => 'enforce'], ['bans' => $bans]);

    for ($i = 0; $i < 100; $i++) {
        $result = $engine->inspect(shieldRequest("/home?page={$i}"), new BehaviorCounters);
        expect($result->allowed())->toBeTrue();
    }

    expect($bans->findActiveByIp('203.0.113.10'))->toBeNull();
});

it('allows allowlisted hosts and paths', function () {
    $result = inspect('/admin/dashboard', [
        'config' => [
            'allowlist' => [
                'hosts' => ['example.test'],
                'paths' => [],
                'ips' => [],
            ],
        ],
    ]);

    expect($result->allowlisted)->toBeTrue();
    expect($result->allowed())->toBeTrue();
});

it('does not allowlist a request outside the configured path prefixes', function (string $uri, bool $expected) {
    $result = inspect($uri, [
        'config' => [
            'allowlist' => [
                'hosts' => [],
                'paths' => ['/admin'],
                'ips' => [],
            ],
        ],
    ]);

    expect($result->allowlisted)->toBe($expected);
})->with([
    ['/admin', true],
    ['/admin/dashboard', true],
    ['/api/v2/users', false],
    ['/administrator', true],
]);

it('does not allowlist critical signatures', function () {
    $result = inspect('/.env', [
        'config' => [
            'allowlist' => [
                'hosts' => ['example.test'],
                'paths' => [],
                'ips' => [],
            ],
        ],
    ]);

    expect($result->allowlisted)->toBeFalse();
    expect($result->shouldBlock())->toBeTrue();
});

it('fail-open lets normal requests pass when the ban store is down', function () {
    $engine = makeEngine(['fail_mode' => 'open'], ['bans' => new ThrowingBanRepository]);

    $result = $engine->inspect(shieldRequest('/home'), new BehaviorCounters);

    expect($result->infrastructureDegraded)->toBeTrue();
    expect($result->allowed())->toBeTrue();
});

it('fail-open still blocks stateless critical signatures when the store is down', function () {
    $engine = makeEngine(['fail_mode' => 'open'], ['bans' => new ThrowingBanRepository]);

    $result = $engine->inspect(shieldRequest('/.env'), new BehaviorCounters);

    expect($result->shouldBlock())->toBeTrue();
});

it('fail-closed blocks when the ban store is down', function () {
    $engine = makeEngine(['fail_mode' => 'closed'], ['bans' => new ThrowingBanRepository]);

    $result = $engine->inspect(shieldRequest('/home'), new BehaviorCounters);

    expect($result->shouldBlock())->toBeTrue();
    expect($result->verdict->reason)->toBe('fail_closed');
});

it('banned ip hitting a normal route is challenged', function () {
    $bans = makeBans();
    $engine = makeEngine(['mode' => 'enforce'], ['bans' => $bans]);
    $bans->createBan(new BanRecord(
        id: null,
        ipAddress: '203.0.113.10',
        status: BanStatus::Active,
        reason: 'score_ban',
        lastRuleId: null,
        riskScore: 25,
        violationCount: 1,
        offenseCount: 1,
        bannedAt: fakeClock()->now(),
        expiresAt: fakeClock()->now()->modify('+1 hour'),
        releasedAt: null,
        challengePassedAt: null,
        lastSeenAt: fakeClock()->now(),
    ));

    $result = $engine->inspect(shieldRequest('/home'), new BehaviorCounters);

    expect($result->shouldChallenge())->toBeTrue();
});

it('release and trusted cookie clear the ban for normal routes', function () {
    $bans = makeBans();
    $engine = makeEngine(['mode' => 'enforce'], ['bans' => $bans, 'trusted' => new StaticTrustedCookie]);
    $bans->createBan(new BanRecord(
        id: null,
        ipAddress: '203.0.113.10',
        status: BanStatus::Active,
        reason: 'score_ban',
        lastRuleId: null,
        riskScore: 25,
        violationCount: 1,
        offenseCount: 1,
        bannedAt: fakeClock()->now(),
        expiresAt: fakeClock()->now()->modify('+1 hour'),
        releasedAt: null,
        challengePassedAt: null,
        lastSeenAt: fakeClock()->now(),
    ));

    expect($engine->releaseBan('203.0.113.10', 'challenge passed'))->toBeTrue();
    $cookie = $engine->issueTrustedCookie(shieldRequest('/home'));

    $result = $engine->inspect(shieldRequest('/home'), new BehaviorCounters, ['trusted_cookie' => $cookie]);

    expect($result->allowed())->toBeTrue();
});

it('critical violation after release re-bans with escalation', function () {
    $bans = makeBans();
    $engine = makeEngine(['mode' => 'enforce'], ['bans' => $bans]);
    $bans->createBan(new BanRecord(
        id: null,
        ipAddress: '203.0.113.10',
        status: BanStatus::Released,
        reason: 'released',
        lastRuleId: null,
        riskScore: 25,
        violationCount: 1,
        offenseCount: 1,
        bannedAt: fakeClock()->now(),
        expiresAt: fakeClock()->now()->modify('-1 hour'),
        releasedAt: fakeClock()->now(),
        challengePassedAt: null,
        lastSeenAt: fakeClock()->now(),
    ));

    $engine->inspect(shieldRequest('/.env'), new BehaviorCounters);

    $active = $bans->findActiveByIp('203.0.113.10');

    expect($active)->not->toBeNull();
    assert($active instanceof BanRecord);
    expect($active->offenseCount)->toBe(2);
    expect($active->expiresAt)->not->toBeNull();
});

it('critical path is still blocked when a trusted cookie is presented', function () {
    $engine = makeEngine(['mode' => 'enforce'], ['trusted' => new StaticTrustedCookie]);

    $result = inspect('/.env', ['trusted_cookie' => 'valid-token', 'engine' => $engine]);

    expect($result->shouldBlock())->toBeTrue();
});

it('behavior burst pushes the score into the challenge band', function () {
    $result = inspect('/random/1', [], ['unique' => 25]);

    expect($result->shouldChallenge())->toBeTrue();
    expect($result->verdict->behaviorSignals)->toContain('unique_uri_burst');
});

it('404 enumeration contributes to the behavior score', function () {
    $result = inspect('/missing/1', [], ['not_found' => 20]);

    expect($result->score->behaviorScore)->toBeGreaterThanOrEqual(10);
});

it('observe mode logs the intended blocking decision but does not block', function () {
    $events = makeEvents();
    $bans = makeBans();
    $engine = makeEngine(['mode' => 'observe'], ['events' => $events, 'bans' => $bans]);

    $result = $engine->inspect(shieldRequest('/.env'), new BehaviorCounters);

    expect($result->shouldBlock())->toBeFalse();
    expect($result->verdict->decision)->toBe(Decision::Observe);
    expect($events->last())->not->toBeNull();
    assert($events->last() instanceof SecurityEvent);
    expect($events->last()->decision)->toBe(Decision::Observe->value);
    expect($events->last()->intendedDecision)->toBe(Decision::BlockRequest->value);
    expect($bans->findActiveByIp('203.0.113.10'))->toBeNull();
});

it('reports observe mode as not blocking without flipping the engine result verdict', function () {
    $engine = makeEngine(['mode' => 'observe']);

    $result = $engine->inspect(shieldRequest('/.env'), new BehaviorCounters);

    expect($result->verdict->decision)->toBe(Decision::Observe);
    expect($result->verdict->intended)->toBe(Decision::BlockRequest);
    expect($result->shouldBlock())->toBeFalse();
    expect($result->allowed())->toBeFalse();
});

it('records the request id passed through the inspect options', function () {
    $events = makeEvents();
    $engine = makeEngine([], ['events' => $events]);

    $engine->inspect(shieldRequest('/.env'), new BehaviorCounters, ['request_id' => 'req-abc-123']);

    $last = $events->last();
    assert($last instanceof SecurityEvent);
    expect($last->requestId)->toBe('req-abc-123');
});

it('leaves the request id null when the option is missing or blank', function () {
    $events = makeEvents();
    $engine = makeEngine([], ['events' => $events]);

    $engine->inspect(shieldRequest('/.env'), new BehaviorCounters);
    $engine->inspect(shieldRequest('/.env'), new BehaviorCounters, ['request_id' => '']);

    expect($events->events)->toHaveCount(2);
    foreach ($events->events as $event) {
        expect($event->requestId)->toBeNull();
    }
});

it('records allowlist and fail-closed short circuits as security events', function () {
    $events = makeEvents();
    $engine = makeEngine(
        ['fail_mode' => 'closed'],
        ['events' => $events, 'bans' => makeFailingBanRepository()],
    );

    $engine->inspect(shieldRequest('/.env'), new BehaviorCounters);

    $last = $events->last();
    assert($last instanceof SecurityEvent);
    expect($last->decision)->toBe(Decision::BlockRequest->value);
    expect($last->intendedDecision)->toBe(Decision::BlockRequest->value);
    expect($last->scoreDelta)->toBe(99);
});

it('records allowlisted requests that were not critical', function () {
    $engine = makeEngine(
        ['allowlist' => ['ips' => ['203.0.113.9']]],
        ['events' => $events = makeEvents()],
    );

    $result = $engine->inspect(shieldRequest('/health', ip: '203.0.113.9'), new BehaviorCounters);

    expect($result->allowlisted)->toBeTrue();
    expect($events->events)->toHaveCount(1);
    $last = $events->last();
    assert($last instanceof SecurityEvent);
    expect($last->decision)->toBe(Decision::Allowed->value);
    expect($last->intendedDecision)->toBe(Decision::Allowed->value);
    expect($last->scoreDelta)->toBe(0);
});

it('can disable bypass event logging without touching regular event logging', function () {
    $events = makeEvents();
    $engine = makeEngine(
        ['fail_mode' => 'closed', 'logging' => ['bypass_events' => false]],
        ['events' => $events, 'bans' => makeFailingBanRepository()],
    );

    $engine->inspect(shieldRequest('/.env'), new BehaviorCounters);

    expect($events->events)->toBeEmpty();

    $regular = makeEngine(
        [],
        ['events' => $events],
    );
    $regular->inspect(shieldRequest('/.env'), new BehaviorCounters);

    expect($events->events)->toHaveCount(1);
});

describe('logging.level', function () {
    it('skips allowed requests by default', function () {
        $events = makeEvents();
        $engine = makeEngine(['mode' => 'enforce'], ['events' => $events]);

        $engine->inspect(shieldRequest('/home'), new BehaviorCounters);

        expect($events->events)->toBeEmpty();
    });

    it('keeps challenge decisions at the default level', function () {
        $events = makeEvents();
        $engine = makeEngine(['mode' => 'challenge'], ['events' => $events]);

        // 12 from the unique-uri burst, over the default threshold of 10.
        $engine->inspect(shieldRequest('/page-1'), new BehaviorCounters(30, 0));

        expect($events->events)->toHaveCount(1);
        expect($events->events[0]->decision)->toBe(Decision::Challenge->value);
    });

    it('keeps observe decisions at the default level', function () {
        $events = makeEvents();
        $engine = makeEngine(['mode' => 'observe'], ['events' => $events]);

        $engine->inspect(shieldRequest('/home'), new BehaviorCounters(0, 0, 0, true));

        expect($events->events)->toHaveCount(1);
        expect($events->events[0]->decision)->toBe(Decision::Observe->value);
    });

    it('records nothing but terminal blocks at the blocked level', function () {
        $events = makeEvents();
        $engine = makeEngine(['mode' => 'challenge', 'logging' => ['level' => 'blocked']], ['events' => $events]);

        $engine->inspect(shieldRequest('/home'), new BehaviorCounters);
        $engine->inspect(shieldRequest('/page-1'), new BehaviorCounters(30, 0));
        expect($events->events)->toBeEmpty();

        $engine->inspect(shieldRequest('/.env'), new BehaviorCounters);
        expect($events->events)->toHaveCount(1);
    });

    it('records every request at the all level', function () {
        $events = makeEvents();
        $engine = makeEngine(['mode' => 'enforce', 'logging' => ['level' => 'all']], ['events' => $events]);

        $engine->inspect(shieldRequest('/home'), new BehaviorCounters);
        $engine->inspect(shieldRequest('/about'), new BehaviorCounters);

        expect($events->events)->toHaveCount(2);
    });
});

describe('rules.skip_paths', function () {
    it('drops behavior signals on a skipped path', function () {
        $engine = makeEngine(['mode' => 'enforce', 'rules' => ['skip_paths' => ['/api/webhooks']]]);

        $result = $engine->inspect(
            shieldRequest('/api/webhooks', 'POST', '203.0.113.10', ['user-agent' => 'sqlmap']),
            new BehaviorCounters(999, 999, 999, true),
        );

        expect($result->score->total)->toBe(0);
        expect($result->score->behaviorSignals)->toBeEmpty();
        expect($result->verdict->decision)->toBe(Decision::Allowed);
    });

    it('still enforces critical signatures on a skipped path', function () {
        $engine = makeEngine(['mode' => 'enforce', 'rules' => ['skip_paths' => ['/api/webhooks']]]);

        $result = $engine->inspect(shieldRequest('/api/webhooks/.env'), new BehaviorCounters);

        expect($result->shouldBlock())->toBeTrue();
        expect($result->verdict->ruleId)->toBe('sensitive.env');
    });

    it('matches a nested path below the prefix', function () {
        $engine = makeEngine(['mode' => 'enforce', 'rules' => ['skip_paths' => ['/api/webhooks']]]);

        $result = $engine->inspect(
            shieldRequest('/api/webhooks/stripe', 'POST'),
            new BehaviorCounters(999, 999, 999, true),
        );

        expect($result->score->behaviorSignals)->toBeEmpty();
    });

    it('leaves other paths unaffected', function () {
        $engine = makeEngine(['mode' => 'enforce', 'rules' => ['skip_paths' => ['/api/webhooks']]]);

        $result = $engine->inspect(
            shieldRequest('/api/orders', 'POST', '203.0.113.10', ['user-agent' => 'sqlmap']),
            new BehaviorCounters(999, 999, 999, true),
        );

        expect($result->score->behaviorSignals)->not->toBeEmpty();
    });
});

describe('bots.mode=observe', function () {
    it('never escalates an unverified crawler claim through behavior alone', function () {
        $engine = makeEngine([
            'mode' => 'challenge',
            'bots' => ['mode' => 'observe'],
        ]);

        // burst 12 + unverified claim 4 = 16, which is over the challenge
        // threshold of 10 but under the ban threshold of 20.
        $result = $engine->inspect(
            shieldRequest('/page-1', 'GET', '203.0.113.10', googlebotHeaders()),
            new BehaviorCounters(30, 0),
        );

        expect($result->score->total)->toBeGreaterThanOrEqual(10);
        expect($result->verdict->decision)->toBe(Decision::Observe);
        expect($result->verdict->reason)->toStartWith('crawler_behavior_exempt_');
    });

    it('does not even ban an unverified crawler that scores past the ban threshold', function () {
        $bans = makeBans();
        $engine = makeEngine([
            'mode' => 'enforce',
            'bots' => ['mode' => 'observe'],
        ], ['bans' => $bans]);

        // burst 12 + not found 10 + unverified claim 4 = 26, over the ban
        // threshold of 20.
        $result = $engine->inspect(
            shieldRequest('/page-1', 'GET', '203.0.113.10', googlebotHeaders()),
            new BehaviorCounters(30, 30),
        );

        expect($result->verdict->decision)->toBe(Decision::Observe);
        expect($bans->findActiveByIp('203.0.113.10'))->toBeNull();
    });

    it('still blocks a signature match from an unverified crawler', function () {
        $engine = makeEngine([
            'mode' => 'enforce',
            'bots' => ['mode' => 'observe'],
        ]);

        $result = $engine->inspect(
            shieldRequest('/.env', 'GET', '203.0.113.10', googlebotHeaders()),
            new BehaviorCounters(30, 0),
        );

        expect($result->verdict->decision)->toBe(Decision::BlockRequest);
        expect($result->verdict->ruleId)->toBe('sensitive.env');
    });

    it('still challenges an already banned crawler', function () {
        $bans = makeBans();
        $bans->createBan(new BanRecord(
            id: '1',
            ipAddress: '203.0.113.10',
            status: BanStatus::Active,
            reason: 'test',
            lastRuleId: null,
            riskScore: 25,
            violationCount: 1,
            offenseCount: 1,
            bannedAt: new DateTimeImmutable('2026-01-01 00:00:00'),
            expiresAt: new DateTimeImmutable('2026-01-01 01:00:00'),
            releasedAt: null,
            challengePassedAt: null,
            lastSeenAt: new DateTimeImmutable('2026-01-01 00:00:00'),
        ));

        $engine = makeEngine([
            'mode' => 'challenge',
            'bots' => ['mode' => 'observe'],
        ], ['bans' => $bans]);

        $result = $engine->inspect(
            shieldRequest('/page-1', 'GET', '203.0.113.10', googlebotHeaders()),
            new BehaviorCounters(30, 0),
        );

        expect($result->verdict->decision)->toBe(Decision::Challenge);
        expect($result->verdict->reason)->toBe('active_ban_challenge');
    });

    it('forces a challenge for an unverified crawler when bots.mode is challenge', function () {
        $engine = makeEngine([
            'mode' => 'challenge',
            'bots' => ['mode' => 'challenge'],
        ]);

        // The unverified claim (4) plus the bare-Mozilla heuristic (2) stay
        // below the challenge threshold, so the forced override is what must
        // produce the challenge.
        $result = $engine->inspect(
            shieldRequest('/page-1', 'GET', '203.0.113.10', googlebotHeaders()),
            new BehaviorCounters,
        );

        expect($result->score->total)->toBe(6);
        expect($result->verdict->decision)->toBe(Decision::Challenge);
        expect($result->verdict->reason)->toBe('unverified_crawler_claim_googlebot');
    });

    it('still challenges an unverified crawler that already scores over the threshold', function () {
        $engine = makeEngine([
            'mode' => 'challenge',
            'bots' => ['mode' => 'challenge'],
        ]);

        $result = $engine->inspect(
            shieldRequest('/page-1', 'GET', '203.0.113.10', googlebotHeaders()),
            new BehaviorCounters(30, 0),
        );

        expect($result->verdict->decision)->toBe(Decision::Challenge);
    });
});

/**
 * @return array<string, string>
 */
function googlebotHeaders(): array
{
    return ['user-agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'];
}
