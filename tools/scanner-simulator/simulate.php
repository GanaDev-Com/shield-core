<?php

declare(strict_types=1);

/**
 * Ganadev Shield — local scanner simulation suite.
 *
 * Replays the scanner corpus through the framework-agnostic core engine using
 * in-memory persistence. It never sends traffic to external systems.
 *
 * Usage:
 *   php tools/scanner-simulator/simulate.php [--corpus=fixtures/scanner-corpus.json] [--normal=fixtures/normal-traffic.json]
 */

use Ganadev\Shield\Core\Clock\ClockInterface;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Decision\DecisionEngine;
use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Detection\BehaviorDetector;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Events\SecurityEvent;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Persistence\BanRepositoryInterface;
use Ganadev\Shield\Core\Persistence\CacheAdapterInterface;
use Ganadev\Shield\Core\Persistence\EventRepositoryInterface;
use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;
use Ganadev\Shield\Core\Reputation\RiskDecay;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Core\Scoring\RiskScorer;
use Ganadev\Shield\Core\Trust\TrustedCookieInterface;

require __DIR__.'/../../vendor/autoload.php';

final class SimClock implements ClockInterface
{
    public function __construct(private DateTimeImmutable $now = new DateTimeImmutable) {}

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }
}

final class SimCache implements CacheAdapterInterface
{
    private array $store = [];

    public function get(string $key): mixed
    {
        return $this->store[$key]['value'] ?? null;
    }

    public function set(string $key, mixed $value, int $ttlSeconds): bool
    {
        $this->store[$key] = ['value' => $value];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->store[$key]);

        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->store);
    }

    public function increment(string $key, int $ttlSeconds): int
    {
        $value = (int) ($this->store[$key]['value'] ?? 0) + 1;
        $this->store[$key] = ['value' => $value];

        return $value;
    }
}

final class SimBans implements BanRepositoryInterface
{
    private array $records = [];

    private int $seq = 1;

    public function findActiveByIp(string $ip): ?BanRecord
    {
        $record = $this->records[$ip] ?? null;

        return $record?->isActive() ? $record : null;
    }

    public function findLatestByIp(string $ip): ?BanRecord
    {
        return $this->records[$ip] ?? null;
    }

    public function findById(string $id): ?BanRecord
    {
        foreach ($this->records as $record) {
            if ($record->id === $id) {
                return $record;
            }
        }

        return null;
    }

    public function createBan(BanRecord $record): BanRecord
    {
        $created = new BanRecord(
            id: (string) $this->seq++,
            ipAddress: $record->ipAddress,
            status: $record->status,
            reason: $record->reason,
            lastRuleId: $record->lastRuleId,
            riskScore: $record->riskScore,
            violationCount: $record->violationCount,
            offenseCount: $record->offenseCount,
            bannedAt: $record->bannedAt,
            expiresAt: $record->expiresAt,
            releasedAt: $record->releasedAt,
            challengePassedAt: $record->challengePassedAt,
            lastSeenAt: $record->lastSeenAt,
            metadata: $record->metadata,
        );
        $this->records[$record->ipAddress] = $created;

        return $created;
    }

    public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
    {
        return $this->mutate($ban, fn (BanRecord $r) => new BanRecord(
            id: $r->id,
            ipAddress: $r->ipAddress,
            status: BanStatus::Released,
            reason: $r->reason,
            lastRuleId: $r->lastRuleId,
            riskScore: $r->riskScore,
            violationCount: $r->violationCount,
            offenseCount: $r->offenseCount,
            bannedAt: $r->bannedAt,
            expiresAt: $r->expiresAt,
            releasedAt: new DateTimeImmutable,
            challengePassedAt: $r->challengePassedAt,
            lastSeenAt: $r->lastSeenAt,
            metadata: $r->metadata,
        ));
    }

    public function extend(BanRecord $ban, DateTimeImmutable $expiresAt, ?string $actor): BanRecord
    {
        return $this->mutate($ban, fn (BanRecord $r) => new BanRecord(
            id: $r->id,
            ipAddress: $r->ipAddress,
            status: $r->status,
            reason: $r->reason,
            lastRuleId: $r->lastRuleId,
            riskScore: $r->riskScore,
            violationCount: $r->violationCount,
            offenseCount: $r->offenseCount,
            bannedAt: $r->bannedAt,
            expiresAt: $expiresAt,
            releasedAt: $r->releasedAt,
            challengePassedAt: $r->challengePassedAt,
            lastSeenAt: $r->lastSeenAt,
            metadata: $r->metadata,
        ));
    }

    public function markChallengePassed(BanRecord $ban, DateTimeImmutable $at): BanRecord
    {
        return $this->mutate($ban, fn (BanRecord $r) => new BanRecord(
            id: $r->id,
            ipAddress: $r->ipAddress,
            status: BanStatus::Released,
            reason: $r->reason,
            lastRuleId: $r->lastRuleId,
            riskScore: $r->riskScore,
            violationCount: $r->violationCount,
            offenseCount: $r->offenseCount,
            bannedAt: $r->bannedAt,
            expiresAt: $r->expiresAt,
            releasedAt: $at,
            challengePassedAt: $at,
            lastSeenAt: $r->lastSeenAt,
            metadata: $r->metadata,
        ));
    }

    public function touchLastSeen(BanRecord $ban, DateTimeImmutable $at): BanRecord
    {
        return $this->mutate($ban, fn (BanRecord $r) => new BanRecord(
            id: $r->id,
            ipAddress: $r->ipAddress,
            status: $r->status,
            reason: $r->reason,
            lastRuleId: $r->lastRuleId,
            riskScore: $r->riskScore,
            violationCount: $r->violationCount,
            offenseCount: $r->offenseCount,
            bannedAt: $r->bannedAt,
            expiresAt: $r->expiresAt,
            releasedAt: $r->releasedAt,
            challengePassedAt: $r->challengePassedAt,
            lastSeenAt: $at,
            metadata: $r->metadata,
        ));
    }

    private function mutate(BanRecord $ban, callable $fn): BanRecord
    {
        $updated = $fn($ban);
        $this->records[$ban->ipAddress] = $updated;

        return $updated;
    }
}

final class SimEvents implements EventRepositoryInterface
{
    public array $events = [];

    public function record(SecurityEvent $event): void
    {
        $this->events[] = $event;
    }

    public function pruneOlderThan(DateTimeImmutable $cutoff): int
    {
        return 0;
    }
}

final class SimTrustedCookie implements TrustedCookieInterface
{
    public function name(): string
    {
        return 'shield_trusted';
    }

    public function issue(RequestContext $context, int $ttlMinutes): string
    {
        return 'sim-trusted';
    }

    public function validate(string $cookieValue, RequestContext $context): bool
    {
        return true;
    }
}

final class Simulator
{
    private array $failures = [];

    public function run(string $corpusPath, string $normalPath): int
    {
        $corpus = json_decode((string) file_get_contents($corpusPath), true, 512, JSON_THROW_ON_ERROR);
        $normal = json_decode((string) file_get_contents($normalPath), true, 512, JSON_THROW_ON_ERROR);

        $this->assertNormalTraffic($normal['requests'] ?? []);
        $this->assertScenarios($corpus['scenarios'] ?? []);

        $this->printSummary();

        return $this->failures === [] ? 0 : 1;
    }

    private function engine(): ShieldEngine
    {
        $definitions = array_merge(
            DefaultRules::definitions(),
            DefaultRules::injectionDefinitions(),
        );

        return new ShieldEngine(
            config: ShieldConfig::fromArray(['mode' => 'enforce']),
            normalizer: new Normalizer,
            signatures: new ThreatSignatureEngine(RuleRepository::fromArray($definitions)),
            behavior: new BehaviorDetector,
            scorer: new RiskScorer,
            decisionEngine: new DecisionEngine,
            banPolicy: new BanPolicy,
            riskDecay: new RiskDecay,
            events: new SimEvents,
            clock: new SimClock,
            bans: new SimBans,
            trusted: new SimTrustedCookie,
        );
    }

    private function assertNormalTraffic(array $requests): void
    {
        $engine = $this->engine();
        $counter = [];

        foreach ($requests as $request) {
            $ctx = $this->context($request);
            $count = ($counter[$ctx->ip] ?? 0) + 1;
            $counter[$ctx->ip] = $count;

            $result = $engine->inspect($ctx, new BehaviorCounters($count, 0));

            if ($result->shouldBlock() || $result->shouldChallenge()) {
                $this->fail('normal-traffic', $ctx->rawUri, 'allow', $result->verdict->decision->value);
            }
        }

        $this->ok('normal-traffic', count($requests).' normal requests');
    }

    private function assertScenarios(array $scenarios): void
    {
        foreach ($scenarios as $scenario) {
            $this->runScenario($scenario);
        }
    }

    private function runScenario(array $scenario): void
    {
        $engine = $this->engine();
        $unique = [];
        $notFound = [];
        $simulate404 = (bool) ($scenario['simulate_404'] ?? false);

        $peaks = [];
        $expected = (string) $scenario['expected'];

        foreach ($scenario['requests'] as $requestData) {
            $ctx = $this->context($requestData);
            $unique[$ctx->ip] = ($unique[$ctx->ip] ?? 0) + 1;
            if ($simulate404) {
                $notFound[$ctx->ip] = ($notFound[$ctx->ip] ?? 0) + 1;
            }

            $result = $engine->inspect(
                $ctx,
                new BehaviorCounters($unique[$ctx->ip], $notFound[$ctx->ip] ?? 0),
            );

            $peaks[] = match (true) {
                $result->shouldBlock() => 'block',
                $result->shouldChallenge() => 'challenge',
                default => 'allow',
            };
        }

        $peak = in_array('block', $peaks, true) ? 'block'
            : (in_array('challenge', $peaks, true) ? 'challenge' : 'allow');

        $passed = match ($expected) {
            'block' => $peak === 'block',
            'challenge', 'ban' => $peak === 'challenge' || $peak === 'block',
            default => $peak === 'allow',
        };

        if (! $passed) {
            $this->fail(
                (string) $scenario['id'],
                'sequence of '.count($peaks).' requests',
                $expected,
                $peak,
            );

            return;
        }

        $this->ok((string) $scenario['id'], (string) $scenario['name']);
    }

    private function context(array $data): RequestContext
    {
        $headers = $data['headers'] ?? [];

        return RequestContext::create(
            rawUri: (string) ($data['uri'] ?? '/'),
            method: (string) ($data['method'] ?? 'GET'),
            host: (string) ($data['host'] ?? 'sim.test'),
            ip: (string) ($data['ip'] ?? '203.0.113.99'),
            headersSubset: $headers,
        );
    }

    private function ok(string $id, string $detail): void
    {
        echo sprintf("  \033[32mPASS\033[0m %-12s %s\n", $id, $detail);
    }

    private function fail(string $id, string $uri, string $expected, string $actual): void
    {
        $this->failures[] = compact('id', 'uri', 'expected', 'actual');
        echo sprintf("  \033[31mFAIL\033[0m %-12s %s expected=%s actual=%s\n", $id, $uri, $expected, $actual);
    }

    private function printSummary(): void
    {
        echo "\n";
        if ($this->failures === []) {
            echo "\033[32mAll simulation scenarios passed.\033[0m\n";
        } else {
            echo sprintf("\033[31m%d scenario(s) failed.\033[0m\n", count($this->failures));
        }
    }
}

$corpus = $argv[1] ?? __DIR__.'/../../fixtures/scanner-corpus.json';
$normal = $argv[2] ?? __DIR__.'/../../fixtures/normal-traffic.json';

exit((new Simulator)->run($corpus, $normal));
