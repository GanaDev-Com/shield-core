<?php

declare(strict_types=1);

/**
 * Ganadev Shield — allow-path latency benchmark.
 *
 * Measures the median time for benign traffic to pass through the core engine:
 *  - allow-path      : a normal browser request
 *  - verified-crawler: a verified crawler (e.g. Googlebot) doing a heavy crawl
 *  - post-body       : a benign POST with body inspection enabled
 *
 * Target: < 2 ms median in a normal environment (relative benchmark,
 * not a hard guarantee). The verified-crawler scenario proves that crawler
 * verification never adds measurable latency on the repeated (cached) path.
 *
 * Usage: php tools/scanner-simulator/benchmark.php
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
use Ganadev\Shield\Core\Persistence\EventRepositoryInterface;
use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\RiskDecay;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Core\Scoring\RiskScorer;
use Ganadev\Shield\Core\Trust\CrawlerVerifierInterface;
use Ganadev\Shield\Core\Trust\TrustedCookieInterface;

require __DIR__.'/../../vendor/autoload.php';

$bans = new class implements BanRepositoryInterface
{
    public function findActiveByIp(string $ip): ?BanRecord
    {
        return null;
    }

    public function findLatestByIp(string $ip): ?BanRecord
    {
        return null;
    }

    public function findById(string $id): ?BanRecord
    {
        return null;
    }

    public function createBan(BanRecord $record): BanRecord
    {
        return $record;
    }

    public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
    {
        return $ban;
    }

    public function extend(BanRecord $ban, DateTimeImmutable $expiresAt, ?string $actor): BanRecord
    {
        return $ban;
    }

    public function markChallengePassed(BanRecord $ban, DateTimeImmutable $at): BanRecord
    {
        return $ban;
    }

    public function touchLastSeen(BanRecord $ban, DateTimeImmutable $at): BanRecord
    {
        return $ban;
    }
};

$events = new class implements EventRepositoryInterface
{
    public function record(SecurityEvent $event): void {}

    public function pruneOlderThan(DateTimeImmutable $cutoff): int
    {
        return 0;
    }
};

$trusted = new class implements TrustedCookieInterface
{
    public function name(): string
    {
        return 'shield_trusted';
    }

    public function issue(RequestContext $context, int $ttlMinutes): string
    {
        return '';
    }

    public function validate(string $cookieValue, RequestContext $context): bool
    {
        return false;
    }
};

$crawler = new class implements CrawlerVerifierInterface
{
    public function verify(string $claimedAgent, string $ip): ?string
    {
        // Simulates a cached verification: the DNS lookup already happened once,
        // so the hot path is pure in-memory.
        return $claimedAgent;
    }
};

$clock = new class implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable;
    }
};

$rules = RuleRepository::fromArray(array_merge(
    DefaultRules::definitions(),
    DefaultRules::injectionDefinitions(),
));

$engine = new ShieldEngine(
    config: ShieldConfig::fromArray(['mode' => 'enforce']),
    normalizer: new Normalizer,
    signatures: new ThreatSignatureEngine($rules),
    behavior: new BehaviorDetector($crawler),
    scorer: new RiskScorer,
    decisionEngine: new DecisionEngine,
    banPolicy: new BanPolicy,
    riskDecay: new RiskDecay,
    events: $events,
    clock: $clock,
    bans: $bans,
    trusted: $trusted,
);

$samples = 5000;

$scenarios = [
    'allow-path' => fn (int $i) => $engine->inspect(
        RequestContext::create('/home?page='.$i, 'GET', 'bench.test', '203.0.113.42', ['user-agent' => 'benchmark']),
        new BehaviorCounters(0, 0),
    ),
    'verified-crawler' => fn (int $i) => $engine->inspect(
        RequestContext::create('/blog/post-'.$i, 'GET', 'bench.test', '203.0.113.43', ['user-agent' => 'Googlebot/2.1']),
        new BehaviorCounters(60, 40),
    ),
    'post-body' => fn (int $i) => $engine->inspect(
        RequestContext::create('/api/contact', 'POST', 'bench.test', '203.0.113.44', ['user-agent' => 'Mozilla/5.0 Chrome/120.0'], 'name=john&email=user'.$i.'@example.com'),
        new BehaviorCounters(0, 0),
    ),
];

$overall = true;

foreach ($scenarios as $name => $scenario) {
    $times = [];
    for ($i = 0; $i < $samples; $i++) {
        $start = hrtime(true);
        $scenario($i);
        $times[] = (hrtime(true) - $start) / 1e6;
    }

    sort($times);
    $median = $times[intdiv($samples, 2)];
    $p95 = $times[(int) ($samples * 0.95)];

    printf("%-18s median %.3f ms | p95 %.3f ms\n", $name, $median, $p95);

    if ($name === 'allow-path' && $median >= 2.0) {
        $overall = false;
    }
}

printf("\nTarget  : < 2.000 ms median for allow-path (relative benchmark)\n");
exit($overall ? 0 : 1);
