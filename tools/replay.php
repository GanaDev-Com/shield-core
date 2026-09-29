<?php

declare(strict_types=1);

/**
 * Ganadev Shield — replay a corpus against the current rules.
 *
 * Loads a corpus fixture (waf-corpus.json / bot-corpus.json / scanner-corpus.json)
 * or an events export and reports which entries the current rule set would block.
 *
 * Usage:
 *   php tools/replay.php --corpus=fixtures/waf-corpus.json [--pack-wordpress] [--min-rate=0.98]
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
use Ganadev\Shield\Core\Trust\TrustedCookieInterface;

require __DIR__.'/../vendor/autoload.php';

$args = [];
foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--([a-z-]+)=(.*)$/', $arg, $m)) {
        $args[$m[1]] = $m[2];
    } elseif (preg_match('/^--([a-z-]+)$/', $arg, $m)) {
        $args[$m[1]] = true;
    }
}

$corpusFile = $args['corpus'] ?? __DIR__.'/../fixtures/waf-corpus.json';
$minRate = (float) ($args['min-rate'] ?? 0.98);
$packWordpress = isset($args['pack-wordpress']);

$definitions = DefaultRules::definitions();
if ($packWordpress) {
    $definitions = array_merge($definitions, DefaultRules::wordpressDefinitions());
}
$definitions = array_merge($definitions, DefaultRules::injectionDefinitions());

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

$clock = new class implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable;
    }
};

$engine = new ShieldEngine(
    config: ShieldConfig::fromArray(['mode' => 'enforce']),
    normalizer: new Normalizer,
    signatures: new ThreatSignatureEngine(RuleRepository::fromArray($definitions)),
    behavior: new BehaviorDetector,
    scorer: new RiskScorer,
    decisionEngine: new DecisionEngine,
    banPolicy: new BanPolicy,
    riskDecay: new RiskDecay,
    events: $events,
    clock: $clock,
    bans: $bans,
    trusted: $trusted,
);

$data = json_decode((string) file_get_contents($corpusFile), true, 512, JSON_THROW_ON_ERROR);

$byCategory = [];
$totalBlock = 0;
$detected = 0;
$falsePositives = 0;

$entries = $data['entries'] ?? [];
$eventsList = $data['events'] ?? [];
if ($eventsList !== []) {
    foreach ($eventsList as $event) {
        $entries[] = [
            'uri' => (string) ($event['normalized_uri'] ?? $event['uri'] ?? '/'),
            'method' => (string) ($event['method'] ?? 'GET'),
            'expected' => 'allow',
            'category' => (string) ($event['rule_id'] ?? 'event'),
        ];
    }
}

foreach ($entries as $index => $entry) {
    $expected = (string) ($entry['expected'] ?? 'allow');
    $ctx = RequestContext::create(
        (string) ($entry['uri'] ?? '/'),
        (string) ($entry['method'] ?? 'GET'),
        'replay.test',
        '203.0.113.'.(($index % 200) + 1),
    );
    $result = $engine->inspect($ctx, new BehaviorCounters);
    $blocked = $result->shouldBlock();
    $category = (string) ($entry['category'] ?? 'uncategorized');

    $byCategory[$category]['total'] = ($byCategory[$category]['total'] ?? 0) + 1;
    $byCategory[$category]['blocked'] = ($byCategory[$category]['blocked'] ?? 0) + ($blocked ? 1 : 0);

    if ($expected === 'block') {
        $totalBlock++;
        if ($blocked) {
            $detected++;
        }
    } elseif ($blocked) {
        $falsePositives++;
    }
}

ksort($byCategory);

echo "\n  Ganadev Shield — replay report\n\n";
echo "  File       : $corpusFile\n";
if ($packWordpress) {
    echo "  Wordpress  : pack enabled\n";
}
echo '  Entries    : '.count($entries)."\n\n";

printf("  %-52s %7s %7s\n", 'Category', 'Total', 'Blocked');
echo '  '.str_repeat('-', 70)."\n";
foreach ($byCategory as $category => $counts) {
    printf("  %-52s %7d %7d\n", mb_substr($category, 0, 52), $counts['total'], $counts['blocked']);
}
echo '  '.str_repeat('-', 70)."\n";

$rate = $totalBlock > 0 ? $detected / $totalBlock : 1.0;
printf("  Detection rate (expected=block): %.1f%% (%d/%d), target >= %.0f%%\n", $rate * 100, $detected, $totalBlock, $minRate * 100);
printf("  False positives (expected=allow but blocked): %d\n", $falsePositives);

echo "\n";
$pass = $rate >= $minRate && $falsePositives === 0;
echo $pass ? "  \033[32mPASS\033[0m\n" : "  \033[31mFAIL\033[0m\n";

exit($pass ? 0 : 1);
