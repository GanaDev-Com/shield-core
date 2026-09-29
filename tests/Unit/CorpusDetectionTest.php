<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Decision\DecisionEngine;
use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Detection\BehaviorDetector;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\RiskDecay;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Core\Scoring\RiskScorer;
use Ganadev\Shield\Core\Tests\Support\InMemoryBanRepository;
use Ganadev\Shield\Core\Tests\Support\InMemoryEventRepository;
use Ganadev\Shield\Core\Tests\Support\StaticTrustedCookie;

/**
 * @param  array<string, mixed>  $config
 */
function corpusEngine(array $config = []): ShieldEngine
{
    $cfg = coreConfig(array_replace(['mode' => 'enforce'], $config));
    $bans = new InMemoryBanRepository;
    $events = new InMemoryEventRepository;

    $rules = RuleRepository::fromArray(array_merge(
        DefaultRules::definitions(),
        DefaultRules::wordpressDefinitions(),
    ));

    return new ShieldEngine(
        config: $cfg,
        normalizer: new Normalizer,
        signatures: new ThreatSignatureEngine($rules),
        behavior: new BehaviorDetector,
        scorer: new RiskScorer,
        decisionEngine: new DecisionEngine,
        banPolicy: new BanPolicy,
        riskDecay: new RiskDecay,
        events: $events,
        clock: fakeClock(),
        bans: $bans,
        trusted: new StaticTrustedCookie,
    );
}

function corpusPath(string $file): string
{
    return __DIR__.'/../../fixtures/'.$file;
}

/**
 * @param  array<string, mixed>  $config
 * @return array<int, array<string, mixed>>
 */
function runCorpus(string $file, array $config = []): array
{
    $corpus = json_decode((string) file_get_contents(corpusPath($file)), true, 512, JSON_THROW_ON_ERROR);
    $engine = corpusEngine($config);

    $results = [];
    foreach ($corpus['entries'] as $index => $entry) {
        $ctx = shieldRequest(
            (string) $entry['uri'],
            (string) ($entry['method'] ?? 'GET'),
            '203.0.113.'.(($index % 200) + 1),
        );

        $result = $engine->inspect($ctx, new BehaviorCounters);

        $results[] = [
            'entry' => $entry,
            'blocked' => $result->shouldBlock(),
            'allowed' => $result->allowed(),
            'rule' => $result->verdict->ruleId,
            'decision' => $result->verdict->decision->value,
        ];
    }

    return $results;
}

/**
 * @param  array<string, mixed>  $config
 */
function assertCorpusDetection(string $file, float $minRate, array $config = []): void
{
    $results = runCorpus($file, $config);
    $block = array_values(array_filter($results, fn ($r) => $r['entry']['expected'] === 'block'));
    $allow = array_values(array_filter($results, fn ($r) => $r['entry']['expected'] === 'allow'));

    $detected = count(array_filter($block, fn ($r) => $r['blocked']));
    $rate = $block === [] ? 1.0 : $detected / count($block);

    expect($rate)->toBeGreaterThanOrEqual($minRate,
        sprintf('%s: %.1f%% (%.0f/%.0f) server-side entries detected, target %.0f%%', $file, $rate * 100, $detected, count($block), $minRate * 100));

    $falsePositives = array_filter($allow, fn ($r) => $r['blocked']);
    expect($falsePositives)->toBeEmpty($file.': weak-signal entries must never block');
}

it('detects >= 98% of the waf corpus server-side attacks', function () {
    assertCorpusDetection('waf-corpus.json', 0.98);
});

it('detects all bot corpus URI-based attacks', function () {
    assertCorpusDetection('bot-corpus.json', 1.0);
});
