<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Decision\DecisionEngine;
use Ganadev\Shield\Core\Decision\DecisionInput;
use Ganadev\Shield\Core\Decision\Verdict;
use Ganadev\Shield\Core\Detection\BehaviorDetector;
use Ganadev\Shield\Core\Detection\BehaviorReport;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\RiskDecay;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\Rule;
use Ganadev\Shield\Core\Rules\RuleMatch;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Core\Scoring\RiskScorer;
use Ganadev\Shield\Core\Scoring\ScoreBreakdown;
use Ganadev\Shield\Core\Tests\Support\ArrayCache;
use Ganadev\Shield\Core\Tests\Support\FakeClock;
use Ganadev\Shield\Core\Tests\Support\FakeCrawlerVerifier;
use Ganadev\Shield\Core\Tests\Support\InMemoryBanRepository;
use Ganadev\Shield\Core\Tests\Support\InMemoryEventRepository;
use Ganadev\Shield\Core\Tests\Support\StaticTrustedCookie;
use Ganadev\Shield\Core\Tests\Support\ThrowingBanRepository;

/**
 * @param  array<string, mixed>  $overrides
 */
function coreConfig(array $overrides = []): ShieldConfig
{
    return ShieldConfig::fromArray($overrides);
}

/**
 * @param  array<string, mixed>  $config
 * @param  array<string, mixed>  $deps
 */
function makeEngine(array $config = [], array $deps = []): ShieldEngine
{
    $cfg = coreConfig(array_replace(['mode' => 'enforce'], $config));
    $bans = $deps['bans'] ?? makeBans();
    $events = $deps['events'] ?? makeEvents();
    $clock = $deps['clock'] ?? fakeClock();
    $trusted = $deps['trusted'] ?? new StaticTrustedCookie;
    $crawler = $deps['crawler'] ?? new FakeCrawlerVerifier;

    $definitions = DefaultRules::definitions();
    if ($cfg->rulesPacksInjection) {
        $definitions = array_merge($definitions, DefaultRules::injectionDefinitions());
    }
    if ($cfg->rulesPacksWordpress) {
        $definitions = array_merge($definitions, DefaultRules::wordpressDefinitions());
    }

    return new ShieldEngine(
        config: $cfg,
        normalizer: new Normalizer,
        signatures: new ThreatSignatureEngine(
            RuleRepository::fromArray($definitions),
        ),
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
}

/**
 * @param  array<string, string>  $headers
 */
function shieldRequest(string $uri, string $method = 'GET', string $ip = '203.0.113.10', array $headers = [], string $body = ''): RequestContext
{
    return RequestContext::create(
        rawUri: $uri,
        method: $method,
        host: 'example.test',
        ip: $ip,
        headersSubset: $headers,
        body: $body,
    );
}

function fakeClock(string $at = '2026-01-01 00:00:00'): FakeClock
{
    return new FakeClock(new DateTimeImmutable($at));
}

function makeBans(): InMemoryBanRepository
{
    return new InMemoryBanRepository;
}

function makeEvents(): InMemoryEventRepository
{
    return new InMemoryEventRepository;
}

/**
 * Ban store that always throws, used to exercise the degraded/fail-closed path.
 */
function makeFailingBanRepository(): ThrowingBanRepository
{
    return new ThrowingBanRepository;
}

function makeCache(): ArrayCache
{
    return new ArrayCache;
}

/**
 * Helper bersama untuk test Decision/Scoring. Ditempatkan di file helper global
 * (bukan di satu file test) agar tetap tersedia saat Pest menjalankan subset
 * test — mis. mutation testing paralel yang hanya memuat file test tertentu.
 */
function breakdown(
    int $signature = 0,
    int $behavior = 0,
    int $offense = 0,
    int $challengePenalty = 0,
    bool $critical = false,
): ScoreBreakdown {
    $report = new BehaviorReport($behavior, $behavior > 0 ? ['behavior_signal'] : []);

    $rules = [];
    if ($signature > 0) {
        $rules[] = new RuleMatch(
            Rule::fromArray([
                'id' => $critical ? 'test.critical' : 'test.rule',
                'matcher' => 'contains',
                'value' => 'x',
                'severity' => $critical ? 'critical' : 'high',
                'score' => $signature,
            ]),
        );
    }

    return (new RiskScorer)->score($rules, $report, $offense, $challengePenalty, coreConfig());
}

function decide(
    ScoreBreakdown $score,
    ?BanRecord $ban = null,
    bool $trusted = false,
    string $mode = 'enforce',
): Verdict {
    $cfg = coreConfig(['mode' => $mode]);

    return (new DecisionEngine)->decide(
        new DecisionInput(
            score: $score,
            activeBan: $ban,
            trusted: $trusted,
            thresholdChallenge: $cfg->thresholdChallenge,
            thresholdBan: $cfg->thresholdBan,
            thresholdStrongBan: $cfg->thresholdStrongBan,
            mode: $cfg->mode,
        ),
    );
}
