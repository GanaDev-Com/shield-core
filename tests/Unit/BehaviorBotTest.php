<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Detection\BehaviorDetector;
use Ganadev\Shield\Core\Detection\BehaviorReport;
use Ganadev\Shield\Core\Exceptions\InvalidConfigException;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Tests\Support\FakeCrawlerVerifier;
use Ganadev\Shield\Core\Trust\CrawlerVerifierInterface;

/**
 * @param  array<string, string>  $headers
 * @param  array<string, mixed>  $config
 */
function behaviorReport(array $headers, string $method = 'GET', array $config = [], ?CrawlerVerifierInterface $verifier = null): BehaviorReport
{
    $cfg = coreConfig($config);
    $ctx = shieldRequest('/home', $method, '203.0.113.5', $headers);

    return (new BehaviorDetector($verifier))->evaluate(
        $ctx,
        (new Normalizer)->normalize($ctx, $cfg),
        new BehaviorCounters,
        $cfg,
    );
}

it('flags a bare Mozilla/5.0 user agent as suspicious', function () {
    $report = behaviorReport(['user-agent' => 'Mozilla/5.0']);

    expect($report->has(BehaviorDetector::SIGNAL_SUSPICIOUS_UA))->toBeTrue();
});

it('does not flag a full browser user agent', function () {
    $report = behaviorReport(['user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36']);

    expect($report->has(BehaviorDetector::SIGNAL_SUSPICIOUS_UA))->toBeFalse();
});

it('flags missing referer only on POST when enabled', function () {
    $report = behaviorReport([], 'POST');

    expect($report->has(BehaviorDetector::SIGNAL_MISSING_REFERER))->toBeTrue();

    $getReport = behaviorReport([], 'GET');
    expect($getReport->has(BehaviorDetector::SIGNAL_MISSING_REFERER))->toBeFalse();
});

it('respects the missing referer signal config', function () {
    $report = behaviorReport([], 'POST', ['behavior' => ['missing_referer_signal' => false]]);

    expect($report->has(BehaviorDetector::SIGNAL_MISSING_REFERER))->toBeFalse();
});

it('classifies known crawlers and reports their name', function () {
    $report = behaviorReport(['user-agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)']);

    expect($report->knownCrawler)->toBe('googlebot');
    expect($report->has(BehaviorDetector::SIGNAL_KNOWN_CRAWLER))->toBeTrue();
});

it('classifies known crawlers from the configurable list', function () {
    $report = behaviorReport(['user-agent' => 'ClaudeBot/1.0'], config: []);

    expect($report->knownCrawler)->toBe('claudebot');
});

it('honours custom suspicious user agent overrides', function () {
    $report = behaviorReport(
        ['user-agent' => 'MyCustomScanner/2.0'],
        'GET',
        ['behavior' => ['suspicious_user_agents' => ['mycustomscanner']]],
    );

    expect($report->has(BehaviorDetector::SIGNAL_SUSPICIOUS_UA))->toBeTrue();
});

it('allows known crawlers when bots.mode is off', function () {
    $engine = makeEngine(['mode' => 'enforce', 'bots' => ['mode' => 'off']]);
    $result = $engine->inspect(
        shieldRequest('/home', 'GET', '203.0.113.5', ['user-agent' => 'Googlebot/2.1']),
        new BehaviorCounters,
    );

    expect($result->allowed())->toBeTrue();
});

it('never challenges an unverified crawler claim with the default bot mode', function () {
    $engine = makeEngine(['mode' => 'enforce']);
    $result = $engine->inspect(
        shieldRequest('/home', 'GET', '203.0.113.5', ['user-agent' => 'Googlebot/2.1']),
        new BehaviorCounters,
    );

    expect($result->shouldChallenge())->toBeFalse();
    expect($result->shouldBlock())->toBeFalse();
});

it('records the unverified crawler signal even when it is not challenged', function () {
    $engine = makeEngine(['mode' => 'enforce']);
    $result = $engine->inspect(
        shieldRequest('/home', 'GET', '203.0.113.5', ['user-agent' => 'Googlebot/2.1']),
        new BehaviorCounters,
    );

    expect($result->verdict->behaviorSignals)
        ->toContain(BehaviorDetector::SIGNAL_UNVERIFIED_CRAWLER_CLAIM);
});

it('challenges an unverified crawler claim when bots.mode is challenge', function () {
    $engine = makeEngine(['mode' => 'enforce', 'bots' => ['mode' => 'challenge']]);
    $result = $engine->inspect(
        shieldRequest('/home', 'GET', '203.0.113.5', ['user-agent' => 'Googlebot/2.1']),
        new BehaviorCounters,
    );

    expect($result->shouldChallenge())->toBeTrue();
    expect($result->verdict->reason)->toBe('unverified_crawler_claim_googlebot');
});

it('lets a verified crawler pass when bots.mode is challenge', function () {
    $engine = makeEngine([
        'mode' => 'enforce',
        'bots' => ['mode' => 'challenge'],
    ], ['crawler' => new FakeCrawlerVerifier(['203.0.113.5' => 'googlebot'])]);

    $result = $engine->inspect(
        shieldRequest('/home', 'GET', '203.0.113.5', ['user-agent' => 'Googlebot/2.1']),
        new BehaviorCounters,
    );

    expect($result->allowed())->toBeTrue();
    expect($result->verdict->reason)->toBe('allowed');
});

it('never challenges a verified crawler even under heavy burst counters', function () {
    $engine = makeEngine([
        'mode' => 'enforce',
        'bots' => ['mode' => 'challenge'],
    ], ['crawler' => new FakeCrawlerVerifier(['203.0.113.5' => 'googlebot'])]);

    $result = $engine->inspect(
        shieldRequest('/home', 'GET', '203.0.113.5', ['user-agent' => 'Googlebot/2.1']),
        new BehaviorCounters(uniqueUriCount: 60, notFoundCount: 50, pathRequestCount: 200),
    );

    expect($result->allowed())->toBeTrue();
});

it('zeroes behavior deltas for a verified crawler', function () {
    $report = behaviorReport(
        ['user-agent' => 'Googlebot/2.1'],
        'GET',
        ['bots' => ['mode' => 'challenge']],
        new FakeCrawlerVerifier(['203.0.113.5' => 'googlebot']),
    );

    expect($report->totalDelta)->toBe(0);
    expect($report->has(BehaviorDetector::SIGNAL_VERIFIED_CRAWLER))->toBeTrue();
    expect($report->has(BehaviorDetector::SIGNAL_UNVERIFIED_CRAWLER_CLAIM))->toBeFalse();
});

it('adds the unverified claim signal when verification fails', function () {
    $report = behaviorReport(
        ['user-agent' => 'Googlebot/2.1'],
        'GET',
        ['bots' => ['mode' => 'challenge']],
    );

    expect($report->has(BehaviorDetector::SIGNAL_UNVERIFIED_CRAWLER_CLAIM))->toBeTrue();
    expect($report->totalDelta)->toBe(4);
});

it('flags a strong scanner tool user agent with the configured signal', function () {
    $report = behaviorReport(['user-agent' => 'sqlmap/1.8#stable'], config: ['behavior' => ['scanner_ua_signal' => 5]]);

    expect($report->has(BehaviorDetector::SIGNAL_SCANNER_TOOL_UA))->toBeTrue();
    expect($report->totalDelta)->toBe(5);
});

it('keeps generic clients on the weak suspicious UA signal', function () {
    $report = behaviorReport(['user-agent' => 'curl/8.4.0']);

    expect($report->has(BehaviorDetector::SIGNAL_SCANNER_TOOL_UA))->toBeFalse();
    expect($report->has(BehaviorDetector::SIGNAL_SUSPICIOUS_UA))->toBeTrue();
    expect($report->totalDelta)->toBe(2);
});

it('does not challenge normal users when bots.mode is challenge', function () {
    $engine = makeEngine(['mode' => 'enforce', 'bots' => ['mode' => 'challenge']]);
    $result = $engine->inspect(
        shieldRequest('/home', 'GET', '203.0.113.5', ['user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0']),
        new BehaviorCounters,
    );

    expect($result->allowed())->toBeTrue();
});

it('rejects an invalid bots.mode configuration', function () {
    expect(fn () => coreConfig(['bots' => ['mode' => 'ban_all']]))
        ->toThrow(InvalidConfigException::class);
});

it('flags a path rate burst on generic paths', function () {
    $cfg = coreConfig();
    $ctx = shieldRequest('/home', 'GET', '203.0.113.5', ['user-agent' => 'Mozilla/5.0 Chrome/120.0']);
    $normalized = (new Normalizer)->normalize($ctx, $cfg);

    $report = (new BehaviorDetector)->evaluate(
        $ctx,
        $normalized,
        new BehaviorCounters(uniqueUriCount: 0, notFoundCount: 0, pathRequestCount: 30),
        $cfg,
    );

    expect($report->has(BehaviorDetector::SIGNAL_PATH_RATE_BURST))->toBeTrue();
    expect($report->totalDelta)->toBe(8);
});

it('flags a sensitive path burst at a lower threshold', function () {
    $cfg = coreConfig();
    $ctx = shieldRequest('/login', 'GET', '203.0.113.5', ['user-agent' => 'Mozilla/5.0 Chrome/120.0']);
    $normalized = (new Normalizer)->normalize($ctx, $cfg);

    $report = (new BehaviorDetector)->evaluate(
        $ctx,
        $normalized,
        new BehaviorCounters(uniqueUriCount: 0, notFoundCount: 0, pathRequestCount: 8, isSensitivePath: true),
        $cfg,
    );

    expect($report->has(BehaviorDetector::SIGNAL_SENSITIVE_PATH_BURST))->toBeTrue();
    expect($report->totalDelta)->toBe(10);
});

it('does not flag path bursts below the thresholds', function () {
    $cfg = coreConfig();
    $ctx = shieldRequest('/home', 'GET', '203.0.113.5', ['user-agent' => 'Mozilla/5.0 Chrome/120.0']);
    $normalized = (new Normalizer)->normalize($ctx, $cfg);

    $report = (new BehaviorDetector)->evaluate(
        $ctx,
        $normalized,
        new BehaviorCounters(uniqueUriCount: 0, notFoundCount: 0, pathRequestCount: 29),
        $cfg,
    );

    expect($report->has(BehaviorDetector::SIGNAL_PATH_RATE_BURST))->toBeFalse();
});
