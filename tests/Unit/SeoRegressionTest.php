<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Core\Tests\Support\FakeCrawlerVerifier;

/**
 * @return array{description: string, entries: list<array<string, mixed>>}
 */
function seoCorpus(): array
{
    return json_decode(
        (string) file_get_contents(__DIR__.'/../../fixtures/seo-corpus.json'),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );
}

it('never blocks or challenges SEO-critical paths from a verified crawler', function () {
    $engine = makeEngine([
        'mode' => 'enforce',
        'bots' => ['mode' => 'challenge'],
    ], ['crawler' => new FakeCrawlerVerifier(['203.0.113.5' => 'googlebot'])]);

    foreach (seoCorpus()['entries'] as $entry) {
        $uri = (string) $entry['uri'];
        $ctx = shieldRequest(
            $uri,
            (string) ($entry['method'] ?? 'GET'),
            '203.0.113.5',
            ['user-agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
        );

        $result = $engine->inspect($ctx, new BehaviorCounters(uniqueUriCount: 60, notFoundCount: 40));

        expect($result->allowed())->toBeTrue($uri.' must be allowed for a verified crawler');
    }
});

it('no default or injection rule matches any SEO-critical path', function () {
    $rules = RuleRepository::fromArray(array_merge(
        DefaultRules::definitions(),
        DefaultRules::injectionDefinitions(),
    ));
    $config = coreConfig();
    $engine = new ThreatSignatureEngine($rules);
    $normalizer = new Normalizer;

    foreach (seoCorpus()['entries'] as $entry) {
        $uri = (string) $entry['uri'];
        $ctx = shieldRequest($uri, 'GET');
        $matches = $engine->evaluate($normalizer->normalize($ctx, $config));

        expect($matches)->toBeEmpty($uri.' must not match any rule');
    }
});

it('never challenges SEO-critical paths from a verified crawler under burst counters', function () {
    $engine = makeEngine([
        'mode' => 'enforce',
        'bots' => ['mode' => 'challenge'],
    ], ['crawler' => new FakeCrawlerVerifier(['203.0.113.5' => 'googlebot'])]);

    $uri = '/sitemap.xml';
    $ctx = shieldRequest($uri, 'GET', '203.0.113.5', ['user-agent' => 'Googlebot/2.1']);

    $result = $engine->inspect(
        $ctx,
        new BehaviorCounters(uniqueUriCount: 80, notFoundCount: 60, pathRequestCount: 500),
    );

    expect($result->allowed())->toBeTrue();
    expect($result->shouldChallenge())->toBeFalse();
});
