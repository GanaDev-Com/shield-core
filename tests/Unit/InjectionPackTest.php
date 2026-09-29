<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\RuleRepository;

/**
 * @param  array<string, mixed>  $config
 * @param  array<string, mixed>  $deps
 */
function injectionEngine(array $config = [], array $deps = []): ShieldEngine
{
    return makeEngine(array_replace(['mode' => 'enforce'], $config), $deps);
}

function bodyRequest(string $body, string $method = 'POST', string $uri = '/api/login'): RequestContext
{
    return shieldRequest($uri, $method, '203.0.113.30', ['user-agent' => 'Mozilla/5.0 Chrome/120.0'], $body);
}

it('blocks SQL injection in the request body', function () {
    $engine = injectionEngine();

    $result = $engine->inspect(
        bodyRequest("username=admin' OR '1'='1' UNION SELECT password FROM users--"),
        new BehaviorCounters,
    );

    expect($result->shouldBlock())->toBeTrue();
    expect($result->verdict->ruleId)->toBe('payload.sqli.union');
});

it('blocks SQL injection via the query string', function () {
    $engine = injectionEngine();

    $result = $engine->inspect(
        shieldRequest('/products?id=1 UNION SELECT username,password FROM users', 'GET'),
        new BehaviorCounters,
    );

    expect($result->shouldBlock())->toBeTrue();
    expect($result->verdict->ruleId)->toBe('payload.sqli.union.query');
});

it('immediately bans php://input in the request body', function () {
    $engine = injectionEngine();

    $result = $engine->inspect(
        bodyRequest('data=php://input&cmd=id'),
        new BehaviorCounters,
    );

    expect($result->shouldBlock())->toBeTrue();
});

it('detects time based SQL injection payloads', function () {
    $engine = injectionEngine();

    $result = $engine->inspect(
        bodyRequest('id=1 AND sleep(5)'),
        new BehaviorCounters,
    );

    expect($result->shouldBlock())->toBeTrue();
});

it('challenges script tags in the request body (challenge band)', function () {
    $engine = injectionEngine();

    $result = $engine->inspect(
        bodyRequest('comment=<script>alert(1)</script>'),
        new BehaviorCounters,
    );

    expect($result->shouldChallenge())->toBeTrue();
    expect($result->verdict->ruleId)->toBe('payload.xss.script');
});

it('detects encoded payloads in the request body', function () {
    $engine = injectionEngine();

    $result = $engine->inspect(
        bodyRequest('q=UNION%20SELECT%20password%20FROM%20users'),
        new BehaviorCounters,
    );

    expect($result->shouldBlock())->toBeTrue();
});

it('does not flag benign body text', function () {
    $engine = injectionEngine();

    $result = $engine->inspect(
        bodyRequest('name=John&message=system upgrade completed successfully&role=executive'),
        new BehaviorCounters,
    );

    expect($result->allowed())->toBeTrue();
});

it('does not inspect the body when the injection pack is disabled', function () {
    $engine = injectionEngine(['rules' => ['packs' => ['injection' => false]]]);

    $result = $engine->inspect(
        bodyRequest("username=admin' UNION SELECT password FROM users--"),
        new BehaviorCounters,
    );

    expect($result->allowed())->toBeTrue();
});

it('normalizes and decodes the request body', function () {
    $config = coreConfig();
    $context = bodyRequest('Q=UNION%20SELECT');
    $normalized = (new Normalizer)->normalize($context, $config);

    expect($normalized->normalizedBody)->toBe('q=union%20select');
    expect($normalized->bodyDecodedVariants[0])->toBe('Q=UNION SELECT');
});

it('skips body decoding when body inspection is disabled', function () {
    $config = coreConfig(['inspection' => ['body' => ['enabled' => false]]]);
    $context = bodyRequest('q=UNION%20SELECT');
    $normalized = (new Normalizer)->normalize($context, $config);

    expect($normalized->normalizedBody)->toBe('q=union%20select');
    expect($normalized->bodyDecodedVariants)->toBe([]);
});

it('injection rules do not match when there is no body', function () {
    $config = coreConfig();
    $rules = RuleRepository::fromArray(array_merge(
        DefaultRules::definitions(),
        DefaultRules::injectionDefinitions(),
    ));

    $context = shieldRequest('/home', 'GET');
    $normalized = (new Normalizer)->normalize($context, $config);

    $matches = (new ThreatSignatureEngine($rules))->evaluate($normalized);

    $bodyMatches = array_values(array_filter(
        $matches,
        fn ($m) => in_array($m->rule->matcher->value, ['body_contains', 'body_regex'], true),
    ));

    expect($bodyMatches)->toBeEmpty();
});

it('body rules validate as ReDoS safe', function () {
    $rules = RuleRepository::fromArray(DefaultRules::injectionDefinitions());

    expect($rules->count())->toBe(14);
});
