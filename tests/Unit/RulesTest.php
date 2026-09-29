<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Exceptions\InvalidConfigException;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\Matchers\RuleMatcherRegistry;
use Ganadev\Shield\Core\Rules\MatcherType;
use Ganadev\Shield\Core\Rules\Rule;
use Ganadev\Shield\Core\Rules\RuleMatch;
use Ganadev\Shield\Core\Rules\RuleSeverity;

function matchAgainst(Rule $rule, string $uri, int $depth = 2): bool
{
    $request = (new Normalizer)->normalize(shieldRequest($uri), coreConfig(['decode_depth' => $depth]));

    return (new RuleMatcherRegistry)->matches($rule, $request);
}

function rule(string $matcher, string $value): Rule
{
    return Rule::fromArray([
        'id' => 'test.rule',
        'category' => 'test',
        'matcher' => $matcher,
        'value' => $value,
        'severity' => 'high',
        'score' => 20,
    ]);
}

it('exact matcher requires an identical path', function () {
    $rule = rule('exact', '/.env');

    expect(matchAgainst($rule, '/.env'))->toBeTrue();
    expect(matchAgainst($rule, '/.env.bak'))->toBeFalse();
});

it('prefix matcher matches the start of a path', function () {
    $rule = rule('prefix', '/admin');

    expect(matchAgainst($rule, '/admin/dashboard'))->toBeTrue();
    expect(matchAgainst($rule, '/xadmin'))->toBeFalse();
});

it('contains matcher finds substrings', function () {
    $rule = rule('contains', 'wp-config.php');

    expect(matchAgainst($rule, '/wp-config.php'))->toBeTrue();
    expect(matchAgainst($rule, '/backup/wp-config.php.save'))->toBeTrue();
});

it('query_contains matches only the query string', function () {
    $rule = rule('query_contains', 'php://input');

    expect(matchAgainst($rule, '/?file=php://input'))->toBeTrue();
    expect(matchAgainst($rule, '/php://input'))->toBeFalse();
});

it('decoded_contains catches encoded traversal variants', function () {
    $rule = rule('decoded_contains', '/proc/self/environ');

    expect(matchAgainst($rule, '/%2e%2e%2fproc%2fself%2fenviron'))->toBeTrue();
    expect(matchAgainst($rule, '/%252e%252e/proc/self/environ'))->toBeTrue();
    expect(matchAgainst($rule, '/proc/self/environ'))->toBeTrue();
});

it('regex matcher respects bounded patterns', function () {
    $rule = rule('regex', 'wp-config\.php\.(bak|old|save|swp|\~)$');

    expect(matchAgainst($rule, '/x/wp-config.php.bak'))->toBeTrue();
    expect(matchAgainst($rule, '/x/wp-config.php'))->toBeFalse();
});

it('rejects catastrophic regex patterns on construction', function () {
    expect(fn () => rule('regex', '(a+)+$'))->toThrow(InvalidConfigException::class);
});

it('default rules cover the documented critical categories', function () {
    $repo = DefaultRules::repository();
    $ids = array_map(fn (Rule $r) => $r->id, $repo->all());

    expect($ids)->toContain('sensitive.env')
        ->toContain('sensitive.git')
        ->toContain('sensitive.aws')
        ->toContain('traversal.proc')
        ->toContain('rce.phpinput')
        ->toContain('rce.prepend');
});

it('repository can disable a rule without editing vendor code', function () {
    $repo = DefaultRules::repository()->withDisabled('sensitive.env');
    $rule = $repo->get('sensitive.env');

    expect($rule)->not->toBeNull();
    assert($rule instanceof Rule);
    expect($rule->enabled)->toBeFalse();
    expect(count($repo->active()))->toBe(count($repo->all()) - 1);
});

it('critical rule detection works through signature engine', function () {
    $engine = new ThreatSignatureEngine(DefaultRules::repository());
    $request = (new Normalizer)->normalize(shieldRequest('/.env'), coreConfig());

    $matches = $engine->evaluate($request);

    expect($matches)->not->toBeEmpty();
    expect($engine->hasCriticalMatch($matches))->toBeTrue();
});

it('matches expose stable rule identity and severity', function () {
    $match = new RuleMatch(rule('contains', 'x'));

    expect($match->id())->toBe('test.rule');
    expect($match->score())->toBe(20);
    expect($match->isCritical())->toBeFalse();
});

it('matcher type enum covers all spec matchers', function () {
    expect(MatcherType::values())->toMatchArray([
        'exact', 'prefix', 'contains', 'regex', 'query_contains', 'decoded_contains',
    ]);
});

it('supports per-rule severity score defaults', function () {
    $critical = Rule::fromArray(['id' => 'c', 'matcher' => 'contains', 'value' => 'x', 'severity' => 'critical']);
    $low = Rule::fromArray(['id' => 'l', 'matcher' => 'contains', 'value' => 'y', 'severity' => 'low']);

    expect($critical->score)->toBe(30);
    expect($low->score)->toBe(4);
    expect(RuleSeverity::Critical->isCritical())->toBeTrue();
});

it('rejects empty rule ids and negative scores', function () {
    expect(fn () => Rule::fromArray(['id' => '', 'matcher' => 'contains', 'value' => 'x', 'severity' => 'high']))
        ->toThrow(InvalidConfigException::class);

    expect(fn () => Rule::fromArray(['id' => 'x', 'matcher' => 'contains', 'value' => 'y', 'severity' => 'high', 'score' => -5]))
        ->toThrow(InvalidConfigException::class);
});
