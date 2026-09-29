<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Rules\Matchers\RuleMatcherRegistry;
use Ganadev\Shield\Core\Rules\Rule;

function advancedMatch(string $matcher, string $value, string $uri): bool
{
    $rule = Rule::fromArray([
        'id' => 'test.'.$matcher,
        'category' => 'test',
        'matcher' => $matcher,
        'value' => $value,
        'severity' => 'high',
        'score' => 20,
    ]);

    $request = (new Normalizer)->normalize(shieldRequest($uri), coreConfig());

    return (new RuleMatcherRegistry)->matches($rule, $request);
}

it('detects /env.* variants without the leading dot', function () {
    expect(advancedMatch('prefix', '/env.', '/env.php'))->toBeTrue();
    expect(advancedMatch('prefix', '/env.', '/env.js'))->toBeTrue();
});

it('detects wp-config variants that are not php', function () {
    expect(advancedMatch('contains', 'wp-config', '/wp-config.old'))->toBeTrue();
    expect(advancedMatch('contains', 'wp-config', '/wp-config.txt'))->toBeTrue();
});

it('detects joomla configuration.php', function () {
    expect(advancedMatch('contains', 'configuration.php', '/configuration.php'))->toBeTrue();
});

it('detects xmlrpc probing', function () {
    expect(advancedMatch('prefix', '/xmlrpc.php', '/xmlrpc.php'))->toBeTrue();
});

it('detects php execution in static directories', function () {
    expect(advancedMatch('regex', '^/(.*/)?(images|media|uploads|cache|cgi-bin|blogs|logs|class|wp-admin/(js|css|images|includes))/[^/]*\.php$', '/images/cache.php'))->toBeTrue();
    expect(advancedMatch('regex', '^/(.*/)?(images|media|uploads|cache|cgi-bin|blogs|logs|class|wp-admin/(js|css|images|includes))/[^/]*\.php$', '/admin/images/config.php'))->toBeTrue();
    expect(advancedMatch('regex', '^/(.*/)?(images|media|uploads|cache|cgi-bin|blogs|logs|class|wp-admin/(js|css|images|includes))/[^/]*\.php$', '/wp-admin/js/index.php'))->toBeTrue();
});

it('detects php anywhere under uploads', function () {
    expect(advancedMatch('regex', '^/.*/(wp-content/)?uploads/.*\.php$', '/wp-content/uploads/2026/222.php'))->toBeTrue();
});

it('detects php in hidden dot-directories', function () {
    expect(advancedMatch('regex', '^/\.[^/]+/.*\.php$', '/.tmb/worksec.php'))->toBeTrue();
    expect(advancedMatch('regex', '^/\.[^/]+/.*\.php$', '/.freepbx-known/config.php'))->toBeTrue();
});

it('detects thinkphp and call_user_func RCE', function () {
    expect(advancedMatch('decoded_contains', 'call_user_func', '/index.php?function=call_user_func_array&vars[0]=system'))->toBeTrue();
    expect(advancedMatch('decoded_contains', 'think\\app', '/index.php?s=index/\\think\\app/invokefunction'))->toBeTrue();
    expect(advancedMatch('decoded_contains', 'invokefunction', '/index.php?s=index/\\think\\app/invokefunction'))->toBeTrue();
});

it('detects php ini directive abuse', function () {
    expect(advancedMatch('decoded_contains', 'allow_url_include', '/cgi-bin/php?allow_url_include%3d1'))->toBeTrue();
    expect(advancedMatch('decoded_contains', 'disable_functions', '/?disable_functions=system'))->toBeTrue();
});

it('detects system call RCE payloads', function () {
    expect(advancedMatch('decoded_contains', 'shell_exec', '/?cmd=shell_exec'))->toBeTrue();
    expect(advancedMatch('decoded_contains', 'passthru', '/?cmd=passthru'))->toBeTrue();
    expect(advancedMatch('decoded_contains', 'proc_open', '/?cmd=proc_open'))->toBeTrue();
});

it('detects backslash traversal in decoded variants', function () {
    expect(advancedMatch('decoded_contains', '..\\', '/%2e%2e%5c%2e%2e%5cetc/passwd'))->toBeTrue();
});

it('detects encoded signature forms via decoding-aware matchers', function () {
    expect(advancedMatch('contains', '/.git', '/%2e%2e/.git/config'))->toBeTrue();
    expect(advancedMatch('regex', '\.php\.(bak|old|save|swp|tmp|orig|copy|zip|tar|gz)$', '/class%2ephp%2eorig'))->toBeTrue();
    expect(advancedMatch('contains', '/wp-content/debug.log', '/wp-content/debug%2elog'))->toBeTrue();
});

it('keeps query_contains scoped to the query string only', function () {
    expect(advancedMatch('query_contains', 'litespeed_debug', '/?litespeed_debug=1'))->toBeTrue();
    expect(advancedMatch('query_contains', 'litespeed_debug', '/litespeed_debug'))->toBeFalse();
});
