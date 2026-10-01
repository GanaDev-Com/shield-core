<?php

declare(strict_types=1);

use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Events\SecurityEvent;
use Ganadev\Shield\Core\Privacy\UriMasker;

/**
 * @param  list<string>  $params
 */
function maskUri(string $uri, array $params = ['token', 'password', 'key', 'secret', 'code', 'auth']): string
{
    return (new UriMasker)->mask($uri, $params);
}

it('masks configured sensitive query parameters', function () {
    expect(maskUri('/?token=abc123&page=2'))->toBe('/?token=***&page=2');
    expect(maskUri('/?password=secret&x=1'))->toBe('/?password=***&x=1');
});

it('masks common suffix variants like access_token', function () {
    expect(maskUri('/?access_token=xyz'))->toBe('/?access_token=***');
    expect(maskUri('/?client_secret=xyz'))->toBe('/?client_secret=***');
});

it('masks sensitive keys that were percent-encoded in the query', function () {
    expect(maskUri('/?access%5Ftoken=xyz'))->toBe('/?access%5Ftoken=***');
    expect(maskUri('/?api%5Fkey=xyz'))->toBe('/?api%5Fkey=***');
    expect(maskUri('/?%74oken=xyz'))->toBe('/?%74oken=***');
    expect(maskUri('/?ACCESS_TOKEN=xyz'))->toBe('/?ACCESS_TOKEN=***');
});

it('leaves non-sensitive parameters untouched', function () {
    expect(maskUri('/home?page=2&q=laravel+security'))->toBe('/home?page=2&q=laravel+security');
});

it('returns uris without a query unchanged', function () {
    expect(maskUri('/.env'))->toBe('/.env');
});

it('handles duplicate and empty pairs gracefully', function () {
    expect(maskUri('/?token=a&token=b&&key=c'))->toBe('/?token=***&token=***&key=***');
});

it('masks uris in stored security events', function () {
    $events = makeEvents();
    $engine = makeEngine(['mode' => 'enforce'], ['events' => $events]);

    $engine->inspect(shieldRequest('/?token=supersecret&x=1'), new BehaviorCounters);

    $last = $events->last();
    expect($last)->not->toBeNull();
    assert($last instanceof SecurityEvent);
    expect($last->rawUri)->toBe('/?token=***&x=1');
    expect($last->rawUri)->not->toContain('supersecret');
});
