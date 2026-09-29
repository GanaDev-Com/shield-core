<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Tests\Support;

use Ganadev\Shield\Core\Persistence\CacheAdapterInterface;

final class ArrayCache implements CacheAdapterInterface
{
    /** @var array<string, array{value: mixed, expires_at: ?int}> */
    private array $store = [];

    private int $now;

    public function __construct(int $now = 0)
    {
        $this->now = $now;
    }

    public function get(string $key): mixed
    {
        if (! isset($this->store[$key])) {
            return null;
        }

        $entry = $this->store[$key];
        if ($entry['expires_at'] !== null && $entry['expires_at'] < $this->now) {
            unset($this->store[$key]);

            return null;
        }

        return $entry['value'];
    }

    public function set(string $key, mixed $value, int $ttlSeconds): bool
    {
        $this->store[$key] = [
            'value' => $value,
            'expires_at' => $ttlSeconds > 0 ? $this->now + $ttlSeconds : null,
        ];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->store[$key]);

        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    public function increment(string $key, int $ttlSeconds): int
    {
        $current = (int) $this->get($key);
        $next = $current + 1;
        $this->set($key, $next, $ttlSeconds);

        return $next;
    }

    public function advance(int $seconds): void
    {
        $this->now += $seconds;
    }
}
