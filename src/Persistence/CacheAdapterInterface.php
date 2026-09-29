<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Persistence;

interface CacheAdapterInterface
{
    public function get(string $key): mixed;

    public function set(string $key, mixed $value, int $ttlSeconds): bool;

    public function delete(string $key): bool;

    public function has(string $key): bool;

    /**
     * Atomically increments a counter when the backend supports it and returns
     * the new value. Falls back to a read-modify-write otherwise.
     */
    public function increment(string $key, int $ttlSeconds): int;
}
