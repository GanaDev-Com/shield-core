<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Tests\Support;

use Ganadev\Shield\Core\Clock\ClockInterface;

final class FakeClock implements ClockInterface
{
    public function __construct(
        private \DateTimeImmutable $now,
    ) {}

    public function now(): \DateTimeImmutable
    {
        return $this->now;
    }

    public function advance(string $modifier): void
    {
        $this->now = $this->now->modify($modifier);
    }
}
