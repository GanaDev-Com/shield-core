<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Clock;

final class SystemClock implements ClockInterface
{
    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable;
    }
}
