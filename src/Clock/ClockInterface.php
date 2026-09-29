<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Clock;

interface ClockInterface
{
    public function now(): \DateTimeImmutable;
}
