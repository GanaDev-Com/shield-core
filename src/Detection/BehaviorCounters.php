<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Detection;

final class BehaviorCounters
{
    public function __construct(
        public readonly int $uniqueUriCount = 0,
        public readonly int $notFoundCount = 0,
        public readonly int $pathRequestCount = 0,
        public readonly bool $isSensitivePath = false,
    ) {}
}
