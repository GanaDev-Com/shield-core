<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Persistence;

use Ganadev\Shield\Core\Events\SecurityEvent;

interface EventRepositoryInterface
{
    public function record(SecurityEvent $event): void;

    public function pruneOlderThan(\DateTimeImmutable $cutoff): int;
}
