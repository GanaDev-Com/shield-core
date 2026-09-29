<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Tests\Support;

use Ganadev\Shield\Core\Events\SecurityEvent;
use Ganadev\Shield\Core\Persistence\EventRepositoryInterface;

final class InMemoryEventRepository implements EventRepositoryInterface
{
    /** @var list<SecurityEvent> */
    public array $events = [];

    public function record(SecurityEvent $event): void
    {
        $this->events[] = $event;
    }

    public function pruneOlderThan(\DateTimeImmutable $cutoff): int
    {
        $before = count($this->events);
        $this->events = array_values(array_filter(
            $this->events,
            static fn (SecurityEvent $event): bool => $event->createdAt >= $cutoff,
        ));

        return $before - count($this->events);
    }

    public function last(): ?SecurityEvent
    {
        return $this->events === [] ? null : $this->events[count($this->events) - 1];
    }
}
