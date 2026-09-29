<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Detection;

final class BehaviorReport
{
    /**
     * @param  list<string>  $signals
     */
    public function __construct(
        public readonly int $totalDelta,
        public readonly array $signals,
        public readonly ?string $knownCrawler = null,
    ) {}

    public function has(string $signal): bool
    {
        return in_array($signal, $this->signals, true);
    }
}
