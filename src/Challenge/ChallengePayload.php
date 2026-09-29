<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Challenge;

final class ChallengePayload
{
    /**
     * @param  array<string, mixed>  $data
     */
    public function __construct(
        public readonly string $driver,
        public readonly string $siteKey = '',
        public readonly string $action = 'shield_challenge',
        public readonly array $data = [],
    ) {}
}
