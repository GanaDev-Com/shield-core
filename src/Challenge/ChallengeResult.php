<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Challenge;

final class ChallengeResult
{
    public function __construct(
        public readonly bool $passed,
        public readonly string $provider,
        public readonly string $reason = '',
        public readonly ?string $challengeToken = null,
    ) {}

    public static function success(string $provider): self
    {
        return new self(true, $provider, 'verified');
    }

    public static function failure(string $provider, string $reason): self
    {
        return new self(false, $provider, $reason);
    }
}
