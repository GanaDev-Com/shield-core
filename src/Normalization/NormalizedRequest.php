<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Normalization;

final class NormalizedRequest
{
    /**
     * @param  array<int, string>  $decodedVariants  Decoded copies at each level 1..N (full URI).
     * @param  array<int, string>  $bodyDecodedVariants  Decoded copies of the body at each level 1..N.
     */
    public function __construct(
        public readonly string $normalizedUri,
        public readonly string $normalizedPath,
        public readonly string $normalizedQuery,
        public readonly array $decodedVariants,
        public readonly bool $truncated,
        public readonly string $normalizedBody = '',
        public readonly array $bodyDecodedVariants = [],
    ) {}

    public function isOversized(): bool
    {
        return $this->truncated;
    }
}
