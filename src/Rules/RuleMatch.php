<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules;

final class RuleMatch
{
    public function __construct(
        public readonly Rule $rule,
    ) {}

    public function id(): string
    {
        return $this->rule->id;
    }

    public function score(): int
    {
        return $this->rule->score;
    }

    public function isCritical(): bool
    {
        return $this->rule->severity->isCritical() || $this->rule->immediateBan;
    }
}
