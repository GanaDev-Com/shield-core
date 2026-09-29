<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Decision;

final class Verdict
{
    /**
     * @param  list<string>  $matchedRuleIds
     * @param  list<string>  $behaviorSignals
     */
    public function __construct(
        public readonly Decision $intended,
        public readonly Decision $decision,
        public readonly string $reason,
        public readonly int $score,
        public readonly array $matchedRuleIds = [],
        public readonly array $behaviorSignals = [],
        public readonly ?string $ruleId = null,
    ) {}

    public function blocked(): bool
    {
        return $this->decision->isBlocking();
    }

    public function challenged(): bool
    {
        return $this->decision === Decision::Challenge;
    }

    public function downgraded(): bool
    {
        return $this->decision !== $this->intended;
    }
}
