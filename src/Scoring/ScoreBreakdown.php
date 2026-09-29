<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Scoring;

final class ScoreBreakdown
{
    /**
     * @param  list<string>  $matchedRuleIds
     * @param  list<string>  $behaviorSignals
     */
    public function __construct(
        public readonly int $signatureScore,
        public readonly int $behaviorScore,
        public readonly int $escalationScore,
        public readonly int $challengePenalty,
        public readonly int $total,
        public readonly array $matchedRuleIds,
        public readonly array $behaviorSignals,
        public readonly bool $hasCritical,
    ) {}
}
