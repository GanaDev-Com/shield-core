<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Scoring;

use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Detection\BehaviorReport;
use Ganadev\Shield\Core\Rules\RuleMatch;

final class RiskScorer
{
    /**
     * Weak behavior signals (+2 UA/header/referer flags) must not trigger the
     * full offense escalation multiplier. Only a signature match or a
     * challenge-level behavior signal counts as a "violation" for escalation.
     */
    public const MIN_ESCALATION_BEHAVIOR_SCORE = 10;

    /**
     * @param  list<RuleMatch>  $ruleMatches
     * @param  int  $challengePenalty  Reserved for failed-challenge scoring. The
     *                                 engine always passes 0 today; no caller feeds
     *                                 a non-zero value yet.
     */
    public function score(
        array $ruleMatches,
        BehaviorReport $behavior,
        int $offenseCount,
        int $challengePenalty,
        ShieldConfig $config,
    ): ScoreBreakdown {
        $signatureScore = 0;
        $matchedRuleIds = [];
        $hasCritical = false;

        foreach ($ruleMatches as $match) {
            $signatureScore += $match->score();
            $matchedRuleIds[] = $match->id();
            if ($match->isCritical()) {
                $hasCritical = true;
            }
        }

        $hasViolation = $signatureScore > 0
            || $behavior->totalDelta >= self::MIN_ESCALATION_BEHAVIOR_SCORE;

        $escalationScore = 0;
        if ($hasViolation && $offenseCount > 0) {
            $escalationScore = min($offenseCount, 5) * $config->escalationStep;
        }

        $total = $signatureScore + $behavior->totalDelta + $escalationScore + $challengePenalty;

        return new ScoreBreakdown(
            signatureScore: $signatureScore,
            behaviorScore: $behavior->totalDelta,
            escalationScore: $escalationScore,
            challengePenalty: $challengePenalty,
            total: $total,
            matchedRuleIds: $matchedRuleIds,
            behaviorSignals: $behavior->signals,
            hasCritical: $hasCritical,
        );
    }
}
