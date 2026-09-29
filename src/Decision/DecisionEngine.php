<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Decision;

use Ganadev\Shield\Core\Config\ShieldConfig;

/**
 * Deterministic decision engine. The same input always yields the same verdict.
 *
 * Priority ordering:
 *  1. Critical signature -> always BLOCK_REQUEST (never bypassed by trusted cookie).
 *  2. Score thresholds -> TEMP_BAN / CHALLENGE / OBSERVE / ALLOW.
 *  3. Active ban on a normal route -> CHALLENGE unless a valid trusted cookie exists.
 *  4. Trusted cookie bypasses CHALLENGE only, never a ban/block decision.
 */
final class DecisionEngine
{
    public const OBSERVE_FLOOR = 5;

    public function decide(DecisionInput $input): Verdict
    {
        $intended = $this->intendedDecision($input);

        $intended = $this->applyActiveBan($input, $intended);
        $intended = $this->applyTrustedCookie($input, $intended);

        $final = $this->applyMode($input->mode, $intended, $input->score->hasCritical);

        $reason = $this->reasonFor($input, $intended, $final);

        return new Verdict(
            intended: $intended,
            decision: $final,
            reason: $reason,
            score: $input->score->total,
            matchedRuleIds: $input->score->matchedRuleIds,
            behaviorSignals: $input->score->behaviorSignals,
            ruleId: $input->score->matchedRuleIds[0] ?? null,
        );
    }

    private function intendedDecision(DecisionInput $input): Decision
    {
        if ($input->score->hasCritical) {
            return Decision::BlockRequest;
        }

        if ($input->score->total >= $input->thresholdStrongBan) {
            return Decision::TempBan;
        }

        if ($input->score->total >= $input->thresholdBan) {
            return Decision::TempBan;
        }

        if ($input->score->total >= $input->thresholdChallenge) {
            return Decision::Challenge;
        }

        if ($input->score->total >= self::OBSERVE_FLOOR) {
            return Decision::Observe;
        }

        return Decision::Allowed;
    }

    private function applyActiveBan(DecisionInput $input, Decision $intended): Decision
    {
        if ($input->score->hasCritical || $input->activeBan === null) {
            return $intended;
        }

        if ($input->trusted && ($intended === Decision::Allowed || $intended === Decision::Observe)) {
            return Decision::Allowed;
        }

        if ($intended === Decision::Allowed || $intended === Decision::Observe) {
            return Decision::Challenge;
        }

        return $intended;
    }

    private function applyTrustedCookie(DecisionInput $input, Decision $intended): Decision
    {
        if (! $input->trusted) {
            return $intended;
        }

        if ($intended === Decision::Challenge && $input->score->total < $input->thresholdBan) {
            return Decision::Allowed;
        }

        return $intended;
    }

    private function applyMode(string $mode, Decision $intended, bool $critical): Decision
    {
        return match ($mode) {
            ShieldConfig::MODE_OBSERVE => Decision::Observe,
            ShieldConfig::MODE_CHALLENGE => $critical
                ? Decision::BlockRequest
                : ($intended === Decision::TempBan ? Decision::Challenge : $intended),
            default => $intended,
        };
    }

    private function reasonFor(DecisionInput $input, Decision $intended, Decision $final): string
    {
        if ($final === Decision::Observe && $intended->isTerminal()) {
            return 'observe_mode: would_have_been_'.$intended->value;
        }

        if ($input->score->hasCritical) {
            return 'critical_signature_'.($input->score->matchedRuleIds[0] ?? 'critical');
        }

        if ($final === Decision::Challenge) {
            if ($input->activeBan !== null) {
                return 'active_ban_challenge';
            }

            return 'score_challenge';
        }

        if ($final === Decision::TempBan) {
            return 'score_ban';
        }

        if ($final === Decision::Allowed && $input->trusted) {
            return 'trusted_cookie';
        }

        if ($final === Decision::BlockRequest) {
            return 'block_request';
        }

        return 'allowed';
    }
}
