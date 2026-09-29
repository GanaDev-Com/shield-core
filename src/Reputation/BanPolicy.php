<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Reputation;

/**
 * Pure ban policy: offense escalation and manual review thresholds
 * (spec section 9).
 */
final class BanPolicy
{
    public const MANUAL_REVIEW_THRESHOLD = 5;

    /**
     * @param  list<int>  $durationsMinutes
     */
    public function durationFor(int $offenseCount, array $durationsMinutes): int
    {
        $index = max(0, $offenseCount - 1);

        return $durationsMinutes[min($index, count($durationsMinutes) - 1)];
    }

    public function requiresManualReview(int $offenseCount): bool
    {
        return $offenseCount >= self::MANUAL_REVIEW_THRESHOLD;
    }

    /**
     * Next offense count after an existing ban record. Offense history is never
     * deleted when a ban is released, so reoffending escalates.
     */
    public function nextOffenseCount(?BanRecord $previous): int
    {
        if ($previous === null) {
            return 1;
        }

        return $previous->offenseCount + 1;
    }
}
