<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Reputation;

/**
 * Risk decay: a reputation score/offense count decays after a quiet period so
 * a previously flagged IP is not punished forever (spec section 9).
 */
final class RiskDecay
{
    /**
     * @return int decayed offense count (never below zero)
     */
    public function decayOffenseCount(
        int $offenseCount,
        \DateTimeImmutable $lastSeen,
        \DateTimeImmutable $now,
        int $decayWindowSeconds = 86400,
        int $decayPerWindow = 1,
    ): int {
        if ($offenseCount <= 0) {
            return 0;
        }

        $quietSeconds = $now->getTimestamp() - $lastSeen->getTimestamp();
        if ($quietSeconds <= 0) {
            return $offenseCount;
        }

        $windows = intdiv($quietSeconds, max(1, $decayWindowSeconds));

        return max(0, $offenseCount - ($windows * $decayPerWindow));
    }

    /**
     * @return int decayed risk score (never below zero)
     */
    public function decayScore(
        int $score,
        \DateTimeImmutable $lastSeen,
        \DateTimeImmutable $now,
        int $decayWindowSeconds = 3600,
        int $decayPerWindow = 10,
    ): int {
        if ($score <= 0) {
            return 0;
        }

        $quietSeconds = $now->getTimestamp() - $lastSeen->getTimestamp();
        if ($quietSeconds <= 0) {
            return $score;
        }

        $windows = intdiv($quietSeconds, max(1, $decayWindowSeconds));

        return max(0, $score - ($windows * $decayPerWindow));
    }
}
