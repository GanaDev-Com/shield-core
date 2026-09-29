<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Decision;

use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Scoring\ScoreBreakdown;

final class DecisionInput
{
    public function __construct(
        public readonly ScoreBreakdown $score,
        public readonly ?BanRecord $activeBan,
        public readonly bool $trusted,
        public readonly int $thresholdChallenge,
        public readonly int $thresholdBan,
        public readonly int $thresholdStrongBan,
        public readonly string $mode,
    ) {}
}
