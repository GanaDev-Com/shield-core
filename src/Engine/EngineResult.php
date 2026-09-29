<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Engine;

use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Decision\Verdict;
use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Rules\RuleMatch;
use Ganadev\Shield\Core\Scoring\ScoreBreakdown;

final class EngineResult
{
    /**
     * @param  list<RuleMatch>  $matches
     */
    public function __construct(
        public readonly Verdict $verdict,
        public readonly RequestContext $request,
        public readonly NormalizedRequest $normalized,
        public readonly ScoreBreakdown $score,
        public readonly array $matches,
        public readonly ?BanRecord $activeBan,
        public readonly bool $trusted,
        public readonly bool $infrastructureDegraded,
        public readonly bool $allowlisted = false,
    ) {}

    public function shouldBlock(): bool
    {
        return $this->verdict->blocked();
    }

    public function shouldChallenge(): bool
    {
        return $this->verdict->challenged();
    }

    public function allowed(): bool
    {
        return $this->verdict->decision->value === 'ALLOW';
    }
}
