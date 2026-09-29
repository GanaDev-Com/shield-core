<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Detection;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\Matchers\RuleMatcherRegistry;
use Ganadev\Shield\Core\Rules\RuleMatch;
use Ganadev\Shield\Core\Rules\RuleRepository;

final class ThreatSignatureEngine
{
    public function __construct(
        private readonly RuleRepository $rules,
        private readonly RuleMatcherRegistry $matchers = new RuleMatcherRegistry,
    ) {}

    /**
     * @return list<RuleMatch>
     */
    public function evaluate(NormalizedRequest $request): array
    {
        $matches = [];
        foreach ($this->rules->active() as $rule) {
            if ($this->matchers->matches($rule, $request)) {
                $matches[] = new RuleMatch($rule);
            }
        }

        return $matches;
    }

    /**
     * @param  list<RuleMatch>  $matches
     */
    public function hasCriticalMatch(array $matches): bool
    {
        foreach ($matches as $match) {
            if ($match->isCritical()) {
                return true;
            }
        }

        return false;
    }
}
