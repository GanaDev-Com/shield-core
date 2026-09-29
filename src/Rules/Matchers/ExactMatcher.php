<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\MatcherType;
use Ganadev\Shield\Core\Rules\Rule;

final class ExactMatcher implements RuleMatcherInterface
{
    public function supports(Rule $rule): bool
    {
        return $rule->matcher === MatcherType::Exact;
    }

    public function matches(Rule $rule, NormalizedRequest $request): bool
    {
        if ($request->normalizedPath === $rule->value || $request->normalizedUri === $rule->value) {
            return true;
        }

        foreach ($request->decodedVariants as $variant) {
            if ($variant === $rule->value) {
                return true;
            }
        }

        return false;
    }
}
