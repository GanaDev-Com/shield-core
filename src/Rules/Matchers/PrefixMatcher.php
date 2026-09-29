<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\MatcherType;
use Ganadev\Shield\Core\Rules\Rule;

final class PrefixMatcher implements RuleMatcherInterface
{
    public function supports(Rule $rule): bool
    {
        return $rule->matcher === MatcherType::Prefix;
    }

    public function matches(Rule $rule, NormalizedRequest $request): bool
    {
        if (str_starts_with($request->normalizedPath, $rule->value)
            || str_starts_with($request->normalizedUri, $rule->value)) {
            return true;
        }

        foreach ($request->decodedVariants as $variant) {
            if (str_starts_with($variant, $rule->value)) {
                return true;
            }
        }

        return false;
    }
}
