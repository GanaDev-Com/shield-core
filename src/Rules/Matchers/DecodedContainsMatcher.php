<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\MatcherType;
use Ganadev\Shield\Core\Rules\Rule;

final class DecodedContainsMatcher implements RuleMatcherInterface
{
    public function supports(Rule $rule): bool
    {
        return $rule->matcher === MatcherType::DecodedContains;
    }

    public function matches(Rule $rule, NormalizedRequest $request): bool
    {
        if (str_contains($request->normalizedUri, $rule->value)
            || str_contains($request->normalizedPath, $rule->value)) {
            return true;
        }

        foreach ($request->decodedVariants as $variant) {
            if (str_contains($variant, $rule->value)) {
                return true;
            }
        }

        return false;
    }
}
