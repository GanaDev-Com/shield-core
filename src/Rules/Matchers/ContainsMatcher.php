<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\MatcherType;
use Ganadev\Shield\Core\Rules\Rule;

final class ContainsMatcher implements RuleMatcherInterface
{
    public function supports(Rule $rule): bool
    {
        return $rule->matcher === MatcherType::Contains;
    }

    public function matches(Rule $rule, NormalizedRequest $request): bool
    {
        foreach ([$request->normalizedUri, $request->normalizedPath] as $haystack) {
            if (str_contains($haystack, $rule->value)) {
                return true;
            }
        }

        foreach ($request->decodedVariants as $variant) {
            if (str_contains($variant, $rule->value)) {
                return true;
            }
        }

        return false;
    }
}
