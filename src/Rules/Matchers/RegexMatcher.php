<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\MatcherType;
use Ganadev\Shield\Core\Rules\Rule;

final class RegexMatcher implements RuleMatcherInterface
{
    public function supports(Rule $rule): bool
    {
        return $rule->matcher === MatcherType::Regex;
    }

    public function matches(Rule $rule, NormalizedRequest $request): bool
    {
        $pattern = '~'.$rule->value.'~i';

        if (preg_match($pattern, $request->normalizedUri) === 1
            || preg_match($pattern, $request->normalizedPath) === 1) {
            return true;
        }

        foreach ($request->decodedVariants as $variant) {
            if (preg_match($pattern, $variant) === 1) {
                return true;
            }
        }

        return false;
    }
}
