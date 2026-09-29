<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\MatcherType;
use Ganadev\Shield\Core\Rules\Rule;

final class BodyRegexMatcher implements RuleMatcherInterface
{
    public function supports(Rule $rule): bool
    {
        return $rule->matcher === MatcherType::BodyRegex;
    }

    public function matches(Rule $rule, NormalizedRequest $request): bool
    {
        if ($request->normalizedBody === '') {
            return false;
        }

        $pattern = '~'.$rule->value.'~i';

        if (preg_match($pattern, $request->normalizedBody) === 1) {
            return true;
        }

        foreach ($request->bodyDecodedVariants as $variant) {
            if (preg_match($pattern, $variant) === 1) {
                return true;
            }
        }

        return false;
    }
}
