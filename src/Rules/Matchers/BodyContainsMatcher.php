<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\MatcherType;
use Ganadev\Shield\Core\Rules\Rule;

final class BodyContainsMatcher implements RuleMatcherInterface
{
    public function supports(Rule $rule): bool
    {
        return $rule->matcher === MatcherType::BodyContains;
    }

    public function matches(Rule $rule, NormalizedRequest $request): bool
    {
        if ($request->normalizedBody === '') {
            return false;
        }

        if (str_contains($request->normalizedBody, $rule->value)) {
            return true;
        }

        foreach ($request->bodyDecodedVariants as $variant) {
            if (str_contains($variant, $rule->value)) {
                return true;
            }
        }

        return false;
    }
}
