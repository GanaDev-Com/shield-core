<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\MatcherType;
use Ganadev\Shield\Core\Rules\Rule;

final class QueryContainsMatcher implements RuleMatcherInterface
{
    public function supports(Rule $rule): bool
    {
        return $rule->matcher === MatcherType::QueryContains;
    }

    public function matches(Rule $rule, NormalizedRequest $request): bool
    {
        return str_contains($request->normalizedQuery, $rule->value);
    }
}
