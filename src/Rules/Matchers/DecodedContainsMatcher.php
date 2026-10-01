<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\MatcherType;
use Ganadev\Shield\Core\Rules\Rule;

/**
 * `decoded_contains` is kept as a distinct matcher type because it is used by
 * shipped rules and is part of the rule vocabulary, but its matching semantics
 * are identical to `contains`. This delegates instead of duplicating so the two
 * cannot drift apart.
 */
final class DecodedContainsMatcher implements RuleMatcherInterface
{
    public function supports(Rule $rule): bool
    {
        return $rule->matcher === MatcherType::DecodedContains;
    }

    public function matches(Rule $rule, NormalizedRequest $request): bool
    {
        return (new ContainsMatcher)->matches($rule, $request);
    }
}
