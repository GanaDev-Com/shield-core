<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\Rule;

/**
 * Bounded, self-registering matcher registry. Adding a new matcher type only
 * requires implementing RuleMatcherInterface and registering it here.
 */
final class RuleMatcherRegistry
{
    /** @var list<RuleMatcherInterface> */
    private array $matchers;

    /**
     * @param  list<RuleMatcherInterface>|null  $matchers
     */
    public function __construct(?array $matchers = null)
    {
        $this->matchers = $matchers ?? [
            new ExactMatcher,
            new PrefixMatcher,
            new ContainsMatcher,
            new QueryContainsMatcher,
            new DecodedContainsMatcher,
            new RegexMatcher,
            new BodyContainsMatcher,
            new BodyRegexMatcher,
        ];
    }

    public function matches(Rule $rule, NormalizedRequest $request): bool
    {
        foreach ($this->matchers as $matcher) {
            if ($matcher->supports($rule)) {
                return $matcher->matches($rule, $request);
            }
        }

        return false;
    }
}
