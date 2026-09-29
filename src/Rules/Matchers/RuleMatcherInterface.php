<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules\Matchers;

use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Rules\Rule;

interface RuleMatcherInterface
{
    public function supports(Rule $rule): bool;

    public function matches(Rule $rule, NormalizedRequest $request): bool;
}
