<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Challenge;

use Ganadev\Shield\Core\Context\RequestContext;

interface ChallengeDriverInterface
{
    public function name(): string;

    public function render(RequestContext $context): ChallengePayload;

    public function verify(string $token, RequestContext $context): ChallengeResult;
}
