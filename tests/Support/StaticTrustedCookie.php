<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Tests\Support;

use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Trust\TrustedCookieInterface;

final class StaticTrustedCookie implements TrustedCookieInterface
{
    public function __construct(
        private bool $valid = true,
    ) {}

    public function issue(RequestContext $context, int $ttlMinutes): string
    {
        return 'trusted-token';
    }

    public function validate(string $cookieValue, RequestContext $context): bool
    {
        return $this->valid;
    }

    public function name(): string
    {
        return 'shield_trusted';
    }
}
