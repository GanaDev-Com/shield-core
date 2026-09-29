<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Trust;

use Ganadev\Shield\Core\Context\RequestContext;

/**
 * Trusted challenge cookie. A valid cookie proves a recent successful challenge
 * and lets legitimate users behind NAT avoid repeated challenges. It must never
 * bypass critical signatures.
 */
interface TrustedCookieInterface
{
    public function issue(RequestContext $context, int $ttlMinutes): string;

    public function validate(string $cookieValue, RequestContext $context): bool;

    /**
     * @return non-empty-string
     */
    public function name(): string;
}
