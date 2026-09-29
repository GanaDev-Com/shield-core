<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Tests\Support;

use Ganadev\Shield\Core\Trust\CrawlerVerifierInterface;

/**
 * Configurable crawler verifier for tests. Either a static map of
 * ip => verified agent or a callable resolver, or null (never verifies).
 */
final class FakeCrawlerVerifier implements CrawlerVerifierInterface
{
    /**
     * @param  array<string, string>  $verifiedByIp  ip => verified agent
     */
    public function __construct(
        private readonly array $verifiedByIp = [],
        private readonly mixed $resolver = null,
    ) {}

    public function verify(string $claimedAgent, string $ip): ?string
    {
        if (isset($this->verifiedByIp[$ip])) {
            return $this->verifiedByIp[$ip];
        }

        if (is_callable($this->resolver)) {
            return ($this->resolver)($claimedAgent, $ip);
        }

        return null;
    }
}
