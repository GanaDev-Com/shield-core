<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Trust;

/**
 * Verifies whether the given IP actually belongs to a known crawler that
 * claimed to be it via its User-Agent. UA strings can be spoofed, so a
 * crawler is only trusted after its identity is confirmed (e.g. reverse-DNS
 * or an allowlisted IP range).
 *
 * Returns the verified crawler name on success, null when the claim could not
 * be confirmed. The core only depends on this contract; DNS/IP logic lives in
 * the framework adapter.
 */
interface CrawlerVerifierInterface
{
    public function verify(string $claimedAgent, string $ip): ?string;
}
