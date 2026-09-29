<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Detection;

use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Normalization\NormalizedRequest;
use Ganadev\Shield\Core\Trust\CrawlerVerifierInterface;

final class BehaviorDetector
{
    public const SIGNAL_UNIQUE_URI_BURST = 'unique_uri_burst';

    public const SIGNAL_NOT_FOUND_ENUMERATION = 'not_found_enumeration';

    public const SIGNAL_METHOD_ANOMALY = 'method_anomaly';

    public const SIGNAL_MISSING_HEADERS = 'missing_headers';

    public const SIGNAL_SUSPICIOUS_UA = 'suspicious_user_agent';

    public const SIGNAL_SCANNER_TOOL_UA = 'scanner_tool_ua';

    public const SIGNAL_MISSING_REFERER = 'missing_referer';

    public const SIGNAL_OVERSIZED = 'oversized_request';

    public const SIGNAL_KNOWN_CRAWLER = 'known_crawler';

    public const SIGNAL_VERIFIED_CRAWLER = 'verified_crawler';

    public const SIGNAL_UNVERIFIED_CRAWLER_CLAIM = 'unverified_crawler_claim';

    public const SIGNAL_PATH_RATE_BURST = 'path_rate_burst';

    public const SIGNAL_SENSITIVE_PATH_BURST = 'sensitive_path_burst';

    /**
     * Generic (but not malicious) HTTP clients. A weak +2 signal: they are
     * common enough (curl, wget, libraries) that they must never block alone.
     *
     * @var list<string>
     */
    private const GENERIC_CLIENT_UA_MARKERS = [
        'curl/',
        'wget',
        'python-requests',
        'python-urllib',
        'python-httpx',
        'scrapy',
        'libwww-perl',
        'go-http-client',
        'node-fetch',
        'axios',
        'okhttp',
        'powershell',
        'java/',
    ];

    public function __construct(
        private readonly ?CrawlerVerifierInterface $crawlerVerifier = null,
    ) {}

    public function evaluate(
        RequestContext $context,
        NormalizedRequest $normalized,
        BehaviorCounters $counters,
        ShieldConfig $config,
    ): BehaviorReport {
        $deltas = [];
        $signals = [];
        $knownCrawler = null;

        if ($counters->uniqueUriCount >= $config->uniqueUriLimit) {
            $deltas['burst_unique_uri'] = 12;
            $signals[] = self::SIGNAL_UNIQUE_URI_BURST;
        }

        if ($counters->notFoundCount >= $config->notFoundLimit) {
            $deltas['not_found_enumeration'] = 10;
            $signals[] = self::SIGNAL_NOT_FOUND_ENUMERATION;
        }

        if ($counters->isSensitivePath
            && $counters->pathRequestCount >= $config->sensitivePathRateLimit) {
            $deltas['sensitive_path_burst'] = 10;
            $signals[] = self::SIGNAL_SENSITIVE_PATH_BURST;
        } elseif ($counters->pathRequestCount >= $config->pathRateLimit) {
            $deltas['path_rate_burst'] = 8;
            $signals[] = self::SIGNAL_PATH_RATE_BURST;
        }

        if ($this->isMethodAnomaly($context->method)) {
            $deltas['method_anomaly'] = 4;
            $signals[] = self::SIGNAL_METHOD_ANOMALY;
        }

        $userAgent = $context->userAgent();
        if (! array_key_exists('user-agent', $context->headersSubset) || $userAgent === '') {
            $deltas['missing_headers'] = 2;
            $signals[] = self::SIGNAL_MISSING_HEADERS;
        } else {
            $knownCrawler = $this->classifyCrawler($userAgent, $config->knownBotAgents);

            if ($knownCrawler !== null) {
                $signals[] = self::SIGNAL_KNOWN_CRAWLER;

                if ($this->isVerifiedCrawler($knownCrawler, $context->ip, $config)) {
                    // A verified crawler (e.g. real Googlebot) must be able to
                    // crawl aggressively without tripping burst/enumeration
                    // counters. Zero all behavior deltas so it is never
                    // challenged or banned by behavior alone.
                    return new BehaviorReport(
                        totalDelta: 0,
                        signals: [self::SIGNAL_KNOWN_CRAWLER, self::SIGNAL_VERIFIED_CRAWLER],
                        knownCrawler: $knownCrawler,
                    );
                }

                $deltas['unverified_crawler_claim'] = $config->unverifiedClaimSignal;
                $signals[] = self::SIGNAL_UNVERIFIED_CRAWLER_CLAIM;
            }

            if ($this->isScannerToolUserAgent($userAgent, $config->scannerUserAgents)) {
                $deltas['scanner_tool_ua'] = $config->scannerUaSignal;
                $signals[] = self::SIGNAL_SCANNER_TOOL_UA;
            } elseif ($this->isSuspiciousUserAgent($userAgent, $config->suspiciousUserAgentOverrides)) {
                $deltas['suspicious_user_agent'] = 2;
                $signals[] = self::SIGNAL_SUSPICIOUS_UA;
            }
        }

        if ($config->missingRefererSignal
            && $context->method === 'POST'
            && ($context->referer() === '' || $context->referer() === '/')) {
            $deltas['missing_referer'] = 2;
            $signals[] = self::SIGNAL_MISSING_REFERER;
        }

        if ($normalized->isOversized()) {
            $deltas['oversized_request'] = 2;
            $signals[] = self::SIGNAL_OVERSIZED;
        }

        return new BehaviorReport(
            totalDelta: array_sum($deltas),
            signals: $signals,
            knownCrawler: $knownCrawler,
        );
    }

    private function isMethodAnomaly(string $method): bool
    {
        return ! in_array($method, ['GET', 'POST', 'HEAD', 'OPTIONS'], true);
    }

    private function isVerifiedCrawler(string $claimedAgent, string $ip, ShieldConfig $config): bool
    {
        if (! $config->crawlerVerificationEnabled || $this->crawlerVerifier === null) {
            return false;
        }

        return $this->crawlerVerifier->verify($claimedAgent, $ip) === $claimedAgent;
    }

    /**
     * Strong signal: the User-Agent names a known vulnerability scanner/tool.
     *
     * @param  list<string>  $scannerMarkers
     */
    private function isScannerToolUserAgent(string $userAgent, array $scannerMarkers): bool
    {
        $lower = strtolower($userAgent);

        foreach ($scannerMarkers as $marker) {
            if ($marker !== '' && str_contains($lower, strtolower($marker))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Weak signal: generic clients, user-configured overrides, or a bare
     * "Mozilla/5.0" that is not a real browser.
     *
     * @param  list<string>  $overrides
     */
    private function isSuspiciousUserAgent(string $userAgent, array $overrides): bool
    {
        $lower = strtolower($userAgent);
        $markers = array_merge(self::GENERIC_CLIENT_UA_MARKERS, $overrides);

        foreach ($markers as $marker) {
            if (str_contains($lower, $marker)) {
                return true;
            }
        }

        if (preg_match('/^mozilla\/5\.0\s*(\([^)]*\))?\s*$/i', $userAgent) === 1) {
            return true;
        }

        return false;
    }

    /**
     * @param  list<string>  $knownAgents
     */
    private function classifyCrawler(string $userAgent, array $knownAgents): ?string
    {
        $lower = strtolower($userAgent);

        foreach ($knownAgents as $agent) {
            if (str_contains($lower, strtolower($agent))) {
                return $agent;
            }
        }

        return null;
    }
}
