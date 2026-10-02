<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Config;

use Ganadev\Shield\Core\Exceptions\InvalidConfigException;

final class ShieldConfig
{
    public const MODE_OBSERVE = 'observe';

    public const MODE_CHALLENGE = 'challenge';

    public const MODE_ENFORCE = 'enforce';

    public const FAIL_OPEN = 'open';

    public const FAIL_CLOSED = 'closed';

    public const BOT_OFF = 'off';

    public const BOT_OBSERVE = 'observe';

    public const BOT_CHALLENGE = 'challenge';

    public const LOG_ALL = 'all';

    public const LOG_SUSPICIOUS = 'suspicious';

    public const LOG_BLOCKED = 'blocked';

    private function __construct(
        public readonly bool $enabled,
        public readonly string $mode,
        public readonly string $appId,
        public readonly int $responseCode,
        public readonly int $decodeDepth,
        public readonly string $failMode,
        public readonly int $thresholdChallenge,
        public readonly int $thresholdBan,
        public readonly int $thresholdStrongBan,
        /** @var list<int> */
        public readonly array $banDurations,
        public readonly string $challengeDriver,
        public readonly int $uniqueUriLimit,
        public readonly int $behaviorWindowSeconds,
        public readonly int $notFoundLimit,
        public readonly string $loggingLevel,
        public readonly bool $logBypassEvents,
        public readonly string $adminAuthorize,
        /** @var array{hosts: list<string>, paths: list<string>, ips: list<string>} */
        public readonly array $allowlist,
        public readonly bool $trustedEnabled,
        public readonly int $trustedTtlMinutes,
        public readonly int $maxUriLength,
        public readonly int $escalationStep,
        /** @var list<string> */
        public readonly array $sensitiveQueryParameters,
        public readonly string $ruleVersion,
        public readonly string $blockedView,
        public readonly string $challengeView,
        /** @var array{title: string, accent_color: string, background_color: string, show_rule_id: bool} */
        public readonly array $branding,
        public readonly string $botMode,
        /** @var list<string> */
        public readonly array $knownBotAgents,
        /** @var list<string> */
        public readonly array $suspiciousUserAgentOverrides,
        public readonly bool $missingRefererSignal,
        /**
         * Core does not assemble the rule set itself; the Laravel adapter reads
         * `shield.rules.packs` directly when building the RuleRepository. This
         * property exists so a core-only consumer can honour the same flag.
         */
        public readonly bool $rulesPacksInjection,
        public readonly bool $rulesPacksWordpress,
        public readonly int $pathRateLimit,
        /** @var list<string> */
        public readonly array $sensitivePaths,
        public readonly int $sensitivePathRateLimit,
        public readonly int $banCacheTtlSeconds,
        public readonly bool $crawlerVerificationEnabled,
        public readonly int $crawlerVerificationTtlHours,
        /** @var array<string, list<string>> */
        public readonly array $crawlerHostnames,
        /** @var array<string, list<string>> */
        public readonly array $crawlerIpRanges,
        public readonly int $unverifiedClaimSignal,
        /** @var list<string> */
        public readonly array $scannerUserAgents,
        public readonly int $scannerUaSignal,
        public readonly bool $bodyInspectionEnabled,
        public readonly int $bodyInspectionMaxBytes,
        /**
         * Path prefixes where body inspection and behavior signals are skipped.
         * Signature matching still applies, so a critical payload in the URI is
         * never exempt. Use it for endpoints that legitimately carry free text
         * (JSON APIs, webhook receivers) or where shared-IP counters are noise
         * (oauth, service-to-service gateways).
         *
         * @var list<string>
         */
        public readonly array $skipPaths,
        /**
         * Path prefixes that always get a JSON representation of block and
         * challenge responses, even without an Accept header.
         *
         * @var list<string>
         */
        public readonly array $apiPaths,
        public readonly bool $apiDetectAccept,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public static function defaults(): array
    {
        return [
            'enabled' => true,
            'mode' => self::MODE_OBSERVE,
            'app_id' => 'default',
            'response_code' => 404,
            'decode_depth' => 2,
            'fail_mode' => self::FAIL_OPEN,
            'thresholds' => [
                'challenge' => 10,
                'ban' => 20,
                'strong_ban' => 30,
            ],
            'ban' => [
                'durations' => [15, 60, 360, 1440],
            ],
            'challenge' => [
                'driver' => 'turnstile',
            ],
            'behavior' => [
                'unique_uri_limit' => 25,
                'window_seconds' => 60,
                'not_found_limit' => 20,
                'missing_referer_signal' => true,
                'suspicious_user_agents' => [],
                'scanner_user_agents' => [
                    'sqlmap',
                    'nikto',
                    'metasploit',
                    'wpscan',
                    'dirbuster',
                    'gobuster',
                    'masscan',
                    'nmap',
                    'nessus',
                    'acunetix',
                    'x00c',
                    'zgrab',
                    'httpx',
                ],
                'scanner_ua_signal' => 4,
                'path_rate_limit' => 30,
                'sensitive_path_rate_limit' => 8,
                'sensitive_paths' => [
                    '/login',
                    '/wp-login.php',
                    '/admin/login',
                    '/administrator/',
                    '/api/login',
                    '/api/auth',
                    '/user/login',
                ],
            ],
            'logging' => [
                // 'all' = every request, 'suspicious' = any decision other than
                // ALLOW, 'blocked' = only terminal blocks (block / temp ban).
                'level' => self::LOG_SUSPICIOUS,
                'bypass_events' => true,
            ],
            'admin' => [
                'authorize' => '',
            ],
            'allowlist' => [
                'hosts' => [],
                'paths' => [],
                'ips' => [],
            ],
            'trusted' => [
                'enabled' => true,
                'ttl_minutes' => 60,
            ],
            'performance' => [
                'max_uri_length' => 2048,
                'ban_cache_ttl_seconds' => 30,
            ],
            'escalation' => [
                'step' => 5,
            ],
            'privacy' => [
                'sensitive_query_parameters' => ['token', 'password', 'passwd', 'key', 'secret', 'code', 'auth'],
            ],
            'rule_version' => '1.0.0',
            'views' => [
                'blocked' => 'shield::blocked',
                'challenge' => 'shield::challenge',
            ],
            'branding' => [
                'title' => 'Ganadev Laravel Shield',
                'accent_color' => '#22d3ee',
                'background_color' => '#0b1220',
                'show_rule_id' => false,
            ],
            'bots' => [
                'mode' => 'observe',
                'unverified_claim_signal' => 4,
                'verification' => [
                    'enabled' => true,
                    'ttl_hours' => 24,
                    'hostnames' => [
                        'googlebot' => ['.googlebot.com', '.google.com'],
                        'bingbot' => ['.search.msn.com'],
                        'yandexbot' => ['.yandex.ru', '.yandex.net'],
                        'baiduspider' => ['.baidu.com', '.baidu.jp'],
                        'duckduckbot' => ['.duckduckgo.com'],
                        'ahrefsbot' => ['.ahrefs.com'],
                        'semrushbot' => ['.semrush.com'],
                        'dotbot' => ['.moz.com'],
                        'ccbot' => ['.cc'],
                    ],
                    'ip_ranges' => [],
                ],
                'known_agents' => [
                    'googlebot',
                    'bingbot',
                    'yandexbot',
                    'baiduspider',
                    'duckduckbot',
                    'ahrefsbot',
                    'semrushbot',
                    'mj12bot',
                    'dotbot',
                    'bytespider',
                    'ccbot',
                    'gptbot',
                    'chatgpt-user',
                    'claudebot',
                    'anthropic',
                    'openai',
                    'oai-searchbot',
                    'perplexitybot',
                ],
            ],
            'rules' => [
                'packs' => [
                    'wordpress' => false,
                    'injection' => true,
                ],
                'skip_paths' => [],
            ],
            'inspection' => [
                'body' => [
                    'enabled' => true,
                    'max_bytes' => 65536,
                ],
            ],
            'api' => [
                'paths' => [],
                'detect_accept' => true,
            ],
        ];
    }

    /**
     * @param  array<string, mixed>  $config
     */
    public static function fromArray(array $config): self
    {
        $defaults = self::defaults();
        $c = self::deepMerge($defaults, $config);

        self::assertValid($c);

        return new self(
            enabled: (bool) $c['enabled'],
            mode: (string) $c['mode'],
            appId: (string) $c['app_id'],
            responseCode: (int) $c['response_code'],
            decodeDepth: (int) $c['decode_depth'],
            failMode: (string) $c['fail_mode'],
            thresholdChallenge: (int) $c['thresholds']['challenge'],
            thresholdBan: (int) $c['thresholds']['ban'],
            thresholdStrongBan: (int) $c['thresholds']['strong_ban'],
            banDurations: array_values(array_map('intval', $c['ban']['durations'])),
            challengeDriver: (string) $c['challenge']['driver'],
            uniqueUriLimit: (int) $c['behavior']['unique_uri_limit'],
            behaviorWindowSeconds: (int) $c['behavior']['window_seconds'],
            notFoundLimit: (int) $c['behavior']['not_found_limit'],
            loggingLevel: (string) ($c['logging']['level'] ?? self::LOG_SUSPICIOUS),
            logBypassEvents: (bool) ($c['logging']['bypass_events'] ?? true),
            adminAuthorize: (string) ($c['admin']['authorize'] ?? ''),
            allowlist: self::normalizeAllowlist($c['allowlist']),
            trustedEnabled: (bool) $c['trusted']['enabled'],
            trustedTtlMinutes: (int) $c['trusted']['ttl_minutes'],
            maxUriLength: (int) $c['performance']['max_uri_length'],
            escalationStep: (int) $c['escalation']['step'],
            sensitiveQueryParameters: array_values(array_map('strval', $c['privacy']['sensitive_query_parameters'])),
            ruleVersion: (string) $c['rule_version'],
            blockedView: (string) $c['views']['blocked'],
            challengeView: (string) $c['views']['challenge'],
            branding: [
                'title' => (string) $c['branding']['title'],
                'accent_color' => (string) $c['branding']['accent_color'],
                'background_color' => (string) $c['branding']['background_color'],
                'show_rule_id' => (bool) ($c['branding']['show_rule_id'] ?? false),
            ],
            botMode: (string) $c['bots']['mode'],
            knownBotAgents: array_values(array_map('strval', $c['bots']['known_agents'])),
            suspiciousUserAgentOverrides: array_values(array_map('strval', $c['behavior']['suspicious_user_agents'])),
            missingRefererSignal: (bool) $c['behavior']['missing_referer_signal'],
            rulesPacksInjection: (bool) ($c['rules']['packs']['injection'] ?? true),
            rulesPacksWordpress: (bool) ($c['rules']['packs']['wordpress'] ?? false),
            pathRateLimit: (int) $c['behavior']['path_rate_limit'],
            sensitivePaths: array_values(array_map('strval', $c['behavior']['sensitive_paths'])),
            sensitivePathRateLimit: (int) $c['behavior']['sensitive_path_rate_limit'],
            banCacheTtlSeconds: (int) $c['performance']['ban_cache_ttl_seconds'],
            crawlerVerificationEnabled: (bool) ($c['bots']['verification']['enabled'] ?? true),
            crawlerVerificationTtlHours: (int) ($c['bots']['verification']['ttl_hours'] ?? 24),
            crawlerHostnames: (array) ($c['bots']['verification']['hostnames'] ?? []),
            crawlerIpRanges: (array) ($c['bots']['verification']['ip_ranges'] ?? []),
            unverifiedClaimSignal: (int) ($c['bots']['unverified_claim_signal'] ?? 4),
            scannerUserAgents: array_values(array_map('strval', (array) ($c['behavior']['scanner_user_agents'] ?? []))),
            scannerUaSignal: (int) ($c['behavior']['scanner_ua_signal'] ?? 4),
            bodyInspectionEnabled: (bool) ($c['inspection']['body']['enabled'] ?? true),
            bodyInspectionMaxBytes: (int) ($c['inspection']['body']['max_bytes'] ?? 65536),
            skipPaths: self::normalizePathPrefixes($c['rules']['skip_paths'] ?? []),
            apiPaths: self::normalizePathPrefixes($c['api']['paths'] ?? []),
            apiDetectAccept: (bool) ($c['api']['detect_accept'] ?? true),
        );
    }

    /**
     * Deep merge that replaces numeric-keyed (list) arrays entirely instead of
     * merging index-by-index.
     *
     * @param  array<string, mixed>  $defaults
     * @param  array<string, mixed>  $override
     * @return array<string, mixed>
     */
    private static function deepMerge(array $defaults, array $override): array
    {
        foreach ($override as $key => $value) {
            if (is_array($value)
                && isset($defaults[$key])
                && is_array($defaults[$key])
                && ! array_is_list($value)) {
                $defaults[$key] = self::deepMerge($defaults[$key], $value);
            } else {
                $defaults[$key] = $value;
            }
        }

        return $defaults;
    }

    /**
     * Trims allowlist entries so surrounding whitespace cannot silently change
     * which requests are matched. assertValid() has already rejected empty and
     * root prefixes by the time this runs.
     *
     * @param  array<string, mixed>  $allowlist
     * @return array{hosts: list<string>, paths: list<string>, ips: list<string>}
     */
    private static function normalizeAllowlist(array $allowlist): array
    {
        $allowlist['hosts'] = array_values(array_map('trim', array_map('strval', $allowlist['hosts'])));
        $allowlist['ips'] = array_values(array_map('trim', array_map('strval', $allowlist['ips'])));
        $allowlist['paths'] = array_values(array_map('trim', array_map('strval', $allowlist['paths'])));

        return $allowlist;
    }

    /**
     * Trims path prefix lists so surrounding whitespace cannot silently change
     * which requests match. assertValid() has already rejected empty, root and
     * query-string entries by the time this runs.
     *
     * @param  array<mixed>  $paths
     * @return list<string>
     */
    private static function normalizePathPrefixes(array $paths): array
    {
        return array_values(array_map('trim', array_map('strval', $paths)));
    }

    /**
     * @param  array<string, mixed>  $c
     */
    private static function assertValid(array $c): void
    {
        if (! in_array($c['mode'], [self::MODE_OBSERVE, self::MODE_CHALLENGE, self::MODE_ENFORCE], true)) {
            throw new InvalidConfigException('Invalid shield mode: '.$c['mode']);
        }
        if (! in_array($c['fail_mode'], [self::FAIL_OPEN, self::FAIL_CLOSED], true)) {
            throw new InvalidConfigException('Invalid fail_mode: '.$c['fail_mode']);
        }
        if (! in_array($c['bots']['mode'], ['off', 'observe', 'challenge'], true)) {
            throw new InvalidConfigException('Invalid bots.mode: '.$c['bots']['mode']);
        }
        if (! in_array($c['logging']['level'] ?? self::LOG_SUSPICIOUS, [self::LOG_ALL, self::LOG_SUSPICIOUS, self::LOG_BLOCKED], true)) {
            throw new InvalidConfigException(
                'Invalid logging.level: '.(string) ($c['logging']['level'] ?? '')
                .'. Expected one of: all, suspicious, blocked.',
            );
        }
        if ((int) $c['behavior']['path_rate_limit'] < 1 || (int) $c['behavior']['sensitive_path_rate_limit'] < 1) {
            throw new InvalidConfigException('Path rate limits must be positive integers.');
        }
        $depth = (int) $c['decode_depth'];
        if ($depth < 0 || $depth > 3) {
            throw new InvalidConfigException('decode_depth must be between 0 and 3.');
        }
        if ($c['thresholds']['challenge'] >= $c['thresholds']['ban'] || $c['thresholds']['ban'] >= $c['thresholds']['strong_ban']) {
            throw new InvalidConfigException('Thresholds must be strictly increasing: challenge < ban < strong_ban.');
        }
        if (! is_array($c['ban']['durations']) || count($c['ban']['durations']) < 4) {
            throw new InvalidConfigException('ban.durations must contain at least 4 escalating durations.');
        }
        if ((int) $c['response_code'] < 100 || (int) $c['response_code'] > 599) {
            throw new InvalidConfigException('response_code must be a valid HTTP status code.');
        }
        if ((int) ($c['bots']['verification']['ttl_hours'] ?? 24) < 1) {
            throw new InvalidConfigException('bots.verification.ttl_hours must be a positive integer.');
        }
        if ((int) ($c['bots']['unverified_claim_signal'] ?? 4) < 0) {
            throw new InvalidConfigException('bots.unverified_claim_signal must be non-negative.');
        }
        if ((int) ($c['behavior']['scanner_ua_signal'] ?? 4) < 0) {
            throw new InvalidConfigException('behavior.scanner_ua_signal must be non-negative.');
        }
        if ((int) ($c['inspection']['body']['max_bytes'] ?? 65536) < 1024) {
            throw new InvalidConfigException('inspection.body.max_bytes must be at least 1024.');
        }
        self::assertPathPrefixes($c['allowlist']['paths'], 'allowlist.paths', 'allowlist every request');
        self::assertPathPrefixes(
            $c['rules']['skip_paths'] ?? [],
            'rules.skip_paths',
            'skip body and behaviour inspection for every request',
        );
        self::assertPathPrefixes($c['api']['paths'] ?? [], 'api.paths', 'return JSON for every request');
    }

    /**
     * Shared validation for every path-prefix list. The allowlist is stricter
     * because a root prefix there would exempt the whole site, while
     * skip_paths/api.paths only widen behaviour on a narrow scope.
     *
     * @param  array<mixed>  $paths
     */
    private static function assertPathPrefixes(array $paths, string $key, string $consequence): void
    {
        foreach ($paths as $path) {
            $trimmed = trim((string) $path);
            if ($trimmed === '' || $trimmed === '/') {
                throw new InvalidConfigException(
                    $key.' must be specific path prefixes starting with "/". '
                    .'The value "'.$trimmed.'" would '.$consequence.'. '
                    .'To allowlist a whole host use allowlist.hosts or allowlist.ips instead.',
                );
            }
            if (! str_starts_with($trimmed, '/')) {
                throw new InvalidConfigException(
                    $key.' entries must start with "/", got "'.$trimmed.'".',
                );
            }
            if (str_contains($trimmed, '?')) {
                throw new InvalidConfigException(
                    $key.' entries must not contain a query string, got "'.$trimmed.'".',
                );
            }
        }
    }
}
