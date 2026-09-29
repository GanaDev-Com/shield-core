<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Events;

final class SecurityEvent
{
    public function __construct(
        public readonly string $ipAddress,
        public readonly string $host,
        public readonly string $method,
        public readonly string $rawUri,
        public readonly string $normalizedUri,
        public readonly ?string $ruleId,
        public readonly ?string $category,
        public readonly string $severity,
        public readonly int $scoreDelta,
        public readonly string $decision,
        public readonly ?string $intendedDecision,
        public readonly string $userAgent,
        public readonly ?string $referer,
        public readonly ?string $requestId,
        public readonly string $ruleVersion,
        public readonly \DateTimeImmutable $createdAt,
    ) {}

    /**
     * @param  array<string, mixed>  $extra
     */
    public static function create(array $extra = []): self
    {
        return new self(
            ipAddress: (string) ($extra['ip'] ?? ''),
            host: (string) ($extra['host'] ?? ''),
            method: (string) ($extra['method'] ?? ''),
            rawUri: (string) ($extra['raw_uri'] ?? ''),
            normalizedUri: (string) ($extra['normalized_uri'] ?? ''),
            ruleId: isset($extra['rule_id']) ? (string) $extra['rule_id'] : null,
            category: isset($extra['category']) ? (string) $extra['category'] : null,
            severity: (string) ($extra['severity'] ?? 'low'),
            scoreDelta: (int) ($extra['score_delta'] ?? 0),
            decision: (string) ($extra['decision'] ?? 'ALLOW'),
            intendedDecision: isset($extra['intended_decision']) ? (string) $extra['intended_decision'] : null,
            userAgent: (string) ($extra['user_agent'] ?? ''),
            referer: isset($extra['referer']) ? (string) $extra['referer'] : null,
            requestId: isset($extra['request_id']) ? (string) $extra['request_id'] : null,
            ruleVersion: (string) ($extra['rule_version'] ?? ''),
            createdAt: $extra['created_at'] instanceof \DateTimeImmutable
                ? $extra['created_at']
                : new \DateTimeImmutable,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ip_address' => $this->ipAddress,
            'host' => $this->host,
            'method' => $this->method,
            'raw_uri' => $this->rawUri,
            'normalized_uri' => $this->normalizedUri,
            'rule_id' => $this->ruleId,
            'category' => $this->category,
            'severity' => $this->severity,
            'score_delta' => $this->scoreDelta,
            'decision' => $this->decision,
            'intended_decision' => $this->intendedDecision,
            'user_agent' => $this->userAgent,
            'referer' => $this->referer,
            'request_id' => $this->requestId,
            'rule_version' => $this->ruleVersion,
            'created_at' => $this->createdAt->format('Y-m-d H:i:s'),
        ];
    }
}
