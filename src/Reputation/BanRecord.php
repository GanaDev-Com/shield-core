<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Reputation;

final class BanRecord
{
    /**
     * @param  array<string, mixed>|null  $metadata
     */
    public function __construct(
        public readonly ?string $id,
        public readonly string $ipAddress,
        public readonly BanStatus $status,
        public readonly string $reason,
        public readonly ?string $lastRuleId,
        public readonly int $riskScore,
        public readonly int $violationCount,
        public readonly int $offenseCount,
        public readonly \DateTimeImmutable $bannedAt,
        public readonly ?\DateTimeImmutable $expiresAt,
        public readonly ?\DateTimeImmutable $releasedAt,
        public readonly ?\DateTimeImmutable $challengePassedAt,
        public readonly \DateTimeImmutable $lastSeenAt,
        public readonly ?array $metadata = null,
    ) {}

    public function isActive(): bool
    {
        return $this->status->isActive();
    }

    /**
     * Cache-safe representation: plain scalars and arrays only.
     *
     * Domain objects must never be written to a persistent cache store because
     * the serialized payload is bound to the class name and to the autoloader
     * state of the process reading it back. An unresolvable class surfaces as
     * __PHP_Incomplete_Class, which is incompatible with the return types here.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'ip_address' => $this->ipAddress,
            'status' => $this->status->value,
            'reason' => $this->reason,
            'last_rule_id' => $this->lastRuleId,
            'risk_score' => $this->riskScore,
            'violation_count' => $this->violationCount,
            'offense_count' => $this->offenseCount,
            'banned_at' => $this->bannedAt->format(\DateTimeInterface::ATOM),
            'expires_at' => $this->expiresAt?->format(\DateTimeInterface::ATOM),
            'released_at' => $this->releasedAt?->format(\DateTimeInterface::ATOM),
            'challenge_passed_at' => $this->challengePassedAt?->format(\DateTimeInterface::ATOM),
            'last_seen_at' => $this->lastSeenAt->format(\DateTimeInterface::ATOM),
            'metadata' => $this->metadata,
        ];
    }

    /**
     * Rebuilds a record from the array produced by toArray().
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: isset($data['id']) ? (string) $data['id'] : null,
            ipAddress: (string) ($data['ip_address'] ?? ''),
            status: BanStatus::from((string) ($data['status'] ?? '')),
            reason: (string) ($data['reason'] ?? ''),
            lastRuleId: isset($data['last_rule_id']) ? (string) $data['last_rule_id'] : null,
            riskScore: (int) ($data['risk_score'] ?? 0),
            violationCount: (int) ($data['violation_count'] ?? 0),
            offenseCount: (int) ($data['offense_count'] ?? 0),
            bannedAt: new \DateTimeImmutable((string) ($data['banned_at'] ?? 'now')),
            expiresAt: self::toDateTime($data['expires_at'] ?? null),
            releasedAt: self::toDateTime($data['released_at'] ?? null),
            challengePassedAt: self::toDateTime($data['challenge_passed_at'] ?? null),
            lastSeenAt: new \DateTimeImmutable((string) ($data['last_seen_at'] ?? 'now')),
            metadata: isset($data['metadata']) && is_array($data['metadata']) ? $data['metadata'] : null,
        );
    }

    private static function toDateTime(mixed $value): ?\DateTimeImmutable
    {
        if ($value === null) {
            return null;
        }

        if ($value instanceof \DateTimeImmutable) {
            return $value;
        }

        if ($value instanceof \DateTimeInterface) {
            return \DateTimeImmutable::createFromInterface($value);
        }

        $value = (string) $value;

        return $value === '' ? null : new \DateTimeImmutable($value);
    }

    public function isExpired(): bool
    {
        return $this->status === BanStatus::Expired;
    }
}
