<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Tests\Support;

use Ganadev\Shield\Core\Persistence\BanRepositoryInterface;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;

final class InMemoryBanRepository implements BanRepositoryInterface
{
    /** @var array<string, BanRecord> */
    private array $records = [];

    private int $sequence = 1;

    public function findActiveByIp(string $ip): ?BanRecord
    {
        $record = $this->records[$ip] ?? null;
        if ($record === null || ! $record->isActive()) {
            return null;
        }

        return $record;
    }

    public function findLatestByIp(string $ip): ?BanRecord
    {
        return $this->records[$ip] ?? null;
    }

    public function findById(string $id): ?BanRecord
    {
        foreach ($this->records as $record) {
            if ($record->id === $id) {
                return $record;
            }
        }

        return null;
    }

    public function createBan(BanRecord $record): BanRecord
    {
        $created = new BanRecord(
            id: (string) $this->sequence++,
            ipAddress: $record->ipAddress,
            status: $record->status,
            reason: $record->reason,
            lastRuleId: $record->lastRuleId,
            riskScore: $record->riskScore,
            violationCount: $record->violationCount,
            offenseCount: $record->offenseCount,
            bannedAt: $record->bannedAt,
            expiresAt: $record->expiresAt,
            releasedAt: $record->releasedAt,
            challengePassedAt: $record->challengePassedAt,
            lastSeenAt: $record->lastSeenAt,
            metadata: $record->metadata,
        );
        $this->records[$record->ipAddress] = $created;

        return $created;
    }

    public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
    {
        $released = new BanRecord(
            id: $ban->id,
            ipAddress: $ban->ipAddress,
            status: BanStatus::Released,
            reason: $ban->reason,
            lastRuleId: $ban->lastRuleId,
            riskScore: $ban->riskScore,
            violationCount: $ban->violationCount,
            offenseCount: $ban->offenseCount,
            bannedAt: $ban->bannedAt,
            expiresAt: $ban->expiresAt,
            releasedAt: $ban->releasedAt ?? new \DateTimeImmutable,
            challengePassedAt: $ban->challengePassedAt,
            lastSeenAt: $ban->lastSeenAt,
            metadata: $ban->metadata,
        );
        $this->records[$ban->ipAddress] = $released;

        return $released;
    }

    public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
    {
        $extended = new BanRecord(
            id: $ban->id,
            ipAddress: $ban->ipAddress,
            status: $ban->status,
            reason: $ban->reason,
            lastRuleId: $ban->lastRuleId,
            riskScore: $ban->riskScore,
            violationCount: $ban->violationCount,
            offenseCount: $ban->offenseCount,
            bannedAt: $ban->bannedAt,
            expiresAt: $expiresAt,
            releasedAt: $ban->releasedAt,
            challengePassedAt: $ban->challengePassedAt,
            lastSeenAt: $ban->lastSeenAt,
            metadata: $ban->metadata,
        );
        $this->records[$ban->ipAddress] = $extended;

        return $extended;
    }

    public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        $updated = new BanRecord(
            id: $ban->id,
            ipAddress: $ban->ipAddress,
            status: $ban->status,
            reason: $ban->reason,
            lastRuleId: $ban->lastRuleId,
            riskScore: $ban->riskScore,
            violationCount: $ban->violationCount,
            offenseCount: $ban->offenseCount,
            bannedAt: $ban->bannedAt,
            expiresAt: $ban->expiresAt,
            releasedAt: $ban->releasedAt,
            challengePassedAt: $at,
            lastSeenAt: $ban->lastSeenAt,
            metadata: $ban->metadata,
        );
        $this->records[$ban->ipAddress] = $updated;

        return $updated;
    }

    public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        $updated = new BanRecord(
            id: $ban->id,
            ipAddress: $ban->ipAddress,
            status: $ban->status,
            reason: $ban->reason,
            lastRuleId: $ban->lastRuleId,
            riskScore: $ban->riskScore,
            violationCount: $ban->violationCount,
            offenseCount: $ban->offenseCount,
            bannedAt: $ban->bannedAt,
            expiresAt: $ban->expiresAt,
            releasedAt: $ban->releasedAt,
            challengePassedAt: $ban->challengePassedAt,
            lastSeenAt: $at,
            metadata: $ban->metadata,
        );
        $this->records[$ban->ipAddress] = $updated;

        return $updated;
    }
}
