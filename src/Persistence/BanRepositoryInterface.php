<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Persistence;

use Ganadev\Shield\Core\Reputation\BanRecord;

interface BanRepositoryInterface
{
    public function findActiveByIp(string $ip): ?BanRecord;

    /**
     * Most recent record for an IP regardless of status. Used to escalate
     * offense counts after a ban has been released or expired.
     */
    public function findLatestByIp(string $ip): ?BanRecord;

    public function findById(string $id): ?BanRecord;

    public function createBan(BanRecord $record): BanRecord;

    public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord;

    public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord;

    public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord;

    public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord;
}
