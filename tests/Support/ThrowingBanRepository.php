<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Tests\Support;

use Ganadev\Shield\Core\Persistence\BanRepositoryInterface;
use Ganadev\Shield\Core\Reputation\BanRecord;

final class ThrowingBanRepository implements BanRepositoryInterface
{
    public function findActiveByIp(string $ip): ?BanRecord
    {
        throw new \RuntimeException('database unavailable');
    }

    public function findLatestByIp(string $ip): ?BanRecord
    {
        throw new \RuntimeException('database unavailable');
    }

    public function findById(string $id): ?BanRecord
    {
        throw new \RuntimeException('database unavailable');
    }

    public function createBan(BanRecord $record): BanRecord
    {
        throw new \RuntimeException('database unavailable');
    }

    public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
    {
        throw new \RuntimeException('database unavailable');
    }

    public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
    {
        throw new \RuntimeException('database unavailable');
    }

    public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        throw new \RuntimeException('database unavailable');
    }

    public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        throw new \RuntimeException('database unavailable');
    }
}
