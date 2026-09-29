<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Reputation;

enum BanStatus: string
{
    case Active = 'active';

    case Expired = 'expired';

    case Released = 'released';

    case ManualBlock = 'manual_block';

    public function isActive(): bool
    {
        return $this === self::Active || $this === self::ManualBlock;
    }
}
