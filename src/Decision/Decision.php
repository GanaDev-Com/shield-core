<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Decision;

enum Decision: string
{
    case Allowed = 'ALLOW';

    case Observe = 'OBSERVE';

    case Challenge = 'CHALLENGE';

    case BlockRequest = 'BLOCK_REQUEST';

    case TempBan = 'TEMP_BAN';

    public function isBlocking(): bool
    {
        return $this === self::BlockRequest || $this === self::TempBan;
    }

    public function isTerminal(): bool
    {
        return $this === self::BlockRequest || $this === self::TempBan || $this === self::Challenge;
    }
}
