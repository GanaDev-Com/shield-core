<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules;

enum RuleSeverity: string
{
    case Low = 'low';

    case Medium = 'medium';

    case High = 'high';

    case Critical = 'critical';

    public function isCritical(): bool
    {
        return $this === self::Critical;
    }
}
