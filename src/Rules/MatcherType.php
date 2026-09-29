<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Rules;

enum MatcherType: string
{
    case Exact = 'exact';

    case Prefix = 'prefix';

    case Contains = 'contains';

    case Regex = 'regex';

    case QueryContains = 'query_contains';

    case DecodedContains = 'decoded_contains';

    case BodyContains = 'body_contains';

    case BodyRegex = 'body_regex';

    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(static fn (self $case): string => $case->value, self::cases());
    }
}
