<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Privacy;

/**
 * Masks sensitive query parameters before URIs are persisted to security
 * events, so tokens/keys/secrets never land in the database (spec 19).
 */
final class UriMasker
{
    /** @var list<string> */
    private const SUFFIXES = ['_token', '_key', '_secret', '_password', '_passwd'];

    /**
     * @param  list<string>  $sensitiveParams
     */
    public function mask(string $uri, array $sensitiveParams): string
    {
        $question = strpos($uri, '?');
        if ($question === false) {
            return $uri;
        }

        $path = substr($uri, 0, $question);
        $query = substr($uri, $question + 1);
        $masked = [];

        foreach (explode('&', $query) as $pair) {
            if ($pair === '') {
                continue;
            }

            $eq = strpos($pair, '=');
            $key = $eq === false ? $pair : substr($pair, 0, $eq);

            if ($this->isSensitive($key, $sensitiveParams)) {
                $masked[] = $key.'=***';
            } else {
                $masked[] = $pair;
            }
        }

        return $path.'?'.implode('&', $masked);
    }

    /**
     * @param  list<string>  $sensitiveParams
     */
    private function isSensitive(string $key, array $sensitiveParams): bool
    {
        $lower = strtolower($key);

        foreach ($sensitiveParams as $param) {
            if ($lower === strtolower($param)) {
                return true;
            }
        }

        foreach (self::SUFFIXES as $suffix) {
            if (str_ends_with($lower, $suffix)) {
                return true;
            }
        }

        return false;
    }
}
