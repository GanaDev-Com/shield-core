<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Context;

final class RequestContext
{
    /**
     * @param  array<string, string>  $headersSubset
     */
    private function __construct(
        public readonly string $rawUri,
        public readonly string $rawPath,
        public readonly string $rawQuery,
        public readonly string $method,
        public readonly string $host,
        public readonly string $ip,
        public readonly array $headersSubset,
        public readonly string $body,
    ) {}

    /**
     * @param  array<string, string>  $headersSubset
     */
    public static function create(
        string $rawUri,
        string $method,
        string $host,
        string $ip,
        array $headersSubset = [],
        string $body = '',
    ): self {
        $rawPath = (string) parse_url($rawUri, PHP_URL_PATH);
        $rawQuery = (string) parse_url($rawUri, PHP_URL_QUERY);

        if ($rawPath === '') {
            $rawPath = '/';
        }

        return new self(
            rawUri: $rawUri,
            rawPath: $rawPath,
            rawQuery: $rawQuery,
            method: strtoupper($method),
            host: strtolower(trim($host)),
            ip: trim($ip),
            headersSubset: $headersSubset,
            body: $body,
        );
    }

    public function userAgent(): string
    {
        return $this->headersSubset['user-agent'] ?? '';
    }

    public function referer(): string
    {
        return $this->headersSubset['referer'] ?? '';
    }
}
