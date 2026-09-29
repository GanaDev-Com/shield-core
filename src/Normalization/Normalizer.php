<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Normalization;

use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;

/**
 * Pure, deterministic request normalizer.
 *
 * The original request is never modified; every transformation is applied to
 * bounded working copies only. Decoding is bounded by the configured depth and
 * never applied recursively without a limit.
 */
final class Normalizer
{
    public function normalize(RequestContext $context, ShieldConfig $config): NormalizedRequest
    {
        $uri = $context->rawUri;

        $truncated = strlen($uri) > $config->maxUriLength;
        if ($truncated) {
            $uri = substr($uri, 0, $config->maxUriLength);
        }

        [$path, $query] = $this->splitPathAndQuery($uri);

        $normalizedPath = $this->canonicalizePath($path);
        $normalizedQuery = $this->canonicalizeQuery($query);
        $normalizedUri = $normalizedPath.($normalizedQuery !== '' ? '?'.$normalizedQuery : '');

        $decodedVariants = [];
        $decoded = $uri;
        for ($i = 1; $i <= $config->decodeDepth; $i++) {
            $decoded = rawurldecode($decoded);
            $decodedVariants[] = $decoded;
        }

        $body = $context->body;
        $normalizedBody = $body === '' ? '' : strtolower($body);

        $bodyDecodedVariants = [];
        if ($body !== '' && $config->bodyInspectionEnabled) {
            $decodedBody = $body;
            for ($i = 1; $i <= $config->decodeDepth; $i++) {
                $decodedBody = rawurldecode($decodedBody);
                $bodyDecodedVariants[] = $decodedBody;
            }
        }

        return new NormalizedRequest(
            normalizedUri: $normalizedUri,
            normalizedPath: $normalizedPath,
            normalizedQuery: $normalizedQuery,
            decodedVariants: $decodedVariants,
            truncated: $truncated,
            normalizedBody: $normalizedBody,
            bodyDecodedVariants: $bodyDecodedVariants,
        );
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function splitPathAndQuery(string $uri): array
    {
        $query = '';
        $path = $uri;

        $questionMark = strpos($uri, '?');
        if ($questionMark !== false) {
            $path = substr($uri, 0, $questionMark);
            $query = substr($uri, $questionMark + 1);
        }

        if ($path === '') {
            $path = '/';
        }

        return [$path, $query];
    }

    private function canonicalizePath(string $path): string
    {
        $normalized = str_replace('\\', '/', $path);
        $normalized = strtolower($normalized);
        $normalized = (string) preg_replace('#/{2,}#', '/', $normalized);

        if ($normalized === '') {
            return '/';
        }

        return $normalized;
    }

    private function canonicalizeQuery(string $query): string
    {
        return strtolower($query);
    }
}
