<?php

declare(strict_types=1);

namespace Ganadev\Shield\Core\Support;

/**
 * Pure IPv4/IPv6 CIDR membership check. No framework dependencies so it can be
 * reused by the core and any adapter (crawler verification, allowlists, ...).
 */
final class IpCidrMatcher
{
    public static function inRange(string $ip, string $cidr): bool
    {
        $cidr = trim($cidr);
        if (str_contains($cidr, '/')) {
            [$network, $prefix] = array_pad(explode('/', $cidr, 2), 2, '');
        } else {
            $network = $cidr;
            $prefix = '';
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return self::matchIpv4($ip, $network, $prefix);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return self::matchIpv6($ip, $network, $prefix);
        }

        return false;
    }

    /**
     * @param  list<string>  $ranges
     */
    public static function inAnyRange(string $ip, array $ranges): bool
    {
        foreach ($ranges as $cidr) {
            if (self::inRange($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    private static function matchIpv4(string $ip, string $network, string $prefix): bool
    {
        if ($prefix === '') {
            return $ip === $network;
        }

        if (! is_numeric($prefix) || (int) $prefix < 0 || (int) $prefix > 32) {
            return false;
        }

        $mask = (int) $prefix === 0 ? 0 : (-1 << (32 - (int) $prefix)) & 0xFFFFFFFF;
        $ipLong = ip2long($ip);
        $netLong = ip2long($network);

        return $ipLong !== false
            && $netLong !== false
            && ($ipLong & $mask) === ($netLong & $mask);
    }

    private static function matchIpv6(string $ip, string $network, string $prefix): bool
    {
        if (! filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return false;
        }

        if ($prefix === '') {
            return $ip === $network;
        }

        if (! is_numeric($prefix) || (int) $prefix < 0 || (int) $prefix > 128) {
            return false;
        }

        $ipBin = inet_pton($ip);
        $netBin = inet_pton($network);
        if ($ipBin === false || $netBin === false) {
            return false;
        }

        $bits = (int) $prefix;
        $ipBits = self::toBits($ipBin);
        $netBits = self::toBits($netBin);

        for ($i = 0; $i < $bits; $i++) {
            if ($ipBits[$i] !== $netBits[$i]) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return list<int>
     */
    private static function toBits(string $bytes): array
    {
        $bits = [];
        for ($i = 0; $i < strlen($bytes); $i++) {
            $byte = ord($bytes[$i]);
            for ($b = 7; $b >= 0; $b--) {
                $bits[] = ($byte >> $b) & 1;
            }
        }

        return $bits;
    }
}
